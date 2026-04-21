#!/usr/bin/env bash
# ============================================================
# JVM 메트릭 수집 스크립트 (jstat + jstack 기반)
# - Heap/GC/Thread 상태를 주기적으로 수집
# - 사용법: ./collect-jvm-metrics.sh [WildFly_PID] [간격(초)] [출력경로]
#   예) ./collect-jvm-metrics.sh $(pgrep -f wildfly) 5 /tmp/jvm
# ============================================================

set -euo pipefail

WF_PID=${1:-$(pgrep -f "jboss-modules" | head -1)}
INTERVAL=${2:-5}
OUTPUT_DIR=${3:-"$(dirname "$0")/../results"}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

JAVA_HOME=${JAVA_HOME:-/usr/lib/jvm/java-11-openjdk}
JSTAT="${JAVA_HOME}/bin/jstat"
JSTACK="${JAVA_HOME}/bin/jstack"
JCMD="${JAVA_HOME}/bin/jcmd"

mkdir -p "${OUTPUT_DIR}/thread_dumps"

GC_FILE="${OUTPUT_DIR}/gc_stats_${TIMESTAMP}.csv"
HEAP_FILE="${OUTPUT_DIR}/heap_stats_${TIMESTAMP}.csv"
THREAD_FILE="${OUTPUT_DIR}/thread_stats_${TIMESTAMP}.csv"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# ── WildFly PID 확인 ────────────────────────────────────────────────────────
if [[ -z "${WF_PID}" ]]; then
  echo "ERROR: WildFly PID를 찾을 수 없습니다. 직접 지정하세요."
  echo "  사용법: $0 <PID>"
  exit 1
fi
log "모니터링 대상 PID: ${WF_PID}"

# ── GC 통계 CSV 헤더 ─────────────────────────────────────────────────────────
# jstat -gcutil 출력 컬럼:
#   S0 S1 E O M CCS YGC YGCT FGC FGCT CGC CGCT GCT
echo "timestamp,S0_pct,S1_pct,Eden_pct,Old_pct,Metaspace_pct,\
YoungGC_count,YoungGC_time_s,FullGC_count,FullGC_time_s,\
GC_total_time_s,GC_overhead_pct" > "${GC_FILE}"

# ── Heap 상세 CSV 헤더 ───────────────────────────────────────────────────────
# jstat -gccapacity 기반
echo "timestamp,Eden_used_KB,Eden_max_KB,Old_used_KB,Old_max_KB,\
Meta_used_KB,Meta_max_KB,YGC,FGC" > "${HEAP_FILE}"

# ── Thread 상태 CSV 헤더 ─────────────────────────────────────────────────────
echo "timestamp,total_threads,runnable,blocked,waiting,timed_waiting,new_state" > "${THREAD_FILE}"

PREV_YGC=0
PREV_YGCT=0
PREV_FGC=0
ELAPSED=0

collect_gc() {
  local raw
  raw=$("${JSTAT}" -gcutil "${WF_PID}" 1 2>/dev/null | tail -1) || return

  read -r S0 S1 E O M CCS YGC YGCT FGC FGCT CGC CGCT GCT <<< "${raw}"

  # GC 오버헤드: 이전 측정 대비 GC 시간 비율
  local delta_ygct delta_fgct gc_overhead
  delta_ygct=$(echo "${YGCT} ${PREV_YGCT}" | awk '{printf "%.3f", $1-$2}')
  delta_fgct=$(echo "${FGCT}" | awk '{printf "%.3f", $1}')
  gc_overhead=$(echo "${delta_ygct} ${delta_fgct} ${INTERVAL}" | \
    awk '{total=$1+$2; pct=(total/$3)*100; printf "%.1f", pct>100?100:pct}')

  echo "$(date '+%Y-%m-%d %H:%M:%S'),${S0},${S1},${E},${O},${M},\
${YGC},${YGCT},${FGC},${FGCT},${GCT},${gc_overhead}" >> "${GC_FILE}"

  # Full GC 발생 시 경보
  if (( $(echo "${FGC} > ${PREV_FGC}" | bc -l) )); then
    log "⚠️  Full GC 감지! (누적: ${FGC}회, 총 시간: ${FGCT}s)"
  fi

  PREV_YGCT=${YGCT}
  PREV_FGC=${FGC}
}

collect_heap() {
  local raw
  raw=$("${JSTAT}" -gccapacity "${WF_PID}" 1 2>/dev/null | tail -1) || return

  read -r NGCMN NGCMX NGC S0C S1C EC OGCMN OGCMX OGC OC MCMN MCMX MC CCSMN CCSMX CCSC YGC FGC <<< "${raw}"

  # Eden/Old/Meta 현재 사용량 추가 조회
  local used_raw
  used_raw=$("${JSTAT}" -gcnew "${WF_PID}" 1 2>/dev/null | tail -1) || return
  read -r S0C_ S1C_ S0U S1U TT MTT DSS EC_ EU YGC_ YGCT_ <<< "${used_raw}"

  local old_used_raw old_u
  old_used_raw=$("${JSTAT}" -gcold "${WF_PID}" 1 2>/dev/null | tail -1) || return
  read -r MC_ MU CCSC_ CCSU OC_ OU YGC__ FGC_ FGCT_ CGC_ CGCT_ GCT_ <<< "${old_used_raw}"

  echo "$(date '+%Y-%m-%d %H:%M:%S'),${EU:-0},${EC},${OU:-0},${OC},${MU:-0},${MC},${YGC},${FGC}" >> "${HEAP_FILE}"
}

collect_threads() {
  local total runnable blocked waiting timed_waiting new_state
  local jstack_out
  jstack_out=$("${JSTACK}" -l "${WF_PID}" 2>/dev/null) || return

  total=$(echo "${jstack_out}" | grep -c "^\"" || echo 0)
  runnable=$(echo "${jstack_out}"     | grep -c "RUNNABLE"      || echo 0)
  blocked=$(echo "${jstack_out}"      | grep -c "BLOCKED"       || echo 0)
  waiting=$(echo "${jstack_out}"      | grep -c " WAITING "     || echo 0)
  timed_waiting=$(echo "${jstack_out}" | grep -c "TIMED_WAITING" || echo 0)
  new_state=$(echo "${jstack_out}"    | grep -c " NEW "         || echo 0)

  echo "$(date '+%Y-%m-%d %H:%M:%S'),${total},${runnable},${blocked},${waiting},${timed_waiting},${new_state}" >> "${THREAD_FILE}"

  # BLOCKED 스레드 과다 시 Thread Dump 저장
  if (( blocked > 5 )); then
    local dump_file="${OUTPUT_DIR}/thread_dumps/dump_$(date +%H%M%S)_blocked${blocked}.txt"
    echo "${jstack_out}" > "${dump_file}"
    log "⚠️  BLOCKED 스레드 ${blocked}개 감지 → Thread dump: ${dump_file}"
  fi
}

# ── Thread Dump 주기적 저장 (10분마다) ──────────────────────────────────────
take_periodic_dump() {
  ELAPSED=$(( ELAPSED + INTERVAL ))
  if (( ELAPSED % 600 == 0 )); then
    local dump_file="${OUTPUT_DIR}/thread_dumps/periodic_$(date +%H%M%S).txt"
    "${JSTACK}" -l "${WF_PID}" > "${dump_file}" 2>/dev/null || true
    log "주기적 Thread dump 저장 → ${dump_file}"
  fi
}

log "JVM 메트릭 수집 시작 (PID: ${WF_PID}, 간격: ${INTERVAL}s)"
log "GC     → ${GC_FILE}"
log "Heap   → ${HEAP_FILE}"
log "Thread → ${THREAD_FILE}"
log "Ctrl+C로 종료"

trap 'log "수집 종료"; exit 0' INT TERM

while true; do
  collect_gc
  collect_heap
  collect_threads
  take_periodic_dump
  sleep "${INTERVAL}"
done
