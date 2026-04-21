#!/usr/bin/env bash
# ============================================================
# Thread Dump 수집 및 분석 스크립트
# - 일정 간격으로 N회 Thread Dump 수집 후 요약 분석
# - 사용법: ./thread-dump.sh [PID] [횟수] [간격(초)] [출력경로]
#   예) ./thread-dump.sh $(pgrep -f wildfly) 5 10 /tmp/dumps
# ============================================================

set -euo pipefail

WF_PID=${1:-$(pgrep -f "jboss-modules" | head -1)}
COUNT=${2:-5}
INTERVAL=${3:-10}
OUTPUT_DIR=${4:-"$(dirname "$0")/../results/thread_dumps"}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

JAVA_HOME=${JAVA_HOME:-/usr/lib/jvm/java-11-openjdk}
JSTACK="${JAVA_HOME}/bin/jstack"

mkdir -p "${OUTPUT_DIR}"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

if [[ -z "${WF_PID}" ]]; then
  echo "ERROR: WildFly PID가 필요합니다."
  exit 1
fi

log "Thread Dump 수집: PID=${WF_PID}, ${COUNT}회, ${INTERVAL}초 간격"

DUMP_FILES=()
for i in $(seq 1 "${COUNT}"); do
  DUMP_FILE="${OUTPUT_DIR}/dump_${TIMESTAMP}_${i}.txt"
  log "  [${i}/${COUNT}] Thread dump 수집 → ${DUMP_FILE}"
  "${JSTACK}" -l "${WF_PID}" > "${DUMP_FILE}" 2>&1
  DUMP_FILES+=("${DUMP_FILE}")
  [[ $i -lt ${COUNT} ]] && sleep "${INTERVAL}"
done

# ── 분석: 각 Dump에서 상태별 Thread 카운트 ──────────────────────────────────
ANALYSIS_FILE="${OUTPUT_DIR}/analysis_${TIMESTAMP}.txt"
{
  echo "============================================================"
  echo "Thread Dump 분석 보고서"
  echo "PID: ${WF_PID} | 수집 시각: $(date)"
  echo "============================================================"

  echo ""
  echo "[ 1. Thread 상태별 카운트 ]"
  echo "────────────────────────────────────────────────────────────"
  printf "%-30s %8s %8s %8s %8s %8s\n" "Dump 파일" "TOTAL" "RUNNABLE" "BLOCKED" "WAITING" "T.WAIT"

  for dump in "${DUMP_FILES[@]}"; do
    fname=$(basename "${dump}")
    total=$( grep -c '^"' "${dump}" || echo 0)
    runnable=$(grep -c "RUNNABLE"       "${dump}" || echo 0)
    blocked=$(grep -c "BLOCKED"         "${dump}" || echo 0)
    waiting=$(grep -c " WAITING "       "${dump}" || echo 0)
    twaiting=$(grep -c "TIMED_WAITING"  "${dump}" || echo 0)
    printf "%-30s %8d %8d %8d %8d %8d\n" "${fname}" "${total}" "${runnable}" "${blocked}" "${waiting}" "${twaiting}"
  done

  echo ""
  echo "[ 2. BLOCKED/WAITING 스레드 상세 (마지막 dump 기준) ]"
  echo "────────────────────────────────────────────────────────────"
  local_last="${DUMP_FILES[-1]}"

  echo "--- BLOCKED ---"
  awk '/BLOCKED/{p=1} p{print; if(/^$/)p=0}' "${local_last}" | head -100

  echo ""
  echo "--- WAITING on monitor ---"
  awk '/waiting on|waiting to lock/{p=1; prev=prev_line} p{print prev; print; p=0} {prev_line=$0}' \
    "${local_last}" | head -100

  echo ""
  echo "[ 3. 가장 많이 등장하는 Lock/Monitor 상위 10개 ]"
  echo "────────────────────────────────────────────────────────────"
  grep -h "waiting to lock\|locked\|parking to wait for" "${local_last}" 2>/dev/null | \
    grep -oP '<[^>]+>' | sort | uniq -c | sort -rn | head 10

  echo ""
  echo "[ 4. WildFly Worker Thread 현황 ]"
  echo "────────────────────────────────────────────────────────────"
  echo "XNIO worker threads:"
  grep -A3 '"XNIO.*worker"' "${local_last}" | grep "java.lang.Thread.State:" | \
    sort | uniq -c | sort -rn

  echo ""
  echo "Undertow HTTP handler threads:"
  grep -A3 '"undertow-.*[0-9]"' "${local_last}" | grep "java.lang.Thread.State:" | \
    sort | uniq -c | sort -rn

  echo ""
  echo "[ 5. CPU 점유 Thread 확인 (jstack -l 기준 CPU 높은 스레드 ID) ]"
  echo "────────────────────────────────────────────────────────────"
  echo "ps 기반 스레드별 CPU 사용량 (상위 10):"
  ps -mp "${WF_PID}" -o THREAD,tid,pcpu,comm 2>/dev/null | sort -k3 -rn | head 12

  echo ""
  echo "============================================================"
  echo "분석 완료"
} > "${ANALYSIS_FILE}" 2>&1

log "분석 완료 → ${ANALYSIS_FILE}"
echo ""
cat "${ANALYSIS_FILE}"
