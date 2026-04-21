#!/usr/bin/env bash
# ============================================================
# WildFly 26 런타임 통계 수집 스크립트
# - 테스트 중 주기적으로 실행하여 CSV로 누적
# - 사용법: ./collect-wildfly-stats.sh [간격(초)] [출력디렉토리]
#   예) ./collect-wildfly-stats.sh 10 /tmp/perf-results
# ============================================================

set -euo pipefail

INTERVAL=${1:-10}
OUTPUT_DIR=${2:-"$(dirname "$0")/../results"}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_FILE="${OUTPUT_DIR}/wildfly_stats_${TIMESTAMP}.csv"

# WildFly jboss-cli 경로 (환경변수 JBOSS_HOME 없으면 기본 경로)
JBOSS_HOME=${JBOSS_HOME:-/opt/wildfly}
CLI="${JBOSS_HOME}/bin/jboss-cli.sh"

# WildFly Management 접속 정보
MGMT_HOST=${WILDFLY_MGMT_HOST:-127.0.0.1}
MGMT_PORT=${WILDFLY_MGMT_PORT:-9990}
MGMT_USER=${WILDFLY_MGMT_USER:-admin}
MGMT_PASS=${WILDFLY_MGMT_PASS:-admin123}

# 수집할 Datasource 이름 (쉼표 구분, 복수 지원)
DS_NAMES=${WILDFLY_DS_NAMES:-"ExampleDS"}

mkdir -p "${OUTPUT_DIR}"

# ── CSV 헤더 ────────────────────────────────────────────────────────────────
echo "timestamp,ds_name,active_count,in_use_count,available_count,max_used_count,\
wait_count,total_get_time,average_get_time,blocking_failure_count,\
created_count,destroyed_count,xacommit_count,xarollback_count,\
undertow_requests_count,undertow_bytes_sent,undertow_bytes_received,\
heap_used_mb,heap_max_mb,thread_count,thread_peak,\
request_count_total,error_count_total" \
  > "${OUTPUT_FILE}"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

run_cli() {
  "${CLI}" \
    --connect \
    --controller="${MGMT_HOST}:${MGMT_PORT}" \
    --user="${MGMT_USER}" \
    --password="${MGMT_PASS}" \
    --command="$1" \
    2>/dev/null | tr -d ' \n'
}

collect_ds_stats() {
  local ds="$1"
  local base="/subsystem=datasources/data-source=${ds}/statistics=pool"

  local active     block_fail in_use avail max_used wait total_get avg_get created destroyed
  active=$(run_cli "read-attribute --node=${base} --name=ActiveCount"          || echo "N/A")
  in_use=$(run_cli "read-attribute --node=${base} --name=InUseCount"           || echo "N/A")
  avail=$(run_cli  "read-attribute --node=${base} --name=AvailableCount"       || echo "N/A")
  max_used=$(run_cli "read-attribute --node=${base} --name=MaxUsedCount"       || echo "N/A")
  wait=$(run_cli   "read-attribute --node=${base} --name=WaitCount"            || echo "N/A")
  total_get=$(run_cli "read-attribute --node=${base} --name=TotalGetTime"      || echo "N/A")
  avg_get=$(run_cli   "read-attribute --node=${base} --name=AverageGetTime"    || echo "N/A")
  block_fail=$(run_cli "read-attribute --node=${base} --name=BlockingFailureCount" || echo "N/A")
  created=$(run_cli  "read-attribute --node=${base} --name=CreatedCount"       || echo "N/A")
  destroyed=$(run_cli "read-attribute --node=${base} --name=DestroyedCount"    || echo "N/A")

  # XA 통계 (일반 DS는 값이 없을 수 있음)
  local xa_commit xa_rollback
  local xa_base="/subsystem=datasources/data-source=${ds}/statistics=jdbc"
  xa_commit=$(run_cli   "read-attribute --node=${xa_base} --name=XACommitCount"   2>/dev/null || echo "0")
  xa_rollback=$(run_cli "read-attribute --node=${xa_base} --name=XARollbackCount" 2>/dev/null || echo "0")

  echo "${ds},${active},${in_use},${avail},${max_used},${wait},${total_get},${avg_get},${block_fail},${created},${destroyed},${xa_commit},${xa_rollback}"
}

collect_undertow_stats() {
  local base="/subsystem=undertow/server=default-server/http-listener=default"
  local req_count bytes_sent bytes_recv
  req_count=$(run_cli  "read-attribute --node=${base} --name=requestCount"  || echo "N/A")
  bytes_sent=$(run_cli "read-attribute --node=${base} --name=bytesSent"     || echo "N/A")
  bytes_recv=$(run_cli "read-attribute --node=${base} --name=bytesReceived" || echo "N/A")
  echo "${req_count},${bytes_sent},${bytes_recv}"
}

collect_jvm_stats() {
  local heap_used heap_max thread_count thread_peak
  heap_used=$(run_cli  "read-attribute --node=/core-service=platform-mbean/type=memory --name=heap-memory-usage" \
    | grep -oP '"used"\s*=>\s*\K[0-9]+' | head -1 || echo "N/A")
  heap_max=$(run_cli   "read-attribute --node=/core-service=platform-mbean/type=memory --name=heap-memory-usage" \
    | grep -oP '"max"\s*=>\s*\K[0-9]+' | head -1 || echo "N/A")
  thread_count=$(run_cli "read-attribute --node=/core-service=platform-mbean/type=threading --name=thread-count" || echo "N/A")
  thread_peak=$(run_cli  "read-attribute --node=/core-service=platform-mbean/type=threading --name=peak-thread-count" || echo "N/A")

  # MB 변환 (정수 나눗셈)
  [[ "$heap_used" =~ ^[0-9]+$ ]] && heap_used=$(( heap_used / 1024 / 1024 ))
  [[ "$heap_max"  =~ ^[0-9]+$ ]] && heap_max=$(( heap_max  / 1024 / 1024 ))

  echo "${heap_used},${heap_max},${thread_count},${thread_peak}"
}

collect_request_stats() {
  local req_total err_total
  req_total=$(run_cli "read-attribute --node=/subsystem=undertow --name=requestsCount" || echo "N/A")
  err_total=$(run_cli "read-attribute --node=/subsystem=undertow --name=errorCount"    || echo "N/A")
  echo "${req_total},${err_total}"
}

log "WildFly 통계 수집 시작 (간격: ${INTERVAL}s) → ${OUTPUT_FILE}"
log "Ctrl+C로 종료"

while true; do
  TS=$(date '+%Y-%m-%d %H:%M:%S')
  UNDERTOW=$(collect_undertow_stats)
  JVM=$(collect_jvm_stats)
  REQ=$(collect_request_stats)

  # 복수 Datasource 지원
  IFS=',' read -ra DS_ARRAY <<< "${DS_NAMES}"
  for ds in "${DS_ARRAY[@]}"; do
    DS=$(collect_ds_stats "${ds}")
    echo "${TS},${DS},${UNDERTOW},${JVM},${REQ}" >> "${OUTPUT_FILE}"
  done

  log "수집 완료 → undertow=${UNDERTOW} | jvm=${JVM}"

  sleep "${INTERVAL}"
done
