#!/usr/bin/env bash
# ============================================================
# WildFly 26 성능테스트 통합 실행 스크립트
# - 사전 점검 → 모니터링 시작 → 부하 발생 → 모니터링 종료 → 분석
# 사용법:
#   ./run-load-test.sh [옵션]
#
# 옵션:
#   -t  테스트 유형   : read | write | mixed | endurance (기본: mixed)
#   -u  동시 사용자 수: 정수 (기본: 100)
#   -d  지속 시간(초) : 정수 (기본: 300)
#   -r  램프업 시간(초): 정수 (기본: 60)
#   -s  테스트 도구   : gatling | jmeter (기본: gatling)
#   -n  반복 횟수     : 정수 (기본: 1, 최소 3회 권장)
#   -h  도움말
#
# 예시:
#   ./run-load-test.sh -t mixed -u 200 -d 600 -r 60 -n 3
#   ./run-load-test.sh -t read  -u 100 -d 300 -s jmeter
# ============================================================

set -euo pipefail

# ── 기본값 ───────────────────────────────────────────────────────────────────
TEST_TYPE="mixed"
USERS=100
DURATION=300
RAMP=60
TOOL="gatling"
REPEAT=1

BASE_URL=${BASE_URL:-"http://localhost:8080"}
APP_CONTEXT=${APP_CONTEXT:-"/myapp"}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
RESULTS_DIR="${ROOT_DIR}/results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RUN_DIR="${RESULTS_DIR}/run_${TIMESTAMP}"

GATLING_HOME=${GATLING_HOME:-"/opt/gatling"}
JMETER_HOME=${JMETER_HOME:-"/opt/jmeter"}
JBOSS_HOME=${JBOSS_HOME:-"/opt/wildfly"}

log()  { echo "[$(date '+%H:%M:%S')] $*"; }
die()  { echo "ERROR: $*" >&2; exit 1; }

usage() {
  grep '^#' "$0" | grep -v '^#!/' | sed 's/^# \{0,2\}//'
  exit 0
}

# ── 인자 파싱 ────────────────────────────────────────────────────────────────
while getopts "t:u:d:r:s:n:h" opt; do
  case "${opt}" in
    t) TEST_TYPE="${OPTARG}" ;;
    u) USERS="${OPTARG}"     ;;
    d) DURATION="${OPTARG}"  ;;
    r) RAMP="${OPTARG}"      ;;
    s) TOOL="${OPTARG}"      ;;
    n) REPEAT="${OPTARG}"    ;;
    h) usage                 ;;
    *) die "알 수 없는 옵션. -h로 도움말 확인" ;;
  esac
done

# ── 유효성 검사 ──────────────────────────────────────────────────────────────
case "${TEST_TYPE}" in
  read|write|mixed|endurance) ;;
  *) die "테스트 유형(-t): read | write | mixed | endurance" ;;
esac
case "${TOOL}" in
  gatling|jmeter) ;;
  *) die "테스트 도구(-s): gatling | jmeter" ;;
esac

# Gatling simulation 클래스 매핑
declare -A SIM_MAP
SIM_MAP["read"]="wildfly.ReadApiSimulation"
SIM_MAP["write"]="wildfly.WriteApiSimulation"
SIM_MAP["mixed"]="wildfly.MixedLoadSimulation"
SIM_MAP["endurance"]="wildfly.EnduranceSimulation"
SIM_CLASS="${SIM_MAP[${TEST_TYPE}]}"

mkdir -p "${RUN_DIR}"

# ── 테스트 실행 설정 요약 출력 ───────────────────────────────────────────────
print_config() {
  log "=============================================="
  log "WildFly 26 성능테스트 실행 설정"
  log "=============================================="
  log "  테스트 유형  : ${TEST_TYPE}"
  log "  도구         : ${TOOL}"
  log "  동시 사용자  : ${USERS}"
  log "  램프업 시간  : ${RAMP}s"
  log "  지속 시간    : ${DURATION}s"
  log "  반복 횟수    : ${REPEAT}회"
  log "  대상 서버    : ${BASE_URL}${APP_CONTEXT}"
  log "  결과 경로    : ${RUN_DIR}"
  log "=============================================="
}

# ── 사전 점검 ────────────────────────────────────────────────────────────────
run_pre_check() {
  log "[1/5] 사전 점검 실행..."
  if ! BASE_URL="${BASE_URL}" APP_CONTEXT="${APP_CONTEXT}" \
       RESULTS_DIR="${RUN_DIR}" \
       bash "${SCRIPT_DIR}/pre-test-check.sh"; then
    die "사전 점검 실패. 환경을 확인하세요."
  fi
  log "사전 점검 완료"
}

# ── 모니터링 백그라운드 시작 ─────────────────────────────────────────────────
MONITOR_PIDS=()

start_monitoring() {
  log "[2/5] 모니터링 시작..."

  # WildFly PID 확인
  WF_PID=$(pgrep -f "jboss-modules" | head -1 2>/dev/null || echo "")

  # WildFly 통계 수집
  bash "${ROOT_DIR}/monitoring/collect-wildfly-stats.sh" 10 "${RUN_DIR}" &
  MONITOR_PIDS+=($!)
  log "  WildFly 통계 수집 시작 (PID: ${MONITOR_PIDS[-1]})"

  # OS 메트릭 수집
  bash "${ROOT_DIR}/monitoring/collect-os-metrics.sh" 5 "${RUN_DIR}" &
  MONITOR_PIDS+=($!)
  log "  OS 메트릭 수집 시작 (PID: ${MONITOR_PIDS[-1]})"

  # JVM 메트릭 수집 (PID가 있을 때만)
  if [[ -n "${WF_PID}" ]]; then
    bash "${ROOT_DIR}/monitoring/collect-jvm-metrics.sh" "${WF_PID}" 5 "${RUN_DIR}" &
    MONITOR_PIDS+=($!)
    log "  JVM 메트릭 수집 시작 (PID: ${MONITOR_PIDS[-1]}, WF_PID: ${WF_PID})"
  else
    log "  ⚠ WildFly PID 미확인 - JVM 메트릭 수집 생략"
  fi

  # 테스트 시작 시점의 WildFly 통계 스냅샷
  {
    echo "=== 테스트 시작 스냅샷 (${TIMESTAMP}) ==="
    "${JBOSS_HOME}/bin/jboss-cli.sh" --connect \
      --command="/subsystem=datasources:read-resource(include-runtime=true)" \
      2>/dev/null || echo "WildFly CLI 접근 불가"
  } > "${RUN_DIR}/snapshot_start.txt" 2>&1

  sleep 3  # 모니터링 안정화 대기
}

# ── 모니터링 종료 ────────────────────────────────────────────────────────────
stop_monitoring() {
  log "[4/5] 모니터링 종료..."

  # 테스트 종료 시점 스냅샷
  {
    echo "=== 테스트 종료 스냅샷 ==="
    "${JBOSS_HOME}/bin/jboss-cli.sh" --connect \
      --command="/subsystem=datasources:read-resource(include-runtime=true)" \
      2>/dev/null || echo "WildFly CLI 접근 불가"
  } > "${RUN_DIR}/snapshot_end.txt" 2>&1

  for pid in "${MONITOR_PIDS[@]}"; do
    kill "${pid}" 2>/dev/null && log "  모니터링 프로세스(${pid}) 종료" || true
  done
  MONITOR_PIDS=()
}

# ── 부하 실행 (Gatling) ──────────────────────────────────────────────────────
run_gatling() {
  local run_num=$1
  local result_dir="${RUN_DIR}/gatling_run${run_num}"
  mkdir -p "${result_dir}"

  log "  Gatling 실행 (${run_num}/${REPEAT}): ${SIM_CLASS}"
  "${GATLING_HOME}/bin/gatling.sh" \
    -s "${SIM_CLASS}" \
    -rd "WildFly-${TEST_TYPE}-run${run_num}-${TIMESTAMP}" \
    -rf "${result_dir}" \
    -DbaseUrl="${BASE_URL}" \
    -DappContext="${APP_CONTEXT}" \
    -DtargetUsers="${USERS}" \
    -DrampDuration="${RAMP}" \
    -DholdDuration="${DURATION}" \
    2>&1 | tee "${result_dir}/gatling.log"

  log "  결과 저장: ${result_dir}"
}

# ── 부하 실행 (JMeter) ───────────────────────────────────────────────────────
run_jmeter() {
  local run_num=$1
  local jtl_file="${RUN_DIR}/jmeter_run${run_num}.jtl"
  local report_dir="${RUN_DIR}/jmeter_report_run${run_num}"

  log "  JMeter 실행 (${run_num}/${REPEAT})"
  "${JMETER_HOME}/bin/jmeter" -n \
    -t "${ROOT_DIR}/jmeter/wildfly-load-test.jmx" \
    -Jhost="${BASE_URL#http://}" \
    -Jport="8080" \
    -Jctx="${APP_CONTEXT}" \
    -Jusers="${USERS}" \
    -Jramp="${RAMP}" \
    -Jduration="${DURATION}" \
    -l "${jtl_file}" \
    -e -o "${report_dir}" \
    2>&1 | tee "${RUN_DIR}/jmeter_run${run_num}.log"

  log "  결과 저장: ${jtl_file}"
  log "  HTML 리포트: ${report_dir}/index.html"
}

# ── 부하 실행 루프 ────────────────────────────────────────────────────────────
run_load_tests() {
  log "[3/5] 부하 테스트 실행 (${REPEAT}회 반복)..."

  for i in $(seq 1 "${REPEAT}"); do
    log "--- 테스트 실행 ${i}/${REPEAT} 시작 ---"

    case "${TOOL}" in
      gatling) run_gatling "${i}" ;;
      jmeter)  run_jmeter  "${i}" ;;
    esac

    if (( i < REPEAT )); then
      log "다음 실행까지 30초 대기 (GC/풀 안정화)..."
      sleep 30
    fi
  done
}

# ── 사후 분석 ────────────────────────────────────────────────────────────────
run_post_analysis() {
  log "[5/5] 사후 분석 실행..."
  bash "${SCRIPT_DIR}/post-test-analysis.sh" "${RUN_DIR}" 2>&1 | \
    tee "${RUN_DIR}/post-analysis.log" || log "⚠ 분석 중 일부 오류 발생 (결과는 확인 가능)"
}

# ── 예외 처리: Ctrl+C 시 모니터링 정리 ──────────────────────────────────────
cleanup() {
  log "인터럽트 감지 - 정리 중..."
  stop_monitoring
  log "중단된 결과: ${RUN_DIR}"
  exit 130
}
trap cleanup INT TERM

# ── 메인 실행 흐름 ────────────────────────────────────────────────────────────
print_config
run_pre_check
start_monitoring
run_load_tests
stop_monitoring
run_post_analysis

log "=============================================="
log "성능테스트 완료"
log "결과 경로: ${RUN_DIR}"
log "=============================================="
