#!/usr/bin/env bash
# ============================================================
# 성능테스트 사전 점검 스크립트
# - 테스트 시작 전 환경/서비스 상태를 자동 점검
# - 사용법: ./pre-test-check.sh
# ============================================================

set -euo pipefail

# ── config.env 자동 로드 ─────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/../config.env"
if [[ -f "${CONFIG_FILE}" ]]; then
  # shellcheck disable=SC1090
  source "${CONFIG_FILE}"
fi

BASE_URL=${BASE_URL:-"http://localhost:8080"}
APP_CONTEXT=${APP_CONTEXT:-""}
JBOSS_HOME=${JBOSS_HOME:-"/opt/wildfly"}
RESULTS_DIR=${RESULTS_DIR:-"$(dirname "$0")/../results"}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CHECK_REPORT="${RESULTS_DIR}/pre-check-${TIMESTAMP}.txt"

mkdir -p "${RESULTS_DIR}"

OK=0
WARN=0
FAIL=0

log()  { echo "[$(date '+%H:%M:%S')] $*" | tee -a "${CHECK_REPORT}"; }
ok()   { echo "  ✓ $*" | tee -a "${CHECK_REPORT}"; (( OK++ ))  || true; }
warn() { echo "  ⚠ $*" | tee -a "${CHECK_REPORT}"; (( WARN++ )) || true; }
fail() { echo "  ✗ $*" | tee -a "${CHECK_REPORT}"; (( FAIL++ )) || true; }

check_header() {
  log "=========================================="
  log "WildFly 성능테스트 사전 점검"
  log "시작 시각: $(date)"
  log "대상 서버: ${BASE_URL}${APP_CONTEXT}"
  log "=========================================="
}

# ── 1. WildFly 프로세스 확인 ────────────────────────────────────────────────
check_wildfly_process() {
  log ""
  log "[ 1. WildFly 프로세스 ]"
  if pgrep -f "jboss-modules" > /dev/null 2>&1; then
    local wf_pid
    wf_pid=$(pgrep -f "jboss-modules" | head -1)
    ok "WildFly 실행 중 (PID: ${wf_pid})"

    # JVM 힙 설정 확인
    local xmx
    xmx=$(cat /proc/${wf_pid}/cmdline 2>/dev/null | tr '\0' '\n' | grep -i "xmx" | head -1 || echo "미확인")
    log "    JVM Xmx: ${xmx}"

    # File descriptor 한도 확인
    local fd_soft
    fd_soft=$(cat /proc/${wf_pid}/limits 2>/dev/null | awk '/open files/{print $4}' || echo "N/A")
    if [[ "${fd_soft}" == "N/A" ]] || (( fd_soft < 10000 )); then
      warn "File Descriptor 한도 낮음 (${fd_soft}) - ulimit -n 65535 권장"
    else
      ok "File Descriptor 한도: ${fd_soft}"
    fi
  else
    fail "WildFly 프로세스 없음 - 서비스 기동 필요"
    return 1
  fi
}

# ── 2. 헬스체크 엔드포인트 ──────────────────────────────────────────────────
check_health_endpoint() {
  log ""
  log "[ 2. 헬스체크 ]"

  local endpoints=(
    "${BASE_URL}/health"
    "${BASE_URL}${APP_CONTEXT}/actuator/health"
    "${BASE_URL}${APP_CONTEXT}/api/health"
  )

  local checked=false
  for ep in "${endpoints[@]}"; do
    local status_code
    status_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "${ep}" 2>/dev/null || echo "000")
    if [[ "${status_code}" == "200" ]]; then
      ok "헬스체크 정상: ${ep} (${status_code})"
      checked=true
      break
    fi
  done

  if ! ${checked}; then
    warn "헬스체크 엔드포인트 응답 없음 - 직접 확인 필요"
  fi

  # WildFly Management API
  local mgmt_url="http://${WILDFLY_MGMT_HOST:-127.0.0.1}:${WILDFLY_MGMT_PORT:-9990}/management"
  local mgmt_status
  mgmt_status=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "${mgmt_url}" 2>/dev/null || echo "000")
  if [[ "${mgmt_status}" =~ ^[234] ]]; then
    ok "WildFly Management API 접근 가능"
  else
    warn "WildFly Management API 접근 불가 (${mgmt_status}) - 모니터링 스크립트 실행 불가"
  fi
}

# ── 3. JVM 메모리 상태 확인 ─────────────────────────────────────────────────
check_jvm_memory() {
  log ""
  log "[ 3. JVM 메모리 ]"
  if ! pgrep -f "jboss-modules" > /dev/null 2>&1; then return; fi

  local wf_pid
  wf_pid=$(pgrep -f "jboss-modules" | head -1)

  # JAVA_HOME 후보를 순서대로 탐색
  local java_home=""
  for candidate in \
      "${JAVA_HOME:-}" \
      "/usr/lib/jvm/java-1.8.0" \
      "/usr/lib/jvm/java-11-openjdk" \
      "/usr/lib/jvm/java-11" \
      "/usr/lib/jvm/java-17-openjdk" \
      "$(dirname "$(readlink -f "$(which java)" 2>/dev/null)" 2>/dev/null)/.."; do
    [[ -x "${candidate}/bin/jstat" ]] && java_home="${candidate}" && break
  done

  if [[ -z "${java_home}" ]]; then
    warn "jstat 없음 (JDK 미설치 또는 JAVA_HOME 경로 확인 필요) - JVM 메모리 점검 생략"
    return
  fi

  # 5초 타임아웃으로 jstat 실행 (hang 방지)
  local gc_info
  gc_info=$(timeout 5 "${java_home}/bin/jstat" -gcutil "${wf_pid}" 1 2>/dev/null | tail -1 || echo "")

  if [[ -n "${gc_info}" ]]; then
    read -r S0 S1 E O M CCS YGC YGCT FGC FGCT CGC CGCT GCT <<< "${gc_info}"
    log "    Eden: ${E}% | Old: ${O}% | Meta: ${M}%"
    log "    YoungGC: ${YGC}회 (${YGCT}s) | FullGC: ${FGC}회 (${FGCT}s)"

    if (( $(echo "${O} > 80" | bc -l 2>/dev/null || echo 0) )); then
      warn "Old Gen 사용률 ${O}% - Heap 부족 또는 누수 의심, 재기동 권장"
    else
      ok "Heap 상태 정상 (Old Gen ${O}%)"
    fi

    if (( FGC > 0 )); then
      warn "Full GC ${FGC}회 이력 있음 - 테스트 전 WildFly 재기동 권장"
    fi
  else
    warn "jstat 응답 없음 (5초 타임아웃) - JVM 접근 권한 또는 프로세스 상태 확인"
  fi
}

# ── 4. OS 리소스 확인 ───────────────────────────────────────────────────────
check_os_resources() {
  log ""
  log "[ 4. OS 리소스 ]"

  # CPU 부하
  local load1
  load1=$(awk '{print $1}' /proc/loadavg)
  local cpu_cores
  cpu_cores=$(nproc)
  if (( $(echo "${load1} > ${cpu_cores}" | bc -l 2>/dev/null || echo 0) )); then
    warn "현재 CPU Load (${load1}) > CPU 코어 수 (${cpu_cores}) - 부하 상태 확인"
  else
    ok "CPU Load 정상: ${load1} (코어: ${cpu_cores})"
  fi

  # 메모리
  local mem_avail mem_total
  mem_avail=$(awk '/^MemAvailable:/{print int($2/1024)}' /proc/meminfo)
  mem_total=$(awk '/^MemTotal:/{print int($2/1024)}' /proc/meminfo)
  local avail_pct=$(( mem_avail * 100 / mem_total ))
  if (( avail_pct < 20 )); then
    warn "가용 메모리 부족: ${mem_avail}MB (${avail_pct}%) - 다른 프로세스 정리 권장"
  else
    ok "가용 메모리: ${mem_avail}MB (${avail_pct}%)"
  fi

  # Swap
  local swap_used
  swap_used=$(awk '/^SwapTotal:/{total=$2} /^SwapFree:/{free=$2} END{print int((total-free)/1024)}' /proc/meminfo)
  if (( swap_used > 100 )); then
    warn "Swap 사용 중: ${swap_used}MB - JVM 성능에 심각한 영향"
  else
    ok "Swap 미사용"
  fi

  # TIME_WAIT 소켓
  if command -v ss &>/dev/null; then
    local time_wait
    time_wait=$(ss -tan 2>/dev/null | grep -c "TIME-WAIT" || echo 0)
    if (( time_wait > 5000 )); then
      warn "TIME_WAIT 소켓 과다: ${time_wait}개 - tcp_tw_reuse=1 설정 권장"
    else
      ok "TIME_WAIT 소켓: ${time_wait}개"
    fi
  fi
}

# ── 5. 디스크 여유 공간 확인 ────────────────────────────────────────────────
check_disk_space() {
  log ""
  log "[ 5. 디스크 공간 ]"

  local dirs=(
    "${RESULTS_DIR}"
    "${JBOSS_HOME}/standalone/log"
    "/tmp"
  )

  for dir in "${dirs[@]}"; do
    [[ -d "${dir}" ]] || continue
    local avail_kb
    avail_kb=$(df -k "${dir}" 2>/dev/null | tail -1 | awk '{print $4}')
    local avail_gb=$(( avail_kb / 1024 / 1024 ))
    if (( avail_gb < 2 )); then
      warn "${dir}: 여유 공간 ${avail_gb}GB 부족 - 로그 정리 필요"
    else
      ok "${dir}: 여유 공간 ${avail_gb}GB"
    fi
  done
}

# ── 6. 테스트 데이터 확인 ────────────────────────────────────────────────────
check_test_data() {
  log ""
  log "[ 6. 테스트 데이터 피더 파일 ]"

  local resources_dir="$(dirname "$0")/../gatling/resources"
  local required_files=("item_ids.csv" "users_with_auth.csv" "search_keywords.csv")

  for f in "${required_files[@]}"; do
    local fpath="${resources_dir}/${f}"
    if [[ -f "${fpath}" ]]; then
      local line_count
      line_count=$(wc -l < "${fpath}" 2>/dev/null || echo 0)
      if (( line_count < 10 )); then
        warn "${f}: 데이터 ${line_count}건으로 부족 - 최소 100건 이상 권장"
      else
        ok "${f}: ${line_count}건"
      fi
    else
      warn "${f} 없음 - generate-test-data.sh 실행 필요"
    fi
  done
}

# ── 최종 요약 ────────────────────────────────────────────────────────────────
print_summary() {
  log ""
  log "=========================================="
  log "점검 결과 요약"
  log "=========================================="
  log "  정상(✓): ${OK}개"
  log "  경고(⚠): ${WARN}개"
  log "  실패(✗): ${FAIL}개"
  log ""

  if (( FAIL > 0 )); then
    log "결론: ✗ FAIL - 실패 항목 해결 후 테스트 시작"
    log ""
    exit 1
  elif (( WARN > 3 )); then
    log "결론: ⚠ WARN - 경고 항목 확인 권장 후 시작 가능"
  else
    log "결론: ✓ OK - 테스트 시작 가능"
  fi

  log "보고서: ${CHECK_REPORT}"
}

# ── 실행 ─────────────────────────────────────────────────────────────────────
check_header
check_wildfly_process
check_health_endpoint
check_jvm_memory
check_os_resources
check_disk_space
check_test_data
print_summary
