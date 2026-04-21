#!/usr/bin/env bash
# ============================================================
# 성능테스트 최종 보고서 생성 스크립트 (HTML + 텍스트)
# - 여러 회차 결과를 통합하여 편차 및 평균값 산출
# - SLA 기준 충족 여부 판정
# 사용법: ./generate-report.sh [결과_최상위_디렉토리] [SLA_설정파일]
#   예) ./generate-report.sh ../results sla.conf
# ============================================================

set -euo pipefail

RESULTS_BASE=${1:-"$(dirname "$0")/../results"}
SLA_CONF=${2:-"$(dirname "$0")/sla.conf"}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_DIR="${RESULTS_BASE}/final_report_${TIMESTAMP}"

mkdir -p "${REPORT_DIR}"

TEXT_REPORT="${REPORT_DIR}/performance_report.txt"
HTML_REPORT="${REPORT_DIR}/performance_report.html"

log() { echo "$*" | tee -a "${TEXT_REPORT}"; }

# ── SLA 기준값 로드 (없으면 기본값) ─────────────────────────────────────────
load_sla() {
  if [[ -f "${SLA_CONF}" ]]; then
    # shellcheck disable=SC1090
    source "${SLA_CONF}"
  fi
  SLA_P95=${SLA_P95:-500}        # p95 응답시간 (ms)
  SLA_P99=${SLA_P99:-2000}       # p99 응답시간 (ms)
  SLA_ERROR_RATE=${SLA_ERROR_RATE:-0.1}  # 에러율 (%)
  SLA_TPS=${SLA_TPS:-100}        # 목표 TPS
  SLA_DESCRIPTION=${SLA_DESCRIPTION:-"기본 SLA 기준"}
}

# ── 실행 결과 디렉토리 탐색 ──────────────────────────────────────────────────
find_run_dirs() {
  find "${RESULTS_BASE}" -maxdepth 1 -type d -name "run_*" | sort
}

# ── Gatling simulation.log에서 핵심 지표 추출 ────────────────────────────────
extract_gatling_metrics() {
  local run_dir="$1"
  local sim_log
  sim_log=$(find "${run_dir}" -name "simulation.log" 2>/dev/null | head -1 || echo "")
  [[ -z "${sim_log}" ]] && return

  awk -F'\t' '
    /^REQUEST/ {
      duration = $5 - $4
      if (duration < 0) next
      times[NR] = duration
      sum += duration
      count++
      if ($6 == "KO") err++
    }
    END {
      if (count == 0) exit
      n = asort(times)
      # 출력: avg p50 p95 p99 max total err_rate
      avg = sum/count
      p50 = times[int(n*0.50)+1]
      p95 = times[int(n*0.95)+1]
      p99 = times[int(n*0.99)+1]
      max_t = times[n]
      err_rate = err/count*100
      printf "%s\t%.0f\t%d\t%d\t%d\t%d\t%d\t%.2f\n",
        FILENAME, avg, p50, p95, p99, max_t, count, err_rate
    }
  ' "${sim_log}"
}

# ── HTML 보고서 생성 ─────────────────────────────────────────────────────────
generate_html() {
  local runs_data="$1"  # 탭 구분 데이터

  cat > "${HTML_REPORT}" << 'HTML_HEADER'
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>WildFly 26 성능테스트 보고서</title>
<style>
  body { font-family: 'Noto Sans KR', Arial, sans-serif; margin: 24px; color: #222; }
  h1 { border-bottom: 3px solid #1976D2; padding-bottom: 8px; }
  h2 { border-left: 4px solid #1976D2; padding-left: 12px; margin-top: 32px; }
  table { border-collapse: collapse; width: 100%; margin: 16px 0; }
  th { background: #1976D2; color: #fff; padding: 8px 12px; text-align: left; }
  td { padding: 7px 12px; border-bottom: 1px solid #e0e0e0; }
  tr:nth-child(even) { background: #f5f5f5; }
  .pass  { color: #2E7D32; font-weight: bold; }
  .fail  { color: #C62828; font-weight: bold; }
  .warn  { color: #E65100; font-weight: bold; }
  .metric-box { display: inline-block; border: 1px solid #ddd; border-radius: 8px;
    padding: 16px 24px; margin: 8px; min-width: 140px; text-align: center; }
  .metric-box .value { font-size: 2em; font-weight: bold; color: #1976D2; }
  .metric-box .label { color: #757575; font-size: 0.9em; }
  pre { background: #f5f5f5; padding: 12px; border-radius: 4px; overflow-x: auto; }
  .bottleneck { background: #FFF3E0; border: 1px solid #FFB300; border-radius: 4px;
    padding: 12px; margin: 8px 0; }
</style>
</head>
<body>
HTML_HEADER

  echo "<h1>WildFly 26 성능테스트 보고서</h1>" >> "${HTML_REPORT}"
  echo "<p>생성 시각: $(date) | 분석 대상: ${RESULTS_BASE}</p>" >> "${HTML_REPORT}"

  # SLA 기준 표
  cat >> "${HTML_REPORT}" << HTML_SLA
<h2>1. SLA 기준 (${SLA_DESCRIPTION})</h2>
<table>
  <tr><th>지표</th><th>기준</th></tr>
  <tr><td>p95 응답시간</td><td>${SLA_P95}ms 이하</td></tr>
  <tr><td>p99 응답시간</td><td>${SLA_P99}ms 이하</td></tr>
  <tr><td>에러율</td><td>${SLA_ERROR_RATE}% 이하</td></tr>
  <tr><td>목표 TPS</td><td>${SLA_TPS} 이상</td></tr>
</table>
HTML_SLA

  # 회차별 결과
  echo "<h2>2. 회차별 측정 결과</h2>" >> "${HTML_REPORT}"
  echo "<table><tr><th>회차</th><th>평균(ms)</th><th>p50(ms)</th><th>p95(ms)</th><th>p99(ms)</th><th>최대(ms)</th><th>전체요청</th><th>에러율(%)</th><th>p95 판정</th><th>에러율 판정</th></tr>" >> "${HTML_REPORT}"

  local p95_sum=0 p99_sum=0 avg_sum=0 err_sum=0 run_count=0

  while IFS=$'\t' read -r run_name avg p50 p95 p99 max_t total err_rate; do
    run_count=$(( run_count + 1 ))
    p95_sum=$(echo "${p95_sum} ${p95}" | awk '{print $1+$2}')
    p99_sum=$(echo "${p99_sum} ${p99}" | awk '{print $1+$2}')
    avg_sum=$(echo "${avg_sum} ${avg}" | awk '{print $1+$2}')
    err_sum=$(echo "${err_sum} ${err_rate}" | awk '{print $1+$2}')

    local p95_class err_class
    p95_class=$(echo "${p95} ${SLA_P95}" | awk '{print ($1<=$2) ? "pass" : "fail"}')
    err_class=$(echo "${err_rate} ${SLA_ERROR_RATE}" | awk '{print ($1+0<=$2+0) ? "pass" : "fail"}')

    echo "<tr>
      <td>$(basename "${run_name}")</td>
      <td>${avg}</td><td>${p50}</td>
      <td class=\"${p95_class}\">${p95}</td>
      <td>${p99}</td><td>${max_t}</td><td>${total}</td>
      <td class=\"${err_class}\">${err_rate}</td>
      <td class=\"${p95_class}\">${p95_class^^}</td>
      <td class=\"${err_class}\">${err_class^^}</td>
    </tr>" >> "${HTML_REPORT}"
  done <<< "${runs_data}"

  # 평균 요약 행
  if (( run_count > 1 )); then
    local avg_p95 avg_err
    avg_p95=$(echo "${p95_sum} ${run_count}" | awk '{printf "%.0f", $1/$2}')
    avg_err=$(echo "${err_sum} ${run_count}" | awk '{printf "%.2f", $1/$2}')
    local avg_class err_class
    avg_class=$(echo "${avg_p95} ${SLA_P95}" | awk '{print ($1<=$2) ? "pass" : "fail"}')
    err_class=$(echo "${avg_err} ${SLA_ERROR_RATE}" | awk '{print ($1+0<=$2+0) ? "pass" : "fail"}')
    echo "<tr style='font-weight:bold;background:#E3F2FD'>
      <td>평균</td><td>-</td><td>-</td>
      <td class=\"${avg_class}\">${avg_p95}</td>
      <td>-</td><td>-</td><td>-</td>
      <td class=\"${err_class}\">${avg_err}</td>
      <td class=\"${avg_class}\">${avg_class^^}</td>
      <td class=\"${err_class}\">${err_class^^}</td>
    </tr>" >> "${HTML_REPORT}"
  fi
  echo "</table>" >> "${HTML_REPORT}"

  # 병목 힌트 섹션
  echo "<h2>3. 병목 진단 힌트</h2>" >> "${HTML_REPORT}"
  local bottleneck_files
  bottleneck_files=$(find "${RESULTS_BASE}" -name "bottleneck_hints.txt" 2>/dev/null || echo "")
  if [[ -n "${bottleneck_files}" ]]; then
    while IFS= read -r bf; do
      echo "<div class='bottleneck'><b>$(dirname "${bf}" | xargs basename):</b><pre>" >> "${HTML_REPORT}"
      cat "${bf}" >> "${HTML_REPORT}"
      echo "</pre></div>" >> "${HTML_REPORT}"
    done <<< "${bottleneck_files}"
  else
    echo "<p>이상 징후 없음</p>" >> "${HTML_REPORT}"
  fi

  echo "<h2>4. WildFly 설정 스냅샷</h2>" >> "${HTML_REPORT}"
  local snap
  snap=$(find "${RESULTS_BASE}" -name "snapshot_start.txt" 2>/dev/null | head -1 || echo "")
  if [[ -n "${snap}" ]]; then
    echo "<pre>" >> "${HTML_REPORT}"
    head -50 "${snap}" >> "${HTML_REPORT}"
    echo "</pre>" >> "${HTML_REPORT}"
  fi

  echo "</body></html>" >> "${HTML_REPORT}"
}

# ── 텍스트 보고서 생성 ───────────────────────────────────────────────────────
generate_text_report() {
  local runs_data="$1"

  load_sla

  log "============================================================"
  log "WildFly 26 성능테스트 최종 보고서"
  log "생성: $(date)"
  log "============================================================"

  log ""
  log "[ SLA 기준: ${SLA_DESCRIPTION} ]"
  log "  p95 응답시간 : ${SLA_P95}ms 이하"
  log "  p99 응답시간 : ${SLA_P99}ms 이하"
  log "  에러율       : ${SLA_ERROR_RATE}% 이하"
  log "  목표 TPS     : ${SLA_TPS} 이상"

  log ""
  log "[ 회차별 결과 ]"
  printf "  %-12s %8s %8s %8s %8s %8s %6s\n" \
    "회차" "avg(ms)" "p50(ms)" "p95(ms)" "p99(ms)" "max(ms)" "에러율" | tee -a "${TEXT_REPORT}"
  printf "  %-12s %8s %8s %8s %8s %8s %6s\n" \
    "----" "-------" "-------" "-------" "-------" "-------" "------" | tee -a "${TEXT_REPORT}"

  local run_count=0 p95_sum=0 err_sum=0 sla_pass=0 sla_fail=0

  while IFS=$'\t' read -r run_name avg p50 p95 p99 max_t total err_rate; do
    run_count=$(( run_count + 1 ))
    p95_sum=$(echo "${p95_sum} ${p95}" | awk '{print $1+$2}')
    err_sum=$(echo "${err_sum} ${err_rate}" | awk '{print $1+$2}')

    local verdict="PASS"
    if awk -v p="${p95}" -v sp="${SLA_P95}" -v e="${err_rate}" -v se="${SLA_ERROR_RATE}" \
         'BEGIN{exit !( p > sp || e > se )}'; then
      verdict="FAIL"
      sla_fail=$(( sla_fail + 1 ))
    else
      sla_pass=$(( sla_pass + 1 ))
    fi

    printf "  %-12s %8.0f %8d %8d %8d %8d %5.2f%%  [%s]\n" \
      "run${run_count}" "${avg}" "${p50}" "${p95}" "${p99}" "${max_t}" "${err_rate}" "${verdict}" \
      | tee -a "${TEXT_REPORT}"
  done <<< "${runs_data}"

  log ""
  if (( run_count > 1 )); then
    local avg_p95 avg_err
    avg_p95=$(echo "${p95_sum} ${run_count}" | awk '{printf "%.0f", $1/$2}')
    avg_err=$(echo "${err_sum} ${run_count}" | awk '{printf "%.2f", $1/$2}')
    log "[ 평균 (${run_count}회) ] p95=${avg_p95}ms  에러율=${avg_err}%"
  fi

  log ""
  log "[ 최종 판정 ]"
  if (( sla_fail == 0 )); then
    log "  ✓ PASS - 모든 회차 SLA 기준 충족 (${sla_pass}/${run_count})"
  else
    log "  ✗ FAIL - SLA 미충족 회차 ${sla_fail}/${run_count}"
  fi
}

# ── 메인 실행 ────────────────────────────────────────────────────────────────
load_sla

RUNS_DATA=""
while IFS= read -r run_dir; do
  metrics=$(extract_gatling_metrics "${run_dir}")
  [[ -n "${metrics}" ]] && RUNS_DATA+="${metrics}"$'\n'
done < <(find_run_dirs)

if [[ -z "${RUNS_DATA}" ]]; then
  echo "분석할 Gatling 결과 없음: ${RESULTS_BASE}"
  echo "JMeter 결과는 post-test-analysis.sh로 확인하세요."
  exit 0
fi

generate_text_report "${RUNS_DATA}"
generate_html "${RUNS_DATA}"

log ""
log "보고서 생성 완료:"
log "  텍스트: ${TEXT_REPORT}"
log "  HTML:   ${HTML_REPORT}"
