#!/usr/bin/env bash
# ============================================================
# 성능테스트 사후 분석 스크립트
# - Gatling/JMeter 결과 요약
# - WildFly/OS/JVM 수집 데이터 분석
# - 병목 지점 자동 탐지
# 사용법: ./post-test-analysis.sh [결과 디렉토리]
# ============================================================

set -euo pipefail

RUN_DIR=${1:-"$(dirname "$0")/../results/$(ls -t "$(dirname "$0")/../results" | head -1)"}
ANALYSIS_FILE="${RUN_DIR}/analysis_report.txt"
BOTTLENECK_FILE="${RUN_DIR}/bottleneck_hints.txt"

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "${ANALYSIS_FILE}"; }
section() {
  echo "" | tee -a "${ANALYSIS_FILE}"
  echo "══════════════════════════════════════════════════" | tee -a "${ANALYSIS_FILE}"
  echo "  $*" | tee -a "${ANALYSIS_FILE}"
  echo "══════════════════════════════════════════════════" | tee -a "${ANALYSIS_FILE}"
}

> "${ANALYSIS_FILE}"
> "${BOTTLENECK_FILE}"

hint() { echo "⚠ $*" | tee -a "${BOTTLENECK_FILE}"; }

log "WildFly 26 성능테스트 분석 보고서"
log "분석 대상: ${RUN_DIR}"
log "생성 시각: $(date)"

# ── 1. Gatling 결과 요약 ─────────────────────────────────────────────────────
analyze_gatling() {
  section "1. Gatling 결과 요약"

  local sim_log
  sim_log=$(find "${RUN_DIR}" -name "simulation.log" 2>/dev/null | head -1 || echo "")

  if [[ -z "${sim_log}" ]]; then
    log "Gatling simulation.log 없음 (JMeter 결과 섹션 확인)"
    return
  fi

  log "파일: ${sim_log}"
  log ""

  # REQUEST 라인 파싱: REQUEST\t그룹\t이름\t시작ms\t종료ms\tOK/KO\t메시지
  local total ok_count ko_count
  total=$(  grep -c "^REQUEST" "${sim_log}" || echo 0)
  ok_count=$(grep "^REQUEST" "${sim_log}" | awk -F'\t' '$6=="OK"'  | wc -l || echo 0)
  ko_count=$(grep "^REQUEST" "${sim_log}" | awk -F'\t' '$6=="KO"'  | wc -l || echo 0)

  local error_rate=0
  (( total > 0 )) && error_rate=$(echo "${ko_count} ${total}" | awk '{printf "%.2f", $1/$2*100}')

  log "전체 요청: ${total}건"
  log "성공(OK): ${ok_count}건"
  log "실패(KO): ${ko_count}건  (에러율: ${error_rate}%)"

  # 응답시간 백분위 계산
  log ""
  log "[ 응답시간 분포 (전체) ]"
  grep "^REQUEST" "${sim_log}" | awk -F'\t' '
    {
      duration = $5 - $4
      if (duration >= 0) {
        times[NR] = duration
        sum += duration
        count++
      }
    }
    END {
      if (count == 0) exit
      n = asort(times)
      printf "  평균: %dms\n", sum/count
      printf "  최소: %dms\n", times[1]
      printf "  최대: %dms\n", times[n]
      printf "  p50:  %dms\n", times[int(n*0.50)+1]
      printf "  p75:  %dms\n", times[int(n*0.75)+1]
      printf "  p90:  %dms\n", times[int(n*0.90)+1]
      printf "  p95:  %dms\n", times[int(n*0.95)+1]
      printf "  p99:  %dms\n", times[int(n*0.99)+1]
    }
  ' | tee -a "${ANALYSIS_FILE}"

  # 시나리오별 요약
  log ""
  log "[ 시나리오별 응답시간 ]"
  grep "^REQUEST" "${sim_log}" | awk -F'\t' '
    {
      name = $3
      duration = $5 - $4
      if (duration >= 0) {
        sum[name] += duration
        cnt[name]++
        if (duration > max[name]) max[name] = duration
        if ($6 == "KO") err[name]++
      }
    }
    END {
      printf "  %-40s %8s %8s %8s %6s\n", "시나리오", "건수", "평균ms", "최대ms", "에러"
      printf "  %-40s %8s %8s %8s %6s\n", "--------", "----", "------", "------", "----"
      for (n in cnt) {
        avg = sum[n]/cnt[n]
        printf "  %-40s %8d %8.0f %8d %6d\n", n, cnt[n], avg, max[n], err[n]+0
      }
    }
  ' | tee -a "${ANALYSIS_FILE}"

  # 에러율 경보
  if (( $(echo "${error_rate} > 0.1" | bc -l 2>/dev/null || echo 0) )); then
    hint "에러율 ${error_rate}% > 기준 0.1%"
  fi

  # KO 에러 메시지 상위 5개
  if (( ko_count > 0 )); then
    log ""
    log "[ 에러 유형 상위 5개 ]"
    grep "^REQUEST" "${sim_log}" | awk -F'\t' '$6=="KO"{print $7}' | \
      sort | uniq -c | sort -rn | head 5 | tee -a "${ANALYSIS_FILE}"
  fi
}

# ── 2. JMeter 결과 요약 (.jtl 파일 기반) ────────────────────────────────────
analyze_jmeter() {
  section "2. JMeter 결과 요약"

  local jtl_files
  jtl_files=$(find "${RUN_DIR}" -name "*.jtl" 2>/dev/null || echo "")

  if [[ -z "${jtl_files}" ]]; then
    log "JMeter .jtl 파일 없음"
    return
  fi

  for jtl in ${jtl_files}; do
    log "파일: $(basename "${jtl}")"
    # JTL CSV 형식: timeStamp,elapsed,label,responseCode,responseMessage,
    #               threadName,dataType,success,failureMessage,bytes,...
    awk -F',' 'NR>1 {
      label = $3
      elapsed = $2
      success = $8
      sum[label] += elapsed
      cnt[label]++
      if (success != "true") err[label]++
      all_times[NR] = elapsed
      total_sum += elapsed
      total_cnt++
      if (success != "true") total_err++
    }
    END {
      if (total_cnt == 0) exit
      printf "  전체 요청: %d건  평균: %.0fms  에러율: %.2f%%\n",
        total_cnt, total_sum/total_cnt, total_err/total_cnt*100
      printf "\n"
      printf "  %-40s %8s %8s %6s\n", "Label", "건수", "평균ms", "에러수"
      for (l in cnt) {
        printf "  %-40s %8d %8.0f %6d\n", l, cnt[l], sum[l]/cnt[l], err[l]+0
      }
    }' "${jtl}" | tee -a "${ANALYSIS_FILE}"
    echo "" | tee -a "${ANALYSIS_FILE}"
  done
}

# ── 3. WildFly 통계 분석 ─────────────────────────────────────────────────────
analyze_wildfly_stats() {
  section "3. WildFly Datasource 풀 분석"

  local stats_file
  stats_file=$(find "${RUN_DIR}" -name "wildfly_stats_*.csv" 2>/dev/null | head -1 || echo "")

  if [[ -z "${stats_file}" ]]; then
    log "WildFly 통계 파일 없음 (collect-wildfly-stats.sh 미실행)"
    return
  fi

  log "파일: $(basename "${stats_file}")"
  log ""

  awk -F',' 'NR==1{next}
    {
      ds = $2
      in_use = $4+0
      wait   = $6+0
      blk    = $9+0
      if (in_use > max_inuse[ds])  max_inuse[ds] = in_use
      if (wait   > max_wait[ds])   max_wait[ds]  = wait
      blk_total[ds] += blk
      cnt[ds]++
    }
    END {
      printf "  %-30s %12s %12s %16s\n", "DataSource", "최대InUse", "최대Wait", "BlockFailure계"
      printf "  %-30s %12s %12s %16s\n", "----------", "---------", "--------", "---------------"
      for (ds in cnt) {
        printf "  %-30s %12d %12d %16d\n", ds, max_inuse[ds], max_wait[ds], blk_total[ds]
        if (max_wait[ds] > 0)       hint_arr[ds] = "wait_count"
        if (blk_total[ds] > 0)      hint_arr[ds] = "blocking_failure"
      }
    }
  ' OFS=',' "${stats_file}" | tee -a "${ANALYSIS_FILE}"

  # wait-count 경보
  local max_wait
  max_wait=$(awk -F',' 'NR>1{if($6+0>m)m=$6+0}END{print m+0}' "${stats_file}")
  if (( max_wait > 0 )); then
    hint "DS wait_count 최대 ${max_wait} - max-pool-size 증가 또는 쿼리 최적화 필요"
  fi

  local blk_total
  blk_total=$(awk -F',' 'NR>1{s+=$9+0}END{print s+0}' "${stats_file}")
  if (( blk_total > 0 )); then
    hint "DS blocking_failure_count 합계 ${blk_total} - 즉시 조치 필요 (blocking-timeout-millis 또는 max-pool-size)"
  fi
}

# ── 4. JVM / GC 분석 ─────────────────────────────────────────────────────────
analyze_jvm() {
  section "4. JVM / GC 분석"

  local gc_file
  gc_file=$(find "${RUN_DIR}" -name "gc_stats_*.csv" 2>/dev/null | head -1 || echo "")

  if [[ -z "${gc_file}" ]]; then
    log "GC 통계 파일 없음 (collect-jvm-metrics.sh 미실행)"
  else
    log "[ GC 요약 ]"
    awk -F',' 'NR==1{next}
      {
        ygc = $7+0; fgc = $9+0; gct = $11+0
        gc_overhead = $12+0
        if (gc_overhead > max_overhead) max_overhead = gc_overhead
        if (fgc > max_fgc) max_fgc = fgc
        if (ygc > max_ygc) max_ygc = ygc
        if (gct > max_gct) max_gct = gct
        cnt++
      }
      END {
        if (cnt == 0) exit
        printf "  Young GC 최대 누적: %d회\n", max_ygc
        printf "  Full GC  최대 누적: %d회\n", max_fgc
        printf "  GC 총 시간 최대:    %.3fs\n", max_gct
        printf "  GC 오버헤드 최대:   %.1f%%\n", max_overhead
      }
    ' "${gc_file}" | tee -a "${ANALYSIS_FILE}"

    local max_fgc
    max_fgc=$(awk -F',' 'NR>1{if($9+0>m)m=$9+0}END{print m+0}' "${gc_file}")
    local max_overhead
    max_overhead=$(awk -F',' 'NR>1{if($12+0>m)m=$12+0}END{print m+0}' "${gc_file}")

    (( max_fgc > 0 )) && hint "Full GC ${max_fgc}회 발생 - Heap 크기 또는 메모리 누수 점검"
    if (( $(echo "${max_overhead} > 10" | bc -l 2>/dev/null || echo 0) )); then
      hint "GC 오버헤드 최대 ${max_overhead}% - GC 튜닝 또는 Heap 증량 필요"
    fi
  fi

  local thread_file
  thread_file=$(find "${RUN_DIR}" -name "thread_stats_*.csv" 2>/dev/null | head -1 || echo "")

  if [[ -n "${thread_file}" ]]; then
    log ""
    log "[ Thread 상태 요약 ]"
    awk -F',' 'NR==1{next}
      {
        if ($4+0 > max_blocked) max_blocked = $4+0
        if ($2+0 > max_total)   max_total   = $2+0
        if ($3+0 > max_run)     max_run     = $3+0
      }
      END {
        printf "  최대 전체 Thread:   %d개\n", max_total
        printf "  최대 RUNNABLE:      %d개\n", max_run
        printf "  최대 BLOCKED:       %d개\n", max_blocked
      }
    ' "${thread_file}" | tee -a "${ANALYSIS_FILE}"

    local max_blocked
    max_blocked=$(awk -F',' 'NR>1{if($4+0>m)m=$4+0}END{print m+0}' "${thread_file}")
    (( max_blocked > 5 )) && hint "최대 BLOCKED Thread ${max_blocked}개 - Lock 경합 또는 DB 대기 의심 (Thread dump 확인)"
  fi
}

# ── 5. OS 리소스 분석 ────────────────────────────────────────────────────────
analyze_os() {
  section "5. OS 리소스 분석"

  local cpu_file
  cpu_file=$(find "${RUN_DIR}" -name "os_cpu_*.csv" 2>/dev/null | head -1 || echo "")

  if [[ -n "${cpu_file}" ]]; then
    log "[ CPU 사용률 ]"
    awk -F',' 'NR==1{next}
      {
        user=$2+0; sys=$3+0; iowait=$4+0
        total_user+=user; total_sys+=sys; total_iowait+=iowait
        if (user+sys > max_busy) max_busy = user+sys
        if (iowait > max_iowait) max_iowait = iowait
        cnt++
      }
      END {
        if (cnt==0) exit
        printf "  평균 CPU 사용:  User=%.1f%%  Sys=%.1f%%  IOWait=%.1f%%\n",
          total_user/cnt, total_sys/cnt, total_iowait/cnt
        printf "  최대 CPU 사용:  %.1f%%\n",  max_busy
        printf "  최대 IOWait:    %.1f%%\n",  max_iowait
      }
    ' "${cpu_file}" | tee -a "${ANALYSIS_FILE}"

    local max_iowait
    max_iowait=$(awk -F',' 'NR>1{if($4+0>m)m=$4+0}END{printf "%.0f",m+0}' "${cpu_file}")
    local max_cpu
    max_cpu=$(awk -F',' 'NR>1{v=$2+$3; if(v>m)m=v}END{printf "%.0f",m+0}' "${cpu_file}")

    (( max_cpu > 80 ))    && hint "CPU 최대 사용률 ${max_cpu}% - CPU bound. 코드 최적화 또는 Scale-up 검토"
    (( max_iowait > 10 )) && hint "IOWait 최대 ${max_iowait}% - 디스크/DB 네트워크 병목. 슬로우쿼리 확인"
  fi

  local mem_file
  mem_file=$(find "${RUN_DIR}" -name "os_mem_*.csv" 2>/dev/null | head -1 || echo "")

  if [[ -n "${mem_file}" ]]; then
    log ""
    log "[ 메모리 사용률 ]"
    awk -F',' 'NR==1{next}
      {
        used=$3+0; total=$2+0; swap=$7+0
        if (used > max_used) max_used = used
        if (swap > max_swap) max_swap = swap
        last_avail = $6+0
      }
      END {
        printf "  최대 메모리 사용: %dMB\n", max_used
        printf "  최대 Swap 사용:   %dMB\n", max_swap
        printf "  종료 시 가용 메모리: %dMB\n", last_avail
      }
    ' "${mem_file}" | tee -a "${ANALYSIS_FILE}"

    local max_swap
    max_swap=$(awk -F',' 'NR>1{if($7+0>m)m=$7+0}END{print m+0}' "${mem_file}")
    (( max_swap > 100 )) && hint "Swap 최대 ${max_swap}MB 사용 - JVM GC Pause 급증 원인. 메모리 증설 또는 Heap 감소 검토"
  fi

  local tcp_file
  tcp_file=$(find "${RUN_DIR}" -name "os_tcp_*.csv" 2>/dev/null | head -1 || echo "")

  if [[ -n "${tcp_file}" ]]; then
    log ""
    log "[ TCP 소켓 현황 ]"
    awk -F',' 'NR==1{next}
      {
        if ($2+0 > max_estab)  max_estab  = $2+0
        if ($7+0 > max_tw)     max_tw     = $7+0
        if ($8+0 > max_cw)     max_cw     = $8+0
      }
      END {
        printf "  최대 ESTABLISHED: %d\n", max_estab
        printf "  최대 TIME_WAIT:   %d\n", max_tw
        printf "  최대 CLOSE_WAIT:  %d\n", max_cw
      }
    ' "${tcp_file}" | tee -a "${ANALYSIS_FILE}"

    local max_tw max_cw
    max_tw=$(awk -F',' 'NR>1{if($7+0>m)m=$7+0}END{print m+0}' "${tcp_file}")
    max_cw=$(awk -F',' 'NR>1{if($8+0>m)m=$8+0}END{print m+0}' "${tcp_file}")

    (( max_tw > 3000 )) && hint "TIME_WAIT 최대 ${max_tw} - tcp_tw_reuse=1, Ephemeral 포트 범위 확장 검토"
    (( max_cw > 100  )) && hint "CLOSE_WAIT 최대 ${max_cw} - 애플리케이션 커넥션 미반환 가능성. 코드 점검"
  fi
}

# ── 6. 병목 진단 요약 ────────────────────────────────────────────────────────
print_bottleneck_summary() {
  section "6. 병목 진단 힌트"

  if [[ ! -s "${BOTTLENECK_FILE}" ]]; then
    log "이상 징후 없음 - 정상 범위 내 동작"
  else
    log "발견된 이상 징후:"
    cat "${BOTTLENECK_FILE}" | tee -a "${ANALYSIS_FILE}"
    log ""
    log "다음 단계 권장 조치:"
    if grep -q "wait_count\|blocking_failure" "${BOTTLENECK_FILE}" 2>/dev/null; then
      log "  1. [DS 풀] max-pool-size 증가 또는 쿼리 처리시간 단축"
    fi
    if grep -q "Full GC\|GC 오버헤드" "${BOTTLENECK_FILE}" 2>/dev/null; then
      log "  2. [GC]  -Xmx 증량, G1HeapRegionSize 조정, 메모리 누수 힙덤프 분석"
    fi
    if grep -q "BLOCKED Thread" "${BOTTLENECK_FILE}" 2>/dev/null; then
      log "  3. [Thread] thread dump 분석 → synchronized 블록 / DB lock 최소화"
    fi
    if grep -q "CPU\|IOWait" "${BOTTLENECK_FILE}" 2>/dev/null; then
      log "  4. [CPU/IO] APM(슬로우쿼리/핫스팟 메서드) 확인 후 코드 최적화"
    fi
    if grep -q "Swap" "${BOTTLENECK_FILE}" 2>/dev/null; then
      log "  5. [Memory] 물리 메모리 증설 또는 Xmx 감소로 OS 여유 확보"
    fi
    if grep -q "TIME_WAIT\|CLOSE_WAIT" "${BOTTLENECK_FILE}" 2>/dev/null; then
      log "  6. [TCP] OS 커널 파라미터 튜닝 (os-kernel-tuning.sh apply)"
    fi
  fi
}

# ── 실행 ─────────────────────────────────────────────────────────────────────
analyze_gatling
analyze_jmeter
analyze_wildfly_stats
analyze_jvm
analyze_os
print_bottleneck_summary

log ""
log "분석 보고서: ${ANALYSIS_FILE}"
log "병목 힌트:   ${BOTTLENECK_FILE}"
