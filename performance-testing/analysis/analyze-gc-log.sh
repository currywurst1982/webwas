#!/usr/bin/env bash
# ============================================================
# GC 로그 분석 스크립트 (Java 11+ Unified GC Logging 형식)
# - -Xlog:gc* 로그 파일 분석
# - Young GC / Full GC / GC Pause / GC 오버헤드 도출
# 사용법: ./analyze-gc-log.sh [GC로그파일] [출력경로]
#   예) ./analyze-gc-log.sh /var/log/wildfly/gc/gc_2024.log
# ============================================================

set -euo pipefail

GC_LOG=${1:-""}
OUTPUT_DIR=${2:-"$(dirname "$0")/../results"}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

if [[ -z "${GC_LOG}" ]] || [[ ! -f "${GC_LOG}" ]]; then
  echo "사용법: $0 <GC 로그 파일> [출력 디렉토리]"
  echo "GC 로그 활성화 방법 (jvm-options.conf 참조):"
  echo "  -Xlog:gc*:file=/var/log/wildfly/gc/gc_%t.log:time,uptime:filecount=5,filesize=100m"
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"
REPORT="${OUTPUT_DIR}/gc_analysis_${TIMESTAMP}.txt"

log() { echo "$*" | tee -a "${REPORT}"; }

log "============================================================"
log "GC 로그 분석 보고서"
log "대상 파일: ${GC_LOG}"
log "파일 크기: $(du -sh "${GC_LOG}" | cut -f1)"
log "분석 시각: $(date)"
log "============================================================"

# ── 로그 형식 감지 ────────────────────────────────────────────────────────────
detect_format() {
  if grep -q "GCH:" "${GC_LOG}" 2>/dev/null; then
    echo "legacy"    # Java 8 -XX:+PrintGCDetails
  elif grep -q "\[gc\]" "${GC_LOG}" 2>/dev/null; then
    echo "unified"   # Java 11+ -Xlog:gc*
  else
    echo "unknown"
  fi
}
GC_FORMAT=$(detect_format)
log "로그 형식: ${GC_FORMAT}"

# ── Young GC 분석 ────────────────────────────────────────────────────────────
log ""
log "[ 1. Young GC (Minor GC) ]"
log "────────────────────────────────────────────────────────────"

if [[ "${GC_FORMAT}" == "unified" ]]; then
  # 형식 예: [2024-01-15T10:30:01.123+0900][1.234s][gc] GC(42) Pause Young (Normal) (G1 Evacuation Pause) 512M->256M(1024M) 12.345ms
  awk '
    /Pause Young/ {
      # ms 값 추출
      match($0, /([0-9]+\.[0-9]+)ms$/, arr)
      if (arr[1] != "") {
        pause = arr[1] + 0
        total_pause += pause
        count++
        if (pause > max_pause) max_pause = pause
        if (count == 1 || pause < min_pause) min_pause = pause
        # 히스토그램: 버킷별 분류
        if (pause < 10)        bucket["<10ms"]++
        else if (pause < 50)   bucket["10-50ms"]++
        else if (pause < 100)  bucket["50-100ms"]++
        else if (pause < 500)  bucket["100-500ms"]++
        else                   bucket[">=500ms"]++
      }
    }
    END {
      if (count == 0) {
        print "  Young GC 없음"
        exit
      }
      printf "  발생 횟수: %d회\n", count
      printf "  평균 Pause: %.2fms\n", total_pause/count
      printf "  최소 Pause: %.2fms\n", min_pause
      printf "  최대 Pause: %.2fms\n", max_pause
      printf "  총 GC 시간: %.2fs\n",  total_pause/1000
      print  ""
      print  "  [ Pause 분포 ]"
      for (b in bucket) printf "    %-12s: %d회\n", b, bucket[b]
    }
  ' "${GC_LOG}" | tee -a "${REPORT}"
fi

# ── Full GC 분석 ─────────────────────────────────────────────────────────────
log ""
log "[ 2. Full GC ]"
log "────────────────────────────────────────────────────────────"

awk '
  /Pause Full/ {
    match($0, /([0-9]+\.[0-9]+)ms$/, arr)
    if (arr[1] != "") {
      pause = arr[1] + 0
      total += pause
      count++
      if (pause > max) max = pause

      # Full GC 발생 시각 추출 (첫 컬럼)
      match($0, /\[([^\]]+)\]/, ts)
      timestamps[count] = ts[1]

      # 원인 추출
      match($0, /Pause Full \(([^)]+)\)/, cause_arr)
      cause = cause_arr[1] != "" ? cause_arr[1] : "Unknown"
      causes[cause]++
    }
  }
  END {
    if (count == 0) {
      print "  Full GC 없음 ✓"
      exit
    }
    printf "  발생 횟수: %d회\n", count
    printf "  평균 Pause: %.0fms\n", total/count
    printf "  최대 Pause: %.0fms\n", max
    printf "  총 GC 시간: %.2fs\n",  total/1000
    print  ""
    print  "  [ Full GC 원인 ]"
    for (c in causes) printf "    %-30s: %d회\n", c, causes[c]
    print  ""
    print  "  [ Full GC 발생 시각 ]"
    for (i=1; i<=count; i++) printf "    %s\n", timestamps[i]
  }
' "${GC_LOG}" | tee -a "${REPORT}"

# ── GC Pause 분포 (전체) ─────────────────────────────────────────────────────
log ""
log "[ 3. 전체 GC Pause 백분위 ]"
log "────────────────────────────────────────────────────────────"

awk '
  /Pause (Young|Full|Old|Mixed)/ {
    match($0, /([0-9]+\.[0-9]+)ms$/, arr)
    if (arr[1] != "") {
      times[NR] = arr[1] + 0
      sum += arr[1] + 0
      count++
    }
  }
  END {
    if (count == 0) { print "  GC Pause 데이터 없음"; exit }
    n = asort(times)
    printf "  p50:  %.2fms\n", times[int(n*0.50)+1]
    printf "  p75:  %.2fms\n", times[int(n*0.75)+1]
    printf "  p90:  %.2fms\n", times[int(n*0.90)+1]
    printf "  p95:  %.2fms\n", times[int(n*0.95)+1]
    printf "  p99:  %.2fms\n", times[int(n*0.99)+1]
    printf "  최대: %.2fms\n", times[n]
    printf "  평균: %.2fms\n", sum/count
  }
' "${GC_LOG}" | tee -a "${REPORT}"

# ── Heap 사용량 추이 ─────────────────────────────────────────────────────────
log ""
log "[ 4. Heap 사용량 추이 (GC 전후) ]"
log "────────────────────────────────────────────────────────────"

awk '
  /Pause Young|Pause Full/ {
    # 패턴: 512M->256M(1024M)
    match($0, /([0-9]+)M->([0-9]+)M\(([0-9]+)M\)/, arr)
    if (arr[1] != "") {
      before = arr[1]+0
      after  = arr[2]+0
      total  = arr[3]+0
      reclaim = before - after
      sum_before += before
      sum_after  += after
      sum_total  += total
      if (before > max_before) max_before = before
      if (after  > max_after)  max_after  = after
      count++
    }
  }
  END {
    if (count == 0) { print "  Heap 데이터 없음"; exit }
    printf "  GC 전 평균 Heap:  %dMB  (최대: %dMB)\n", sum_before/count, max_before
    printf "  GC 후 평균 Heap:  %dMB  (최대: %dMB)\n", sum_after/count,  max_after
    printf "  평균 회수량:      %dMB\n", (sum_before-sum_after)/count
    printf "  평균 Heap 크기:   %dMB\n", sum_total/count
    pct = (sum_after/count) / (sum_total/count) * 100
    printf "  GC 후 Heap 점유율: %.1f%%\n", pct
    if (pct > 70) printf "  ⚠ GC 후 Heap 점유율 %.1f%% - Old Gen 누수 또는 Heap 부족\n", pct
  }
' "${GC_LOG}" | tee -a "${REPORT}"

# ── Safepoint 분석 ────────────────────────────────────────────────────────────
log ""
log "[ 5. Safepoint 분석 (safepoint 로그 필요) ]"
log "────────────────────────────────────────────────────────────"

local_safepoint="${GC_LOG/gc_/safepoint_}"
if [[ -f "${local_safepoint}" ]]; then
  awk '
    /Safepoint/ {
      match($0, /Total: ([0-9]+) ms/, arr)
      if (arr[1] != "") {
        total_ms = arr[1]+0
        sum += total_ms
        count++
        if (total_ms > 100) long_count++
      }
    }
    END {
      if (count == 0) { print "  Safepoint 데이터 없음"; exit }
      printf "  Safepoint 횟수: %d회\n", count
      printf "  평균 시간: %.2fms\n", sum/count
      printf "  100ms 초과: %d회\n", long_count+0
    }
  ' "${local_safepoint}" | tee -a "${REPORT}"
else
  log "  Safepoint 로그 없음 (safepoint 로깅 추가: -Xlog:safepoint)"
fi

# ── GC 오버헤드 계산 ─────────────────────────────────────────────────────────
log ""
log "[ 6. GC 오버헤드 (전체 시간 대비) ]"
log "────────────────────────────────────────────────────────────"

awk '
  /Pause (Young|Full|Old|Mixed)/ {
    match($0, /([0-9]+\.[0-9]+)ms$/, pause_arr)
    if (pause_arr[1] != "") gc_time += pause_arr[1]+0

    # 경과 시간 추출: [uptime] 형식
    match($0, /\[([0-9]+\.[0-9]+)s\]/, uptime_arr)
    if (uptime_arr[1]+0 > max_uptime) max_uptime = uptime_arr[1]+0
  }
  END {
    if (max_uptime == 0 || gc_time == 0) {
      print "  계산 불가 (uptime 정보 없음)"
      exit
    }
    overhead = (gc_time/1000) / max_uptime * 100
    printf "  총 GC 시간:   %.2fs\n", gc_time/1000
    printf "  총 실행 시간: %.2fs\n", max_uptime
    printf "  GC 오버헤드:  %.2f%%\n", overhead
    if (overhead > 5)  printf "  ⚠ GC 오버헤드 %.1f%% > 5%% - 튜닝 필요\n", overhead
    if (overhead > 20) printf "  ✗ GC 오버헤드 %.1f%% > 20%% - GC가 애플리케이션 성능에 심각한 영향\n", overhead
  }
' "${GC_LOG}" | tee -a "${REPORT}"

log ""
log "============================================================"
log "분석 완료: ${REPORT}"
log ""
log "추가 분석 도구 권장:"
log "  - GCViewer: https://github.com/chewiebug/GCViewer"
log "  - GCEasy:   https://gceasy.io (무료 온라인)"
log "  - JClarity Censum (상용)"
