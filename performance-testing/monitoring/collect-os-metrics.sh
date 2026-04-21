#!/usr/bin/env bash
# ============================================================
# OS 레벨 메트릭 수집 스크립트
# - CPU / Memory / Disk I/O / Network / TCP 상태 수집
# - 사용법: ./collect-os-metrics.sh [간격(초)] [출력경로]
# ============================================================

set -euo pipefail

INTERVAL=${1:-5}
OUTPUT_DIR=${2:-"$(dirname "$0")/../results"}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "${OUTPUT_DIR}"

CPU_FILE="${OUTPUT_DIR}/os_cpu_${TIMESTAMP}.csv"
MEM_FILE="${OUTPUT_DIR}/os_mem_${TIMESTAMP}.csv"
DISK_FILE="${OUTPUT_DIR}/os_disk_${TIMESTAMP}.csv"
NET_FILE="${OUTPUT_DIR}/os_net_${TIMESTAMP}.csv"
TCP_FILE="${OUTPUT_DIR}/os_tcp_${TIMESTAMP}.csv"

# 모니터링 대상 네트워크 인터페이스 (환경에 맞게 변경)
NET_IFACE=${NET_IFACE:-eth0}
# 모니터링 대상 디스크 (환경에 맞게 변경)
DISK_DEV=${DISK_DEV:-sda}

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# ── CSV 헤더 ─────────────────────────────────────────────────────────────────
echo "timestamp,cpu_user,cpu_system,cpu_iowait,cpu_idle,cpu_steal,load1,load5,load15" > "${CPU_FILE}"
echo "timestamp,mem_total_mb,mem_used_mb,mem_free_mb,mem_buffers_mb,mem_cached_mb,mem_avail_mb,swap_used_mb,swap_total_mb" > "${MEM_FILE}"
echo "timestamp,disk_device,reads_completed,writes_completed,read_kb,write_kb,io_await_ms,util_pct" > "${DISK_FILE}"
echo "timestamp,iface,rx_bytes,tx_bytes,rx_packets,tx_packets,rx_errors,tx_errors,rx_dropped,tx_dropped" > "${NET_FILE}"
echo "timestamp,tcp_established,tcp_syn_sent,tcp_syn_recv,tcp_fin_wait1,tcp_fin_wait2,tcp_time_wait,tcp_close_wait,tcp_last_ack,tcp_listen" > "${TCP_FILE}"

collect_cpu() {
  local user sys idle iowait steal load
  read -r _ user nice sys idle iowait irq softirq steal < /proc/stat

  # 누적값 → 델타 계산
  local total=$((user + nice + sys + idle + iowait + irq + softirq + steal))
  local delta_total=$(( total - PREV_CPU_TOTAL ))
  local delta_idle=$(( idle - PREV_CPU_IDLE ))

  local cpu_user=0 cpu_sys=0 cpu_idle=0 cpu_iowait=0 cpu_steal=0
  if (( delta_total > 0 )); then
    cpu_user=$(echo   "${user}   ${PREV_CPU_USER}   ${delta_total}" | awk '{printf "%.1f", ($1-$2)/$3*100}')
    cpu_sys=$(echo    "${sys}    ${PREV_CPU_SYS}    ${delta_total}" | awk '{printf "%.1f", ($1-$2)/$3*100}')
    cpu_idle=$(echo   "${idle}   ${PREV_CPU_IDLE}   ${delta_total}" | awk '{printf "%.1f", ($1-$2)/$3*100}')
    cpu_iowait=$(echo "${iowait} ${PREV_CPU_IOWAIT} ${delta_total}" | awk '{printf "%.1f", ($1-$2)/$3*100}')
    cpu_steal=$(echo  "${steal}  ${PREV_CPU_STEAL}  ${delta_total}" | awk '{printf "%.1f", ($1-$2)/$3*100}')
  fi

  load=$(awk '{print $1","$2","$3}' /proc/loadavg)

  echo "$(date '+%Y-%m-%d %H:%M:%S'),${cpu_user},${cpu_sys},${cpu_iowait},${cpu_idle},${cpu_steal},${load}" >> "${CPU_FILE}"

  # CPU IOWait 과다 경고 (10% 이상)
  if (( $(echo "${cpu_iowait} > 10" | bc -l) )); then
    log "⚠️  IOWait ${cpu_iowait}% - 디스크/네트워크 병목 의심"
  fi

  PREV_CPU_TOTAL=${total}
  PREV_CPU_IDLE=${idle}
  PREV_CPU_USER=${user}
  PREV_CPU_SYS=${sys}
  PREV_CPU_IOWAIT=${iowait}
  PREV_CPU_STEAL=${steal}
}

collect_memory() {
  local total free buffers cached avail swap_total swap_free
  total=$(     awk '/^MemTotal:/     {print int($2/1024)}' /proc/meminfo)
  free=$(      awk '/^MemFree:/      {print int($2/1024)}' /proc/meminfo)
  buffers=$(   awk '/^Buffers:/      {print int($2/1024)}' /proc/meminfo)
  cached=$(    awk '/^Cached:/       {print int($2/1024)}' /proc/meminfo)
  avail=$(     awk '/^MemAvailable:/ {print int($2/1024)}' /proc/meminfo)
  swap_total=$(awk '/^SwapTotal:/    {print int($2/1024)}' /proc/meminfo)
  swap_free=$( awk '/^SwapFree:/     {print int($2/1024)}' /proc/meminfo)

  local used=$(( total - free - buffers - cached ))
  local swap_used=$(( swap_total - swap_free ))

  echo "$(date '+%Y-%m-%d %H:%M:%S'),${total},${used},${free},${buffers},${cached},${avail},${swap_used},${swap_total}" >> "${MEM_FILE}"

  # Swap 사용 경고
  if (( swap_used > 100 )); then
    log "⚠️  Swap 사용 ${swap_used}MB - 메모리 부족 의심"
  fi
}

collect_disk() {
  local line reads writes read_kb write_kb await util
  line=$(awk -v dev="${DISK_DEV}" '$3==dev {print}' /proc/diskstats 2>/dev/null || echo "")
  [[ -z "${line}" ]] && return

  read -r _ _ _ reads read_merges read_sectors read_ms \
              writes write_merges write_sectors write_ms \
              io_in_progress io_ms weighted_io_ms <<< "${line}"

  read_kb=$(( read_sectors / 2 ))
  write_kb=$(( write_sectors / 2 ))

  # io_ms / INTERVAL * 100 = util%
  local delta_io=$(( io_ms - PREV_IO_MS ))
  util=$(echo "${delta_io} ${INTERVAL}" | awk '{pct=$1/($2*10); printf "%.1f", pct>100?100:pct}')

  echo "$(date '+%Y-%m-%d %H:%M:%S'),${DISK_DEV},${reads},${writes},${read_kb},${write_kb},0,${util}" >> "${DISK_FILE}"

  PREV_IO_MS=${io_ms}
}

collect_network() {
  local rx_bytes tx_bytes rx_pkts tx_pkts rx_err tx_err rx_drop tx_drop
  local line
  line=$(awk -v iface="${NET_IFACE}:" '$1==iface {print}' /proc/net/dev 2>/dev/null || echo "")
  [[ -z "${line}" ]] && return

  read -r _ rx_bytes rx_pkts rx_err rx_drop _ _ _ _ \
              tx_bytes tx_pkts tx_err tx_drop _ _ _ _ <<< "${line}"

  local delta_rx=$(( rx_bytes - PREV_RX_BYTES ))
  local delta_tx=$(( tx_bytes - PREV_TX_BYTES ))

  echo "$(date '+%Y-%m-%d %H:%M:%S'),${NET_IFACE},${delta_rx},${delta_tx},${rx_pkts},${tx_pkts},${rx_err},${tx_err},${rx_drop},${tx_drop}" >> "${NET_FILE}"

  PREV_RX_BYTES=${rx_bytes}
  PREV_TX_BYTES=${tx_bytes}
}

collect_tcp() {
  # /proc/net/sockstat에서 TCP 상태별 카운트
  # 또는 ss 명령 사용
  local established syn_sent syn_recv fin_wait1 fin_wait2 \
        time_wait close_wait last_ack listen

  if command -v ss &>/dev/null; then
    local ss_out
    ss_out=$(ss -tan 2>/dev/null || echo "")
    established=$(echo "${ss_out}" | grep -c "^ESTAB"      || echo 0)
    syn_sent=$(echo    "${ss_out}" | grep -c "SYN-SENT"    || echo 0)
    syn_recv=$(echo    "${ss_out}" | grep -c "SYN-RECV"    || echo 0)
    fin_wait1=$(echo   "${ss_out}" | grep -c "FIN-WAIT-1"  || echo 0)
    fin_wait2=$(echo   "${ss_out}" | grep -c "FIN-WAIT-2"  || echo 0)
    time_wait=$(echo   "${ss_out}" | grep -c "TIME-WAIT"   || echo 0)
    close_wait=$(echo  "${ss_out}" | grep -c "CLOSE-WAIT"  || echo 0)
    last_ack=$(echo    "${ss_out}" | grep -c "LAST-ACK"    || echo 0)
    listen=$(echo      "${ss_out}" | grep -c "^LISTEN"     || echo 0)
  else
    established=0; syn_sent=0; syn_recv=0; fin_wait1=0; fin_wait2=0
    time_wait=0; close_wait=0; last_ack=0; listen=0
  fi

  echo "$(date '+%Y-%m-%d %H:%M:%S'),${established},${syn_sent},${syn_recv},${fin_wait1},${fin_wait2},${time_wait},${close_wait},${last_ack},${listen}" >> "${TCP_FILE}"

  # TIME_WAIT 과다 경고 (1000 이상)
  if (( time_wait > 1000 )); then
    log "⚠️  TIME_WAIT ${time_wait}개 - tcp_tw_reuse/recycle 설정 확인"
  fi
}

# ── 초기값 설정 ──────────────────────────────────────────────────────────────
read -r _ PREV_CPU_USER _ PREV_CPU_SYS PREV_CPU_IDLE PREV_CPU_IOWAIT _ _ PREV_CPU_STEAL < /proc/stat
PREV_CPU_TOTAL=$(( PREV_CPU_USER + PREV_CPU_SYS + PREV_CPU_IDLE + PREV_CPU_IOWAIT + PREV_CPU_STEAL ))
PREV_IO_MS=0
PREV_RX_BYTES=0
PREV_TX_BYTES=0

log "OS 메트릭 수집 시작 (간격: ${INTERVAL}s)"
log "CPU    → ${CPU_FILE}"
log "Memory → ${MEM_FILE}"
log "Disk   → ${DISK_FILE}"
log "Net    → ${NET_FILE}"
log "TCP    → ${TCP_FILE}"
log "Ctrl+C로 종료"

trap 'log "수집 종료"; exit 0' INT TERM

while true; do
  collect_cpu
  collect_memory
  collect_disk
  collect_network
  collect_tcp
  sleep "${INTERVAL}"
done
