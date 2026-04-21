#!/usr/bin/env bash
# ============================================================
# Linux OS 커널 파라미터 튜닝 스크립트 (WildFly 성능 최적화)
# 실행: sudo ./os-kernel-tuning.sh [apply|check|revert]
#
# 주의: 운영 적용 전 스테이징에서 충분히 검증 필요
#       apply 전에 기존 설정을 자동으로 백업
# ============================================================

set -euo pipefail

ACTION=${1:-check}
BACKUP_FILE="/etc/sysctl.d/wildfly-perf-backup-$(date +%Y%m%d%H%M%S).conf"

log()  { echo "[$(date '+%H:%M:%S')] $*"; }
warn() { echo "[$(date '+%H:%M:%S')] ⚠️  $*"; }

check_root() {
  [[ $EUID -eq 0 ]] || { echo "ERROR: root 권한 필요 (sudo 사용)"; exit 1; }
}

# ── 현재 설정 확인 ──────────────────────────────────────────────────────────
check_current() {
  log "====== 현재 커널 파라미터 상태 ======"
  echo ""
  echo "[ File Descriptor 한도 ]"
  echo "  시스템 최대: $(cat /proc/sys/fs/file-max)"
  echo "  현재 프로세스: $(ulimit -n)"
  echo "  WildFly 프로세스:"
  if pgrep -f "jboss-modules" > /dev/null 2>&1; then
    local wf_pid
    wf_pid=$(pgrep -f "jboss-modules" | head -1)
    echo "    soft: $(cat /proc/${wf_pid}/limits | awk '/open files/{print $4}')"
    echo "    hard: $(cat /proc/${wf_pid}/limits | awk '/open files/{print $5}')"
  fi

  echo ""
  echo "[ TCP 소켓 설정 ]"
  sysctl -a 2>/dev/null | grep -E "tcp_fin_timeout|tcp_tw_reuse|tcp_keepalive|somaxconn|tcp_max_syn|rmem|wmem" | \
    grep -v "#" | sort

  echo ""
  echo "[ 메모리 설정 ]"
  sysctl vm.swappiness vm.overcommit_memory vm.dirty_ratio vm.dirty_background_ratio 2>/dev/null || true

  echo ""
  echo "[ 현재 TIME_WAIT 소켓 수 ]"
  ss -tan 2>/dev/null | grep TIME-WAIT | wc -l || echo "N/A"

  echo ""
  echo "[ 현재 ESTABLISHED 소켓 수 ]"
  ss -tan 2>/dev/null | grep ESTAB | wc -l || echo "N/A"
}

# ── 튜닝 파라미터 적용 ──────────────────────────────────────────────────────
apply_tuning() {
  check_root

  # 기존 설정 백업
  sysctl -a 2>/dev/null | grep -E "^net\.|^vm\.|^fs\." > "${BACKUP_FILE}" || true
  log "기존 설정 백업: ${BACKUP_FILE}"

  log "커널 파라미터 튜닝 적용 시작..."

  # ── File Descriptor 설정 ─────────────────────────────────────────────────
  # WildFly가 열 수 있는 파일 수 (소켓 + 파일 포함)
  cat > /etc/security/limits.d/wildfly.conf << 'EOF'
wildfly soft nofile 65535
wildfly hard nofile 65535
* soft nofile 65535
* hard nofile 65535
EOF

  sysctl -w fs.file-max=2097152

  # ── TCP 소켓 최적화 ──────────────────────────────────────────────────────
  # 동시 연결 대기열 크기 (SYN 큐 + Accept 큐)
  sysctl -w net.core.somaxconn=65535
  sysctl -w net.ipv4.tcp_max_syn_backlog=65535

  # TIME_WAIT 소켓 재사용 (같은 IP:포트로 빠른 재연결)
  sysctl -w net.ipv4.tcp_tw_reuse=1

  # TIME_WAIT 상태 유지 시간 단축 (기본 60초 → 30초)
  sysctl -w net.ipv4.tcp_fin_timeout=30

  # TCP Keepalive: 좀비 연결 조기 정리
  sysctl -w net.ipv4.tcp_keepalive_time=300    # 마지막 데이터 후 300초
  sysctl -w net.ipv4.tcp_keepalive_intvl=30    # probe 재전송 간격
  sysctl -w net.ipv4.tcp_keepalive_probes=5    # 실패 허용 횟수

  # 소켓 버퍼 크기 (처리량 향상)
  sysctl -w net.core.rmem_max=16777216         # 수신 버퍼 최대 16MB
  sysctl -w net.core.wmem_max=16777216         # 송신 버퍼 최대 16MB
  sysctl -w net.ipv4.tcp_rmem="4096 87380 16777216"
  sysctl -w net.ipv4.tcp_wmem="4096 65536 16777216"

  # 네트워크 패킷 큐 크기
  sysctl -w net.core.netdev_max_backlog=65535

  # Ephemeral 포트 범위 확장 (부하 발생기 → WAS 직접 연결 시)
  sysctl -w net.ipv4.ip_local_port_range="10240 65535"

  # ── 메모리 최적화 ─────────────────────────────────────────────────────────
  # swap 최소화 (JVM은 swap이 발생하면 GC pause 급증)
  sysctl -w vm.swappiness=1

  # 메모리 overcommit: JVM 큰 Heap 할당 허용
  sysctl -w vm.overcommit_memory=1

  # Dirty Page 비율 (디스크 flush 빈도 조정)
  sysctl -w vm.dirty_ratio=60
  sysctl -w vm.dirty_background_ratio=5

  # Transparent Huge Pages 비활성화 (GC pause 증가 원인)
  if [[ -f /sys/kernel/mm/transparent_hugepage/enabled ]]; then
    echo never > /sys/kernel/mm/transparent_hugepage/enabled
    echo never > /sys/kernel/mm/transparent_hugepage/defrag
    log "Transparent Huge Pages 비활성화 완료"
  fi

  # ── /etc/sysctl.d/ 영구 설정 파일 생성 ──────────────────────────────────
  cat > /etc/sysctl.d/99-wildfly-perf.conf << 'SYSCTL'
# WildFly 26 성능 튜닝 설정
fs.file-max = 2097152

net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 65535
net.ipv4.ip_local_port_range = 10240 65535

vm.swappiness = 1
vm.overcommit_memory = 1
vm.dirty_ratio = 60
vm.dirty_background_ratio = 5
SYSCTL

  sysctl -p /etc/sysctl.d/99-wildfly-perf.conf

  log "튜닝 적용 완료"
  log "재부팅 후 영구 적용 여부 확인: sysctl vm.swappiness"
}

# ── 롤백 ─────────────────────────────────────────────────────────────────────
revert_tuning() {
  check_root
  local latest_backup
  latest_backup=$(ls -t /etc/sysctl.d/wildfly-perf-backup-*.conf 2>/dev/null | head -1 || echo "")

  if [[ -z "${latest_backup}" ]]; then
    warn "백업 파일을 찾을 수 없습니다."
    exit 1
  fi

  log "롤백 적용: ${latest_backup}"
  while IFS='=' read -r key value; do
    [[ "${key}" =~ ^# ]] && continue
    [[ -z "${key}" ]] && continue
    sysctl -w "${key}=${value}" 2>/dev/null || true
  done < "${latest_backup}"

  rm -f /etc/sysctl.d/99-wildfly-perf.conf
  log "롤백 완료"
}

case "${ACTION}" in
  apply)   apply_tuning   ;;
  check)   check_current  ;;
  revert)  revert_tuning  ;;
  *)
    echo "사용법: $0 [apply|check|revert]"
    echo "  apply  - 튜닝 파라미터 적용"
    echo "  check  - 현재 설정 확인"
    echo "  revert - 이전 설정으로 롤백"
    exit 1
    ;;
esac
