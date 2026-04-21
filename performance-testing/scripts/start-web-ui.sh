#!/usr/bin/env bash
# ============================================================
# Web UI 모니터링 스택 시작/종료 스크립트
# 사용법:
#   ./start-web-ui.sh start    - 스택 시작
#   ./start-web-ui.sh stop     - 스택 종료
#   ./start-web-ui.sh status   - 상태 확인
#   ./start-web-ui.sh logs     - 로그 보기
#   ./start-web-ui.sh open     - 브라우저 주소 출력
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WEB_UI_DIR="${SCRIPT_DIR}/../web-ui"
ACTION=${1:-start}

SERVER_IP=$(hostname -I | awk '{print $1}' 2>/dev/null || echo "localhost")

log() { echo "[$(date '+%H:%M:%S')] $*"; }

check_docker() {
  if ! command -v docker &>/dev/null; then
    echo "ERROR: Docker가 설치되어 있지 않습니다."
    echo "  설치: curl -fsSL https://get.docker.com | sh"
    exit 1
  fi
  if ! docker compose version &>/dev/null 2>&1; then
    if ! docker-compose version &>/dev/null 2>&1; then
      echo "ERROR: docker compose 플러그인이 없습니다."
      echo "  설치: sudo apt install docker-compose-plugin"
      exit 1
    fi
    COMPOSE_CMD="docker-compose"
  else
    COMPOSE_CMD="docker compose"
  fi
}

print_urls() {
  echo ""
  echo "═══════════════════════════════════════════════════"
  echo "  Web UI 접속 주소"
  echo "═══════════════════════════════════════════════════"
  echo ""
  echo "  📊 Grafana 대시보드 (실시간 모니터링)"
  echo "     http://${SERVER_IP}:5000"
  echo "     ID: admin / PW: admin123"
  echo ""
  echo "  📋 테스트 결과 리포트 뷰어"
  echo "     http://${SERVER_IP}:8888/results/"
  echo ""
  echo "  🔍 Prometheus (메트릭 직접 조회)"
  echo "     http://${SERVER_IP}:9090"
  echo ""
  echo "  🗄  InfluxDB (Gatling 실시간 데이터)"
  echo "     http://${SERVER_IP}:8086"
  echo ""
  echo "═══════════════════════════════════════════════════"
  echo ""
}

case "${ACTION}" in
  start)
    check_docker
    log "Web UI 모니터링 스택 시작..."
    cd "${WEB_UI_DIR}"
    ${COMPOSE_CMD} up -d
    log "시작 완료. 컨테이너 상태:"
    ${COMPOSE_CMD} ps
    print_urls
    log "Grafana가 완전히 준비되는데 약 10~20초 소요됩니다."
    ;;

  stop)
    check_docker
    log "Web UI 모니터링 스택 종료..."
    cd "${WEB_UI_DIR}"
    ${COMPOSE_CMD} down
    log "종료 완료"
    ;;

  restart)
    check_docker
    cd "${WEB_UI_DIR}"
    ${COMPOSE_CMD} restart
    log "재시작 완료"
    print_urls
    ;;

  status)
    check_docker
    cd "${WEB_UI_DIR}"
    ${COMPOSE_CMD} ps
    echo ""
    log "포트 사용 현황:"
    ss -tlnp 2>/dev/null | grep -E "3000|9090|8086|8888|9100|9404" || \
      netstat -tlnp 2>/dev/null | grep -E "3000|9090|8086|8888|9100|9404" || true
    ;;

  logs)
    check_docker
    cd "${WEB_UI_DIR}"
    SERVICE=${2:-""}
    ${COMPOSE_CMD} logs -f --tail=100 ${SERVICE}
    ;;

  open)
    print_urls
    ;;

  *)
    echo "사용법: $0 [start|stop|restart|status|logs|open]"
    exit 1
    ;;
esac
