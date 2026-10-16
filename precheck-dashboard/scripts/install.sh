#!/usr/bin/env bash
# =====================================================================
#  install.sh - Apache 사전점검 에이전트 설치/삭제
#
#  설치:  sudo bash install.sh <대시보드주소> <에이전트이름> [--ca-cert CA파일]
#         예) sudo bash install.sh https://dashboard.example.com/precheck web01
#         → 토큰은 실행 중에 물어봅니다(화면에 표시되지 않음).
#           자동화할 때는 환경변수 PRECHECK_AGENT_TOKEN 으로 넘길 수 있습니다.
#  삭제:  sudo bash install.sh --uninstall
#
#  하는 일
#   1) /opt/precheck-agent 에 precheck-agent.sh, apache_precheck.sh 설치
#      (install.sh 와 같은 폴더에 두 파일이 있으면 그것을, 없으면 대시보드에서 받음)
#   2) /etc/precheck-agent.conf 생성 (권한 600, 토큰 저장)
#   3) 대시보드 연결 확인
#   4) 1분마다 실행되도록 등록 (systemd 타이머, 없으면 /etc/cron.d)
# =====================================================================
set -u

DEST=/opt/precheck-agent
CONF=/etc/precheck-agent.conf
UNIT_DIR=/etc/systemd/system
CRON_FILE=/etc/cron.d/precheck-agent

say() { printf '[설치] %s\n' "$*"; }
die() { printf '[설치 실패] %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "root 로 실행하세요:  sudo bash $0 ..."

has_systemd() { command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; }

if [ "${1:-}" = "--uninstall" ]; then
  if has_systemd; then
    systemctl disable --now precheck-agent.timer >/dev/null 2>&1
    rm -f "$UNIT_DIR/precheck-agent.timer" "$UNIT_DIR/precheck-agent.service"
    systemctl daemon-reload
  fi
  rm -f "$CRON_FILE"
  rm -rf "$DEST" "$CONF"
  say "삭제했습니다. (대시보드의 에이전트 목록에서도 삭제하세요)"
  exit 0
fi

URL="${1:-}"; NAME="${2:-}"; shift 2 2>/dev/null
CA_CERT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --ca-cert) CA_CERT="${2:-}"; shift 2 ;;
    *) die "알 수 없는 옵션: $1" ;;
  esac
done
[ -n "$URL" ] && [ -n "$NAME" ] || die "사용법: sudo bash $0 <대시보드주소> <에이전트이름> [--ca-cert CA파일]"
URL="${URL%/}"
[[ "$URL" =~ ^https?:// ]] || die "대시보드 주소는 http:// 또는 https:// 로 시작해야 합니다."
[[ "$NAME" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{1,39}$ ]] || die "에이전트 이름이 올바르지 않습니다: $NAME"
[ -z "$CA_CERT" ] || [ -r "$CA_CERT" ] || die "CA 파일을 읽을 수 없습니다: $CA_CERT"
command -v curl >/dev/null 2>&1 || die "curl 이 필요합니다. (yum install curl / apt install curl)"
command -v flock >/dev/null 2>&1 || die "flock 이 필요합니다. (util-linux 패키지)"
[[ "$URL" == http://* ]] && say "주의: http 로 연결합니다. 토큰과 점검 결과가 암호화되지 않으므로 https 사용을 권장합니다."

TOKEN="${PRECHECK_AGENT_TOKEN:-}"
if [ -z "$TOKEN" ]; then
  printf '대시보드에서 받은 에이전트 토큰을 붙여 넣고 Enter: '
  read -rs TOKEN; echo
fi
[ -n "$TOKEN" ] || die "토큰이 비어 있습니다."

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
HERE="$(cd "$(dirname "$0")" && pwd)"
for f in precheck-agent.sh apache_precheck.sh; do
  if [ -f "$HERE/$f" ]; then
    cp "$HERE/$f" "$TMP/$f"
    say "$f : 같은 폴더의 파일 사용"
  else
    curl -fsS --connect-timeout 10 ${CA_CERT:+--cacert "$CA_CERT"} -o "$TMP/$f" "$URL/agent-api/files/$f" \
      || die "$f 를 대시보드에서 받지 못했습니다: $URL/agent-api/files/$f"
    say "$f : 대시보드에서 받음"
  fi
  head -c 2 "$TMP/$f" | grep -q '#!' || die "$f 가 스크립트 파일이 아닙니다. 대시보드 주소를 확인하세요."
  bash -n "$TMP/$f" || die "$f 문법 오류"
done

mkdir -p "$DEST"
chmod 700 "$DEST"
install -m 700 "$TMP/precheck-agent.sh" "$DEST/precheck-agent.sh"
install -m 700 "$TMP/apache_precheck.sh" "$DEST/apache_precheck.sh"

# 기존 설정의 선택 항목은 유지
OLD_RECENT=""; OLD_LOGS=""; OLD_TIMEOUT=""
if [ -r "$CONF" ]; then
  OLD_RECENT="$(sed -n 's/^RECENT_DAYS=//p' "$CONF" | tail -n1)"
  OLD_LOGS="$(sed -n 's/^LOG_PATHS=//p' "$CONF" | tail -n1)"
  OLD_TIMEOUT="$(sed -n 's/^RUN_TIMEOUT=//p' "$CONF" | tail -n1)"
  cp -p "$CONF" "$CONF.bak"
fi
q() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }
umask 077
cat > "$CONF" <<EOF
# precheck-agent 설정 (install.sh 가 생성, 권한 600)
DASHBOARD_URL=$(q "$URL")
AGENT_NAME=$(q "$NAME")
AGENT_TOKEN=$(q "$TOKEN")
CA_CERT=$(q "$CA_CERT")
# 점검 최대 실행 시간(초)
RUN_TIMEOUT=${OLD_TIMEOUT:-3600}
# apache_precheck.sh -d (최근 변경 파일 점검 기간, 일)
RECENT_DAYS=${OLD_RECENT:-30}
# apache_precheck.sh -l (접근 로그 경로를 직접 지정할 때만. 예: '/logs/apache/access_log*')
LOG_PATHS=${OLD_LOGS:-}
EOF
chmod 600 "$CONF"
say "설정 파일 작성: $CONF"

say "대시보드 연결 확인 중..."
"$DEST/precheck-agent.sh" test || die "대시보드에 연결하지 못했습니다. 주소·이름·토큰과 방화벽(웹서버 → 대시보드)을 확인하세요. 다시 설치하면 됩니다."

if has_systemd; then
  cat > "$UNIT_DIR/precheck-agent.service" <<EOF
[Unit]
Description=Apache precheck agent (poll dashboard, run apache_precheck.sh when requested)
After=network-online.target

[Service]
Type=oneshot
ExecStart=$DEST/precheck-agent.sh poll
# 점검 스크립트가 실제 /tmp, /proc, 웹 로그를 봐야 하므로 PrivateTmp 등 격리 옵션을 쓰지 않음
Nice=10
IOSchedulingClass=idle
EOF
  cat > "$UNIT_DIR/precheck-agent.timer" <<EOF
[Unit]
Description=Run precheck agent every minute

[Timer]
OnBootSec=2min
OnUnitActiveSec=60s
AccuracySec=10s

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now precheck-agent.timer >/dev/null 2>&1 || die "systemd 타이머 등록 실패"
  rm -f "$CRON_FILE"
  say "systemd 타이머 등록 완료 (상태 확인: systemctl status precheck-agent.timer / 로그: journalctl -u precheck-agent)"
else
  printf '# Apache 사전점검 에이전트: 1분마다 대시보드 확인\n* * * * * root %s/precheck-agent.sh poll >>/var/log/precheck-agent.log 2>&1\n' "$DEST" > "$CRON_FILE"
  chmod 644 "$CRON_FILE"
  say "cron 등록 완료: $CRON_FILE (로그: /var/log/precheck-agent.log)"
fi

say "설치 완료. 1~2분 안에 대시보드 에이전트 목록에 '온라인'으로 표시됩니다."
say "바로 점검하려면: 대시보드에서 [지금 점검]  또는  sudo $DEST/precheck-agent.sh run"
