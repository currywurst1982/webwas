#!/usr/bin/env bash
#
# WildFly Dashboard 업데이트 스크립트
#
#   sudo ./update.sh              최신 코드로 업데이트 + 재시작 + 새 빌드 응답 확인
#   sudo ./update.sh --rollback   직전 백업으로 되돌리고 재시작
#   sudo ./update.sh --help
#
# 설정 (환경 변수로 바꿀 수 있음)
#   INSTALL_DIR  대시보드 설치 폴더            (기본: /opt/wildfly-dashboard)
#   RUN_USER     대시보드 실행 계정            (기본: 설치 폴더 소유자, 예: was)
#   BRANCH       받을 GitHub 브랜치             (기본: claude/vigilant-heisenberg-87v3t1)
#   REPO         GitHub 저장소                 (기본: currywurst1982/webwas)
#   KEEP_BACKUPS 보관할 백업 개수              (기본: 5)
#   SOURCE_ZIP   인터넷이 안 되는 서버: PC 에서 받아 올린 ZIP 파일 경로 (지정하면 다운로드하지 않음)
#
# config/config.json 과 data/ (사용자 계정, 힙 덤프) 는 절대 건드리지 않습니다.

set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/wildfly-dashboard}"
BRANCH="${BRANCH:-claude/vigilant-heisenberg-87v3t1}"
REPO="${REPO:-currywurst1982/webwas}"
KEEP_BACKUPS="${KEEP_BACKUPS:-5}"
SERVICE="wildfly-dashboard"
BACKUP_ROOT="$INSTALL_DIR/backup"
# files and folders owned by the release; everything else in INSTALL_DIR is left alone
RELEASE_ITEMS=(public src scripts server.js package.json package-lock.json)

c_ok=$'\e[32m'; c_err=$'\e[31m'; c_warn=$'\e[33m'; c_off=$'\e[0m'
[ -t 1 ] || { c_ok=; c_err=; c_warn=; c_off=; }
step() { echo; echo "== $*"; }
ok()   { echo "${c_ok}✔ $*${c_off}"; }
warn() { echo "${c_warn}▲ $*${c_off}"; }
die()  { echo "${c_err}✘ $*${c_off}" >&2; exit 1; }

usage() { sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

# ------------------------------------------------------------------ checks
[ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ] && usage
[ "$(id -u)" -eq 0 ] || die "root 로 실행하세요: sudo $0 $*"
[ -f "$INSTALL_DIR/server.js" ] || die "$INSTALL_DIR 에 대시보드가 없습니다 (INSTALL_DIR 를 확인하세요)"
command -v node >/dev/null || die "node 를 찾을 수 없습니다"
NODE_BIN="$(command -v node)"
RUN_USER="${RUN_USER:-$(stat -c %U "$INSTALL_DIR")}"
id "$RUN_USER" >/dev/null 2>&1 || die "실행 계정 $RUN_USER 이(가) 없습니다"

# Command prefix that runs as RUN_USER (sudo may be missing on minimal hosts; runuser is part of util-linux).
as_user_prefix() {
  if [ "$RUN_USER" = "$(id -un)" ]; then AS_USER=()
  elif command -v runuser >/dev/null; then AS_USER=(runuser -u "$RUN_USER" --)
  elif command -v sudo >/dev/null; then AS_USER=(sudo -u "$RUN_USER")
  else AS_USER=(su -s /bin/sh "$RUN_USER" -c 'exec "$0" "$@"'); fi
}

port() {
  (cd "$INSTALL_DIR" && "$NODE_BIN" -e "
    let p = process.env.DASHBOARD_PORT;
    try { p = p || JSON.parse(require('fs').readFileSync('config/config.json', 'utf8')).port; } catch (_) {}
    console.log(p || 9080);") 2>/dev/null || echo 9080
}

build_of() { grep -o "BUILD: '[^']*'" "$1/src/build.js" 2>/dev/null | cut -d"'" -f2 || true; }

uses_systemd() { command -v systemctl >/dev/null && systemctl cat "$SERVICE" >/dev/null 2>&1; }

# PIDs of dashboard processes started from INSTALL_DIR (other node programs are left alone)
dashboard_pids() {
  local p
  for p in $(pgrep -f 'node .*server\.js' || true); do
    if [ "$(readlink "/proc/$p/cwd" 2>/dev/null)" = "$INSTALL_DIR" ]; then echo "$p"; fi
  done
  return 0
}

stop_dashboard() {
  if uses_systemd; then systemctl stop "$SERVICE" || true; fi
  local pids
  pids="$(dashboard_pids)"
  if [ -n "$pids" ]; then
    kill $pids 2>/dev/null || true
    for _ in $(seq 1 20); do [ -z "$(dashboard_pids)" ] && break; sleep 0.5; done
    pids="$(dashboard_pids)"
    if [ -n "$pids" ]; then warn "종료되지 않아 강제 종료합니다: $pids"; kill -9 $pids 2>/dev/null || true; fi
  fi
}

# Is the dashboard port already taken? Tested by binding it with node, so ss/netstat are not needed.
port_in_use() {
  "$NODE_BIN" -e "
    const s = require('net').createServer();
    s.once('error', (e) => process.exit(e.code === 'EADDRINUSE' ? 0 : 2));
    s.listen(+process.argv[1], '0.0.0.0', () => s.close(() => process.exit(1)));" "$(port)"
}

# Refuses to go on (before anything is stopped) when the port is taken while no dashboard from
# INSTALL_DIR is running, i.e. something else owns it and the new dashboard could not start.
check_port_free_for_us() {
  if [ -z "$(dashboard_pids)" ] && port_in_use; then
    local who
    who="$( (ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null) | grep -E "[:.]$(port)[[:space:]]" || true)"
    die "포트 $(port) 를 대시보드가 아닌 프로세스가 사용 중입니다. 아무것도 바꾸지 않았습니다. ${who:-(ss/netstat 로 확인하세요)}"
  fi
}

start_dashboard() {
  if uses_systemd; then
    systemctl start "$SERVICE"
    echo "systemd 서비스 $SERVICE 시작"
  else
    as_user_prefix
    # exec + setsid: nothing of this script (not even a copy of its stdout) stays attached to the
    # dashboard, so `update.sh | tee ...` or an SSH session returns as soon as the script ends.
    (cd "$INSTALL_DIR" && exec setsid nohup "${AS_USER[@]}" "$NODE_BIN" server.js \
      >> "$INSTALL_DIR/dashboard.log" 2>&1 < /dev/null) &
    echo "nohup 으로 시작 (로그: $INSTALL_DIR/dashboard.log, 계정: $RUN_USER)"
  fi
}

# Waits until /healthz answers with the expected build (or any answer when none is expected).
verify() {
  local want="$1" p got=""
  p="$(port)"
  for _ in $(seq 1 30); do
    got="$(curl -fsS "http://127.0.0.1:$p/healthz" 2>/dev/null | grep -o '"build":"[^"]*"' | cut -d'"' -f4 || true)"
    [ -n "$got" ] && { [ -z "$want" ] || [ "$got" = "$want" ]; } && break
    sleep 1
  done
  if [ -n "$got" ] && { [ -z "$want" ] || [ "$got" = "$want" ]; }; then
    ok "대시보드 응답 확인: http://127.0.0.1:$p (build $got)"
    return 0
  fi
  # builds before /healthz existed (e.g. after a rollback) can only be checked through the login page
  if [ -z "$got" ] && [ "${2:-}" = "allow-old" ] && [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/login")" = "200" ]; then
    ok "대시보드 응답 확인: http://127.0.0.1:$p (이전 빌드라 build 번호는 확인할 수 없음)"
    return 0
  fi
  echo "${c_err}✘ 새 빌드 응답을 확인하지 못했습니다 (기대: ${want:-아무 응답}, 응답: ${got:-없음})${c_off}"
  if uses_systemd; then journalctl -u "$SERVICE" -n 20 --no-pager || true
  else tail -20 "$INSTALL_DIR/dashboard.log" 2>/dev/null || true; fi
  return 1
}

# ------------------------------------------------------------------ rollback
if [ "${1:-}" = "--rollback" ]; then
  last="$(ls -1d "$BACKUP_ROOT"/*/ 2>/dev/null | sort | tail -1 || true)"
  [ -n "$last" ] || die "백업이 없습니다 ($BACKUP_ROOT)"
  step "백업으로 되돌리기: $last"
  check_port_free_for_us
  stop_dashboard
  for item in "${RELEASE_ITEMS[@]}"; do
    [ -e "$last/$item" ] || continue
    [ "$item" = "scripts" ] && continue      # keep this (newer) update.sh so it stays usable
    rm -rf "${INSTALL_DIR:?}/$item"
    command cp -a "$last/$item" "$INSTALL_DIR/$item"
  done
  chown -R "$RUN_USER:" "$INSTALL_DIR"
  start_dashboard
  verify "$(build_of "$INSTALL_DIR")" allow-old && ok "되돌리기 완료 (build $(build_of "$INSTALL_DIR"))"
  exit 0
fi

# ------------------------------------------------------------------ update
current="$(build_of "$INSTALL_DIR")"
echo "설치 폴더 : $INSTALL_DIR"
echo "실행 계정 : $RUN_USER"
echo "현재 빌드 : ${current:-이전 버전 (build 정보 없음)}"
echo "받을 코드 : ${SOURCE_ZIP:-https://github.com/$REPO (브랜치 $BRANCH)}"

step "1/5 최신 코드 받기"
TMP="$(mktemp -d /tmp/wfdash-update.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
if [ -n "${SOURCE_ZIP:-}" ]; then
  [ -f "$SOURCE_ZIP" ] || die "SOURCE_ZIP 파일이 없습니다: $SOURCE_ZIP"
  command cp "$SOURCE_ZIP" "$TMP/src.zip"
  echo "로컬 ZIP 사용: $SOURCE_ZIP"
else
  curl -fsSL -o "$TMP/src.zip" "https://github.com/$REPO/archive/refs/heads/$BRANCH.zip" \
    || die "다운로드 실패. 서버에서 github.com 에 접속할 수 있는지 확인하세요 (안 되면 SOURCE_ZIP 사용)"
fi
command -v unzip >/dev/null || die "unzip 이 없습니다 (yum install -y unzip)"
unzip -q "$TMP/src.zip" -d "$TMP"
NEW="$(ls -1d "$TMP"/*/wildfly-dashboard 2>/dev/null | head -1)"
[ -n "$NEW" ] && [ -f "$NEW/server.js" ] && [ -f "$NEW/src/build.js" ] || die "받은 코드에 wildfly-dashboard 가 없습니다"
target="$(build_of "$NEW")"
ok "받은 빌드: $target"
if [ "$target" = "$current" ] && [ "${FORCE:-}" != "1" ]; then
  ok "이미 최신 빌드입니다. 재시작만 하려면 FORCE=1 $0"
  exit 0
fi

check_port_free_for_us

step "2/5 현재 버전 백업"
if [ "$target" = "$current" ]; then
  # reinstalling the same build: keep the backup of the real previous version for --rollback
  ok "같은 빌드 재설치라 백업을 건너뜁니다"
else
  stamp="$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$BACKUP_ROOT/$stamp"
  for item in "${RELEASE_ITEMS[@]}"; do
    if [ -e "$INSTALL_DIR/$item" ]; then command cp -a "$INSTALL_DIR/$item" "$BACKUP_ROOT/$stamp/"; fi
  done
  ok "백업: $BACKUP_ROOT/$stamp (빌드 ${current:-이전 버전})"
  ls -1d "$BACKUP_ROOT"/*/ | sort | head -n -"$KEEP_BACKUPS" | xargs -r rm -rf
fi

step "3/5 대시보드 중지"
stop_dashboard
ok "중지됨"

step "4/5 새 코드 복사 (config/, data/ 는 그대로)"
deps_changed=0
cmp -s "$NEW/package.json" "$INSTALL_DIR/package.json" || deps_changed=1
for item in "${RELEASE_ITEMS[@]}"; do
  [ -e "$NEW/$item" ] || continue
  rm -rf "${INSTALL_DIR:?}/$item"           # removes files dropped in the new release
  command cp -a "$NEW/$item" "$INSTALL_DIR/$item"
done
chmod +x "$INSTALL_DIR/scripts/"*.sh 2>/dev/null || true
if [ "$deps_changed" = 1 ] || [ ! -d "$INSTALL_DIR/node_modules" ]; then
  echo "라이브러리 변경 → npm ci"
  (cd "$INSTALL_DIR" && npm ci --omit=dev --no-audit --no-fund) || die "npm ci 실패. 되돌리려면: $0 --rollback"
fi
chown -R "$RUN_USER:" "$INSTALL_DIR"
[ "$(build_of "$INSTALL_DIR")" = "$target" ] || die "복사 후 빌드가 맞지 않습니다. 되돌리려면: $0 --rollback"
ok "복사 완료"

step "5/5 시작 + 확인"
start_dashboard
if verify "$target"; then
  echo
  ok "업데이트 완료: ${current:-이전 버전} → $target"
  echo "브라우저에서 Ctrl+F5 로 새로고침하세요. 문제가 있으면: sudo $0 --rollback"
else
  die "업데이트 후 확인 실패. 되돌리려면: sudo $0 --rollback"
fi
