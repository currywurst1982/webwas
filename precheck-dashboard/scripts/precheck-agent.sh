#!/usr/bin/env bash
# =====================================================================
#  precheck-agent.sh - Apache 사전점검 대시보드 에이전트
#
#  웹서버에 설치되어 1분마다(systemd 타이머 또는 cron) 대시보드에 "점검할 차례인지" 묻고,
#  차례이면 같은 폴더의 apache_precheck.sh 를 실행해 결과 리포트를 대시보드로 보냅니다.
#
#  - 대시보드 쪽으로 나가는 연결(HTTP/HTTPS)만 사용합니다. 웹서버에 포트를 열지 않습니다.
#  - 대시보드는 "실행해라/말아라"만 알려 줍니다. 명령어·인자를 받아 실행하지 않습니다.
#    실행되는 것은 이 서버에 설치된 apache_precheck.sh 하나뿐입니다.
#  - 대시보드가 꺼져 있으면 리포트를 outbox 에 보관했다가 다음에 다시 보냅니다.
#
#  사용법 (root):
#    precheck-agent.sh poll   ← 타이머/cron 이 1분마다 실행 (차례일 때만 점검)
#    precheck-agent.sh run    ← 지금 바로 점검하고 결과 전송
#    precheck-agent.sh test   ← 대시보드 연결·인증만 확인
#
#  설정 파일: /etc/precheck-agent.conf (install.sh 가 만듦)
#    DASHBOARD_URL=https://대시보드주소/precheck
#    AGENT_NAME=web01
#    AGENT_TOKEN=...
#    CA_CERT=            (사설 인증서면 CA 파일 경로)
#    RUN_TIMEOUT=3600    (점검 최대 실행 시간, 초)
#    RECENT_DAYS=30      (apache_precheck.sh -d 값)
#    LOG_PATHS=          (apache_precheck.sh -l 값, 접근 로그 경로를 직접 지정할 때)
# =====================================================================

AGENT_VERSION="1.0.0"
CONF="${PRECHECK_AGENT_CONF:-/etc/precheck-agent.conf}"
BASE_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
SCRIPT="$BASE_DIR/apache_precheck.sh"
OUTBOX="$BASE_DIR/outbox"
SENT="$BASE_DIR/sent"
LOCK="$BASE_DIR/.lock"
KEEP_SENT=20

log() { printf '%s [precheck-agent] %s\n' "$(date '+%F %T')" "$*" >&2; }
die() { log "오류: $*"; exit 1; }

[ "$(id -u)" -eq 0 ] || die "root 로 실행해야 합니다. (sudo $0 ${1:-poll})"
[ -r "$CONF" ] || die "설정 파일이 없습니다: $CONF  (install.sh 로 설치하세요)"
# shellcheck disable=SC1090
. "$CONF"
[ -n "${DASHBOARD_URL:-}" ] && [ -n "${AGENT_NAME:-}" ] && [ -n "${AGENT_TOKEN:-}" ] || die "설정 파일에 DASHBOARD_URL / AGENT_NAME / AGENT_TOKEN 이 필요합니다."
[ -r "$SCRIPT" ] || die "점검 스크립트가 없습니다: $SCRIPT"
DASHBOARD_URL="${DASHBOARD_URL%/}"
RUN_TIMEOUT="${RUN_TIMEOUT:-3600}"
command -v curl >/dev/null 2>&1 || die "curl 이 필요합니다."

umask 077
mkdir -p "$OUTBOX" "$SENT"
WORK="$(mktemp -d /tmp/precheck-agent.XXXXXX)" || die "임시 폴더를 만들 수 없습니다."
trap 'rm -rf "$WORK"' EXIT

# 토큰이 ps 명령에 보이지 않도록 curl 설정 파일(권한 600)로 헤더를 넘김
CURLCFG="$WORK/curl.cfg"
{
  printf 'header = "X-Precheck-Agent: %s"\n' "$AGENT_NAME"
  printf 'header = "Authorization: Bearer %s"\n' "$AGENT_TOKEN"
  printf 'connect-timeout = 10\nmax-time = 120\nsilent\nshow-error\n'
  [ -n "${CA_CERT:-}" ] && printf 'cacert = "%s"\n' "$CA_CERT"
} > "$CURLCFG"

# api <경로> [curl 인자...]  → 응답 본문은 $WORK/resp, HTTP 코드는 표준출력
api() {
  local path="$1"; shift
  curl -K "$CURLCFG" -o "$WORK/resp" -w '%{http_code}' "$@" "$DASHBOARD_URL/agent-api/$path" 2>"$WORK/curl.err"
}

script_sha() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$SCRIPT" | awk '{print $1}'; else echo ""; fi
}

heartbeat() { # $1 = busy(0/1), $2 = probe(0/1, 연결 확인만)
  api heartbeat -X POST \
    --data-urlencode "probe=${2:-0}" \
    --data-urlencode "hostname=$(hostname -f 2>/dev/null || hostname)" \
    --data-urlencode "version=$AGENT_VERSION" \
    --data-urlencode "scriptSha256=$(script_sha)" \
    --data-urlencode "busy=$1"
}

# outbox 의 리포트를 모두 전송. 전송 성공 수를 출력
flush_outbox() {
  local f code n=0
  for f in "$OUTBOX"/apache_precheck_*.txt; do
    [ -f "$f" ] || continue
    code="$(api "report?name=$(basename "$f")" -X POST -H 'Content-Type: text/plain; charset=UTF-8' --data-binary @"$f")"
    if [ "$code" = "200" ]; then
      mv -f "$f" "$SENT/" && n=$((n+1))
    else
      log "리포트 전송 실패($code): $(basename "$f") $(head -c 300 "$WORK/resp" 2>/dev/null) $(cat "$WORK/curl.err" 2>/dev/null)"
    fi
  done
  # 보낸 리포트는 최근 KEEP_SENT 개만 보관
  ls -1t "$SENT"/apache_precheck_*.txt 2>/dev/null | tail -n +$((KEEP_SENT+1)) | while read -r old; do rm -f "$old"; done
  echo "$n"
}

do_run() {
  local marker="$WORK/marker" rc n_made n_sent msg args=()
  : > "$marker"; sleep 1
  [ -n "${RECENT_DAYS:-}" ] && args+=(-d "$RECENT_DAYS")
  [ -n "${LOG_PATHS:-}" ] && args+=(-l "$LOG_PATHS")
  log "점검 시작: $SCRIPT ${args[*]}"
  if command -v timeout >/dev/null 2>&1; then
    PRECHECK_NO_SUDO=1 timeout "$RUN_TIMEOUT" bash "$SCRIPT" "${args[@]}" </dev/null >"$WORK/run.log" 2>&1
  else
    PRECHECK_NO_SUDO=1 bash "$SCRIPT" "${args[@]}" </dev/null >"$WORK/run.log" 2>&1
  fi
  rc=$?
  # 이번 실행에서 만들어진 리포트(인스턴스가 여러 개면 여러 개)를 outbox 로 옮김
  n_made=0
  while IFS= read -r f; do
    mv -f "$f" "$OUTBOX/" && n_made=$((n_made+1))
  done < <(find /tmp -maxdepth 1 -type f -name 'apache_precheck_*.txt' -newer "$marker" 2>/dev/null)
  n_sent="$(flush_outbox)"

  if [ "$rc" -eq 124 ]; then msg="점검 시간 초과(${RUN_TIMEOUT}초)로 중단됨"
  elif [ "$n_made" -eq 0 ]; then msg="리포트가 만들어지지 않음: $(tail -n 3 "$WORK/run.log" | tr '\n' ' ' | cut -c1-300)"
  elif [ "$n_sent" -lt "$n_made" ]; then msg="리포트 ${n_made}개 중 ${n_sent}개만 전송됨 (나머지는 다음에 재전송)"
  else msg="리포트 ${n_sent}개 전송 완료"
  fi
  log "점검 종료(exit=$rc): $msg"
  api result -X POST --data-urlencode "exit=$rc" --data-urlencode "reports=$n_sent" --data-urlencode "message=$msg" >/dev/null
}

case "${1:-poll}" in
  test)
    code="$(heartbeat 0 1)"
    if [ "$code" = "200" ]; then log "대시보드 연결 성공: $DASHBOARD_URL (에이전트 $AGENT_NAME)"; cat "$WORK/resp"; echo; exit 0; fi
    die "대시보드 연결 실패(HTTP ${code:-없음}): $(cat "$WORK/resp" "$WORK/curl.err" 2>/dev/null)"
    ;;
  run|poll)
    exec 9>"$LOCK"
    if ! flock -n 9; then
      # 이미 점검이 진행 중 → 상태만 알림
      [ "$1" = "poll" ] && heartbeat 1 >/dev/null
      [ "$1" = "run" ] && log "이미 점검이 진행 중입니다."
      exit 0
    fi
    if [ "${1:-poll}" = "run" ]; then
      heartbeat 1 >/dev/null
      do_run
      exit 0
    fi
    [ -n "$(ls -A "$OUTBOX" 2>/dev/null)" ] && flush_outbox >/dev/null
    code="$(heartbeat 0)"
    if [ "$code" != "200" ]; then
      log "heartbeat 실패(HTTP ${code:-없음}): $(head -c 300 "$WORK/resp" 2>/dev/null) $(cat "$WORK/curl.err" 2>/dev/null)"
      exit 1
    fi
    if grep -q '"run":true' "$WORK/resp"; then
      do_run
    fi
    ;;
  *)
    echo "사용법: $0 {poll|run|test}"; exit 1 ;;
esac
