#!/usr/bin/env bash
# =====================================================================
#  webwas-precheck-agent.sh - Web/WAS(Apache·WildFly·Tomcat·Nginx) 사전점검 대시보드 에이전트
#
#  서버에 설치되어 1분마다(systemd 타이머 또는 cron) 대시보드에 "점검할 차례인지" 묻고,
#  차례이면 이 서버에서 실행 중인 제품을 찾아 같은 폴더의 점검 스크립트를 실행하고 결과 리포트를 대시보드로 보냅니다.
#    Apache(httpd)  → apache_precheck.sh
#    WildFly        → wildfly_precheck.sh
#    Tomcat         → tomcat_precheck.sh
#    Nginx          → nginx_precheck.sh
#  점검 직전에 대시보드에서 제품별 최신 CVE 목록(/agent-api/cve/제품)을 받아 스크립트에 넘깁니다(PRECHECK_CVE_DB).
#  받지 못하면(대시보드 장애 등) 지난번에 받은 목록 → 스크립트 내장 목록 순서로 씁니다.
#
#  - 대시보드 쪽으로 나가는 연결(HTTP/HTTPS)만 사용합니다. 서버에 포트를 열지 않습니다.
#  - 대시보드는 "실행해라/말아라"만 알려 줍니다. 명령어·인자를 받아 실행하지 않습니다.
#    실행되는 것은 이 서버에 설치된 점검 스크립트뿐이며, CVE 목록은 스크립트가 "데이터"로만 읽습니다.
#  - 대시보드가 꺼져 있으면 리포트를 outbox 에 보관했다가 다음에 다시 보냅니다.
#
#  사용법 (root):
#    webwas-precheck-agent.sh poll   ← 타이머/cron 이 1분마다 실행 (차례일 때만 점검)
#    webwas-precheck-agent.sh detect ← 이 서버에서 점검할 제품만 확인 (점검·전송 안 함)
#    webwas-precheck-agent.sh run    ← 지금 바로 점검하고 결과 전송
#    webwas-precheck-agent.sh test   ← 대시보드 연결·인증만 확인
#
#  설정 파일: /etc/webwas-precheck-agent.conf (install.sh 가 만듦)
#    DASHBOARD_URL=https://대시보드주소/webwas-precheck
#    AGENT_NAME=web01
#    AGENT_TOKEN=...
#    CA_CERT=            (사설 인증서면 CA 파일 경로)
#    RUN_TIMEOUT=3600    (제품 하나 점검 최대 실행 시간, 초)
#    PRODUCTS=auto       (auto = 실행 중인 제품 자동 탐지 / 직접 지정: "apache tomcat" 처럼 공백으로)
#    RECENT_DAYS=30      (점검 스크립트 -d 값)
#    APACHE_LOG_PATHS=   (apache_precheck.sh  -l 값, 접근 로그 경로를 직접 지정할 때)
#    WILDFLY_LOG_PATHS=  (wildfly_precheck.sh -l 값. 예: 앞단 Apache 로그)
#    TOMCAT_LOG_PATHS=   (tomcat_precheck.sh  -l 값)
#    NGINX_LOG_PATHS=    (nginx_precheck.sh   -l 값)
#    WILDFLY_SERVER_LOG_PATHS= (wildfly_precheck.sh -s 값, server.log 가 표준 위치가 아닐 때)
#    TOMCAT_SERVER_LOG_PATHS=  (tomcat_precheck.sh  -s 값, catalina.out 등이 logs 폴더 밖에 있을 때)
# =====================================================================

AGENT_VERSION="2.4.0"   # 2.2.0: 서버 로그 경로(-s) / 2.3.0: Nginx / 2.3.1: 구버전 ps 호환 / 2.4.0: 대시보드 버튼으로 원격 스크립트 업데이트(update_scripts)
CONF="${WEBWAS_PRECHECK_AGENT_CONF:-/etc/webwas-precheck-agent.conf}"
BASE_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
ALL_PRODUCTS="apache wildfly tomcat nginx"   # 순서 고정 (스크립트 SHA-256 계산 순서 = 대시보드 Product 순서와 같음)
OUTBOX="$BASE_DIR/outbox"
CVE_DIR="$BASE_DIR/cve"
SENT="$BASE_DIR/sent"
LOCK="$BASE_DIR/.lock"
KEEP_SENT=20

log() { printf '%s [webwas-precheck-agent] %s\n' "$(date '+%F %T')" "$*" >&2; }
die() { log "오류: $*"; exit 1; }

[ "$(id -u)" -eq 0 ] || die "root 로 실행해야 합니다. (sudo $0 ${1:-poll})"
[ -r "$CONF" ] || die "설정 파일이 없습니다: $CONF  (install.sh 로 설치하세요)"
# shellcheck disable=SC1090
. "$CONF"
[ -n "${DASHBOARD_URL:-}" ] && [ -n "${AGENT_NAME:-}" ] && [ -n "${AGENT_TOKEN:-}" ] || die "설정 파일에 DASHBOARD_URL / AGENT_NAME / AGENT_TOKEN 이 필요합니다."
for p in $ALL_PRODUCTS; do [ -r "$BASE_DIR/${p}_precheck.sh" ] || die "점검 스크립트가 없습니다: $BASE_DIR/${p}_precheck.sh (install.sh 를 다시 실행하세요)"; done
DASHBOARD_URL="${DASHBOARD_URL%/}"
RUN_TIMEOUT="${RUN_TIMEOUT:-3600}"
command -v curl >/dev/null 2>&1 || die "curl 이 필요합니다."

umask 077
mkdir -p "$OUTBOX" "$SENT" "$CVE_DIR"
WORK="$(mktemp -d /tmp/webwas-precheck-agent.XXXXXX)" || die "임시 폴더를 만들 수 없습니다."
trap 'keepalive_stop; rm -rf "$WORK"' EXIT

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

# 점검 스크립트 3개를 정해진 순서로 이어 붙인 SHA-256 (대시보드의 것과 같으면 "스크립트 최신")
script_sha() {
  command -v sha256sum >/dev/null 2>&1 || { echo ""; return; }
  local p; for p in $ALL_PRODUCTS; do cat "$BASE_DIR/${p}_precheck.sh"; done | sha256sum | awk '{print $1}'
}

# 이 서버에서 점검할 제품 (PRODUCTS=auto 면 실행 중인 프로세스로 판단)
detect_products() {
  local want="${PRODUCTS:-auto}" out="" p
  if [ "$want" != "auto" ]; then
    for p in $want; do case " $ALL_PRODUCTS " in *" $p "*) out="$out $p" ;; esac; done
    echo "${out# }"; return
  fi
  local ps_out; ps_out="$(ps -e -o comm= -o args= 2>/dev/null)"
  printf '%s\n' "$ps_out" | grep -qE '^(httpd|apache2|httpd\.worker|httpd\.event)[[:space:]]' && out="$out apache"
  printf '%s\n' "$ps_out" | grep -q 'jboss-modules\.jar' && out="$out wildfly"
  printf '%s\n' "$ps_out" | grep -q 'org\.apache\.catalina\.startup\.Bootstrap' && out="$out tomcat"
  printf '%s\n' "$ps_out" | grep -qE '^nginx[[:space:]]+nginx: master process' && out="$out nginx"
  echo "${out# }"
}

# 제품별 최신 CVE 목록 받기 (실패하면 지난번 목록 유지). 사용할 파일 경로 출력 (없으면 빈 값)
fetch_cve() {
  local p="$1" f="$CVE_DIR/${1}_cve.txt" code
  code="$(api "cve/$p" -X GET)"
  if [ "$code" = "200" ] && grep -q '^# --- CVE_DB 시작' "$WORK/resp" && grep -q '^CVE-' "$WORK/resp"; then
    mv -f "$WORK/resp" "$f"
  else
    log "CVE 목록 받기 실패($p, HTTP ${code:-없음}) → $( [ -s "$f" ] && echo '지난번 목록' || echo '스크립트 내장 목록') 사용"
  fi
  [ -s "$f" ] && echo "$f"
}

heartbeat() { # $1 = busy(0/1), $2 = probe(0/1, 연결 확인만)
  api heartbeat -X POST \
    --data-urlencode "probe=${2:-0}" \
    --data-urlencode "hostname=$(hostname -f 2>/dev/null || hostname)" \
    --data-urlencode "version=$AGENT_VERSION" \
    --data-urlencode "scriptSha256=$(script_sha)" \
    --data-urlencode "busy=$1"
}

# 점검이 오래 걸려도(수 분) 대시보드에 "오프라인"으로 보이지 않도록, 점검하는 동안 1분마다 "점검 중" 신호를 보냄.
# (systemd 타이머는 점검이 끝날 때까지 다음 poll 을 시작하지 않으므로 이 신호가 없으면 3분 뒤 오프라인으로 보임)
KEEPALIVE_PID=""
keepalive_start() {
  local sha host
  sha="$(script_sha)"; host="$(hostname -f 2>/dev/null || hostname)"
  (
    while sleep 60; do
      curl -K "$CURLCFG" -o /dev/null -X POST --data-urlencode "probe=0" --data-urlencode "hostname=$host" \
        --data-urlencode "version=$AGENT_VERSION" --data-urlencode "scriptSha256=$sha" --data-urlencode "busy=1" \
        "$DASHBOARD_URL/agent-api/heartbeat" 2>/dev/null
    done
  ) </dev/null >/dev/null 2>&1 &
  KEEPALIVE_PID=$!
}
keepalive_stop() {
  [ -n "$KEEPALIVE_PID" ] || return 0
  pkill -P "$KEEPALIVE_PID" 2>/dev/null   # 대기 중인 sleep 도 함께 정리
  kill "$KEEPALIVE_PID" 2>/dev/null
  wait "$KEEPALIVE_PID" 2>/dev/null
  KEEPALIVE_PID=""
}

# outbox 의 리포트를 모두 전송. 전송 성공 수를 출력
flush_outbox() {
  local f code n=0
  for f in "$OUTBOX"/*_precheck_*.txt; do
    [ -f "$f" ] || continue
    code="$(api "report?name=$(basename "$f")" -X POST -H 'Content-Type: text/plain; charset=UTF-8' --data-binary @"$f")"
    if [ "$code" = "200" ]; then
      mv -f "$f" "$SENT/" && n=$((n+1))
    else
      log "리포트 전송 실패($code): $(basename "$f") $(head -c 300 "$WORK/resp" 2>/dev/null) $(cat "$WORK/curl.err" 2>/dev/null)"
    fi
  done
  # 보낸 리포트는 최근 KEEP_SENT 개만 보관
  ls -1t "$SENT"/*_precheck_*.txt 2>/dev/null | tail -n +$((KEEP_SENT+1)) | while read -r old; do rm -f "$old"; done
  echo "$n"
}

# 대시보드가 "스크립트 업데이트"를 지시하면(heartbeat 응답 update:true) 호출.
# 에이전트가 자기 대시보드(DASHBOARD_URL)에서 점검 스크립트 4개 + 에이전트 본체를 다시 받아 교체.
#   - 받은 파일이 비어있지 않고 '#!' 로 시작하고 bash 문법검사를 통과할 때만 교체(원자적 mv). 아니면 기존 유지.
#   - 에이전트 본체는 맨 마지막에 교체 → 다음 타이머 실행부터 새 버전 적용.
update_scripts() {
  log "스크립트 업데이트 시작 (대시보드에서 다시 받기)"
  local name code tmp fail=0
  for name in apache_precheck.sh wildfly_precheck.sh tomcat_precheck.sh nginx_precheck.sh webwas-precheck-agent.sh; do
    code="$(api "files/$name" -X GET)"
    if [ "$code" = "200" ] && [ -s "$WORK/resp" ] && head -n1 "$WORK/resp" | grep -q '^#!' && bash -n "$WORK/resp" 2>/dev/null; then
      tmp="$BASE_DIR/.upd.$$.$name"
      if cp -f "$WORK/resp" "$tmp" 2>/dev/null && chmod +x "$tmp" && mv -f "$tmp" "$BASE_DIR/$name"; then
        log "  갱신: $name"
      else rm -f "$tmp" 2>/dev/null; log "  실패(쓰기 권한 확인): $name"; fail=1; fi
    else
      log "  실패: $name (HTTP ${code:-없음} 또는 내용 이상 → 건너뜀, 기존 유지)"; fail=1
    fi
  done
  [ "$fail" = 0 ] && log "스크립트 업데이트 완료" || log "스크립트 업데이트 일부 실패 — 대시보드에서 다시 요청하세요"
  heartbeat 0 >/dev/null 2>&1 || true   # 새 스크립트 해시를 바로 보고(화면이 '같음'으로 갱신되도록)
}

do_run() {
  local marker="$WORK/marker" rc=0 one n_made n_sent msg products p args cve lp slp script done_list="" fail_list=""
  : > "$marker"; sleep 1
  keepalive_start
  products="$(detect_products)"
  if [ -z "$products" ]; then
    msg="점검할 제품을 찾지 못함 (실행 중인 Apache/WildFly/Tomcat/Nginx 없음. 꺼져 있으면 설정 파일에 PRODUCTS=\"apache\" 처럼 지정)"
    log "점검 종료: $msg"
    keepalive_stop
    api result -X POST --data-urlencode "exit=3" --data-urlencode "reports=0" --data-urlencode "message=$msg" >/dev/null
    return
  fi
  for p in $products; do
    script="$BASE_DIR/${p}_precheck.sh"
    args=()
    [ -n "${RECENT_DAYS:-}" ] && args+=(-d "$RECENT_DAYS")
    case "$p" in
      apache) lp="${APACHE_LOG_PATHS:-${LOG_PATHS:-}}" ;;
      wildfly) lp="${WILDFLY_LOG_PATHS:-}" ;;
      tomcat) lp="${TOMCAT_LOG_PATHS:-}" ;;
      nginx) lp="${NGINX_LOG_PATHS:-}" ;;
    esac
    [ -n "$lp" ] && args+=(-l "$lp")
    case "$p" in
      wildfly) slp="${WILDFLY_SERVER_LOG_PATHS:-}" ;;
      tomcat) slp="${TOMCAT_SERVER_LOG_PATHS:-}" ;;
      *) slp="" ;;
    esac
    [ -n "$slp" ] && args+=(-s "$slp")
    cve="$(fetch_cve "$p")"
    log "점검 시작: $script ${args[*]}${cve:+ (CVE 목록: $cve)}"
    if command -v timeout >/dev/null 2>&1; then
      PRECHECK_NO_SUDO=1 PRECHECK_CVE_DB="$cve" timeout "$RUN_TIMEOUT" bash "$script" "${args[@]}" </dev/null >"$WORK/run_$p.log" 2>&1
    else
      PRECHECK_NO_SUDO=1 PRECHECK_CVE_DB="$cve" bash "$script" "${args[@]}" </dev/null >"$WORK/run_$p.log" 2>&1
    fi
    one=$?
    if [ "$one" -eq 0 ]; then done_list="$done_list $p"; else fail_list="$fail_list $p(exit=$one)"; rc=$one; fi
  done
  # 이번 실행에서 만들어진 리포트(제품·인스턴스가 여러 개면 여러 개)를 outbox 로 옮김
  n_made=0
  while IFS= read -r f; do
    mv -f "$f" "$OUTBOX/" && n_made=$((n_made+1))
  done < <(find /tmp -maxdepth 1 -type f \( -name 'apache_precheck_*.txt' -o -name 'wildfly_precheck_*.txt' -o -name 'tomcat_precheck_*.txt' -o -name 'nginx_precheck_*.txt' \) -newer "$marker" 2>/dev/null)
  n_sent="$(flush_outbox)"

  if [ "$rc" -eq 124 ]; then msg="점검 시간 초과(${RUN_TIMEOUT}초)로 중단됨:${fail_list}"
  elif [ "$n_made" -eq 0 ]; then msg="리포트가 만들어지지 않음 (${products}): $(for p in $products; do tail -n 2 "$WORK/run_$p.log"; done | tr '\n' ' ' | cut -c1-300)"
  elif [ "$n_sent" -lt "$n_made" ]; then msg="리포트 ${n_made}개 중 ${n_sent}개만 전송됨 (나머지는 다음에 재전송)"
  else msg="리포트 ${n_sent}개 전송 완료 (${products// /, })${fail_list:+ / 오류:$fail_list}"
  fi
  log "점검 종료(exit=$rc): $msg"
  keepalive_stop
  api result -X POST --data-urlencode "exit=$rc" --data-urlencode "reports=$n_sent" --data-urlencode "message=$msg" >/dev/null
}

case "${1:-poll}" in
  detect)
    p="$(detect_products)"
    echo "점검할 제품: ${p:-(없음)}  (설정 PRODUCTS=${PRODUCTS:-auto})"
    exit 0
    ;;
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
    # 응답 플래그를 먼저 읽음 (update_scripts 가 $WORK/resp 를 덮어쓰므로)
    do_upd=0; do_chk=0
    grep -q '"update":true' "$WORK/resp" && do_upd=1
    grep -q '"run":true' "$WORK/resp" && do_chk=1
    [ "$do_upd" = 1 ] && update_scripts
    [ "$do_chk" = 1 ] && do_run
    ;;
  *)
    echo "사용법: $0 {poll|run|test|detect}"; exit 1 ;;
esac
