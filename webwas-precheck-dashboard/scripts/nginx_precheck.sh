#!/usr/bin/env bash
# =====================================================================
#  nginx_precheck.sh
#  Nginx 서버 - 패치 전 보안 사전 점검 스크립트
#
#  - 읽기 전용: 설정 변경/파일 삭제/서비스 재시작을 하지 않습니다.
#  - 점검 항목
#      [1] 버전 / 브랜치(mainline·stable·지원 종료) / 설치 방식(RPM·DEB·소스) 확인
#      [2] 버전별 해당 CVE 판정 (nginx.org 보안 공지 기준, 설정에서 쓰는 기능으로 해당/미해당 구분,
#          패키지 설치본은 changelog 에 수정 기록이 있으면 "백포트 추정")
#      [3] 위험 설정 점검 (nginx -T 로 실제로 읽는 설정 전체: 버전 노출, 디렉터리 목록, 약한 TLS,
#          alias 경로 탐색, stub_status 노출, WebDAV, 프록시 SSRF, PHP 실행 위험, 실행 계정, 파일 권한)
#      [4] 침해 흔적 점검 (접근 로그, 웹 루트의 웹쉘 의심 파일, 의심 프로세스/연결/크론, OS 로그인 기록)
#  - 결과: 화면 출력 + 리포트 파일(/tmp/nginx_precheck_<호스트>_<시각>[_pid<PID>].txt)
#
#  CVE 데이터 출처: https://nginx.org/en/security_advisories.html
#                   (원본 XML https://raw.githubusercontent.com/nginx/nginx.org/main/xml/en/security_advisories.xml,
#                    2026-11-10 기준 66건). 대시보드에 연결된 에이전트로 실행하면 대시보드가 12시간마다
#                   갱신한 최신 목록을 자동으로 받아 씁니다(PRECHECK_CVE_DB). 직접 실행할 때는 -C 로 지정.
#  최신 버전 기준: https://nginx.org/en/download.html (원본 xml/versions.xml) 의 stable 1.30.6
#                  (운영 기준을 stable 로 둠. stable 보다 새 mainline 은 "최신"으로 보되 mainline 최신 여부는 따로 확인)
#
#  사용법:  ./nginx_precheck.sh            ← 옵션 없이 실행 (권장)
#    - 실행 중인 nginx 마스터 프로세스를 자동으로 찾아 실행파일·설정파일(-c)을 따라갑니다.
#    - 인스턴스가 여러 개면 각각 점검하고 리포트를 따로 만듭니다.
#    - root 가 아니면 sudo 로 자동 재실행합니다(비밀번호를 물을 수 있음).
#  선택 옵션: [-b nginx경로] [-c 설정파일] [-d 일수] [-l '로그경로'] [-C CVE목록파일]
#    -b : nginx 실행파일 경로 직접 지정 (Nginx 가 꺼져 있어 자동 탐지가 안 될 때)
#    -c : 설정 파일 직접 지정 (기본: nginx -V 의 --conf-path)
#    -d : "최근 변경 파일" 점검 기간(일). 기본 30. OS 로그인 기록(/var/log/secure 등) 점검 기간으로도 씀
#    -l : 접근 로그 경로 직접 지정 (와일드카드 가능, 반드시 작은따옴표로 감쌀 것)
#         예: -l '/logs/nginx/access*.log*'
#    -C : CVE 목록 파일 (대시보드의 /agent-api/cve/nginx 에서 받은 파일)
# =====================================================================

# 최신 버전 기준: stable 브랜치 최신. 대시보드 CVE 목록의 "# LATEST=" 값이 있으면 그 값을 사용
LATEST_BRANCHES="1.30.6"

NGINX_BIN=""
NGINX_CONF=""
NGINX_PREFIX=""
RECENT_DAYS=30
LOG_PATHS=""
ORIG_ARGS=("$@")
while getopts "b:c:p:d:l:C:h" opt; do
  case "$opt" in
    b) NGINX_BIN="$OPTARG" ;;
    c) NGINX_CONF="$OPTARG" ;;
    p) NGINX_PREFIX="$OPTARG" ;;   # 내부용: 인스턴스의 -p 값
    d) RECENT_DAYS="$OPTARG" ;;
    l) LOG_PATHS="$OPTARG" ;;
    C) PRECHECK_CVE_DB="$(readlink -f "$OPTARG")"; export PRECHECK_CVE_DB ;;
    h) sed -n '2,/^# =\{10,\}$/p' "$0"; exit 0 ;;
    *) echo "알 수 없는 옵션입니다. -h 로 사용법을 확인하세요."; exit 1 ;;
  esac
done
[[ "$RECENT_DAYS" =~ ^[0-9]+$ ]] || RECENT_DAYS=30

SELF="$(readlink -f "$0")"

# --- root 가 아니면 sudo 로 자동 재실행 ----------------------------------
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && [ -z "${PRECHECK_NO_SUDO:-}" ]; then
  echo "[안내] root 권한이 필요해 sudo 로 다시 실행합니다. (비밀번호를 물으면 입력하세요)"
  if sudo -v 2>/dev/null; then
    exec sudo PRECHECK_NO_SUDO=1 PRECHECK_CVE_DB="${PRECHECK_CVE_DB:-}" bash "$SELF" "${ORIG_ARGS[@]}"
  fi
  echo "[안내] sudo 권한을 얻지 못해 현재 계정 권한으로 계속합니다. (결과가 불완전할 수 있음)"
fi

# --- 실행 중인 Nginx 인스턴스(마스터 프로세스) 자동 탐지 ------------------
# 출력 형식: 실행파일<US>설정파일(-c)<US>prefix(-p)<US>PID   (US=\x1f)
# nginx 마스터의 명령줄은 "nginx: master process /usr/sbin/nginx -c /etc/nginx/nginx.conf" 처럼 한 줄로 바뀌어 있음
detect_instances() {
  local pid ppid comm pcomm exe args conf prefix
  ps -eo pid=,ppid=,comm= 2>/dev/null | awk '$3 == "nginx"' | while read -r pid ppid comm; do
    pcomm="$(ps -o comm= -p "$ppid" 2>/dev/null)"
    [ "$pcomm" = "nginx" ] && continue   # 워커·캐시 관리 프로세스
    args="$(tr '\0' ' ' < /proc/"$pid"/cmdline 2>/dev/null)"
    exe="$(readlink /proc/"$pid"/exe 2>/dev/null)"; exe="${exe% (deleted)}"
    if [ -z "$exe" ] || [ ! -x "$exe" ]; then
      exe="$(printf '%s' "$args" | sed -n 's/^nginx: master process \([^ ]*\).*/\1/p')"
      [[ "$exe" != /* ]] && exe="$(command -v "${exe:-nginx}" 2>/dev/null)"
    fi
    [ -z "$exe" ] && continue
    conf="$(printf '%s' "$args" | sed -n 's/.* -c \([^ ]*\).*/\1/p')"
    prefix="$(printf '%s' "$args" | sed -n 's/.* -p \([^ ]*\).*/\1/p')"
    printf '%s\x1f%s\x1f%s\x1f%s\n' "$exe" "$conf" "$prefix" "$pid"
  done | sort -u -t$'\x1f' -k1,3
}

if [ -z "$NGINX_BIN" ]; then
  INSTANCES="$(detect_instances)"
  N_INST=0; [ -n "$INSTANCES" ] && N_INST="$(printf '%s\n' "$INSTANCES" | wc -l)"
  if [ "$N_INST" -gt 1 ]; then
    echo "[안내] 실행 중인 Nginx 인스턴스 ${N_INST}개를 찾았습니다. 각각 점검합니다."
    i=0
    while IFS=$'\x1f' read -r exe conf prefix pid; do
      i=$((i+1))
      echo ""; echo "################ 인스턴스 ${i}/${N_INST} (PID ${pid}) ################"
      PASS=(-b "$exe" -d "$RECENT_DAYS")
      [ -n "$conf" ] && PASS+=(-c "$conf")
      [ -n "$prefix" ] && PASS+=(-p "$prefix")
      [ -n "$LOG_PATHS" ] && PASS+=(-l "$LOG_PATHS")
      PRECHECK_NO_SUDO=1 PRECHECK_PID="$pid" bash "$SELF" "${PASS[@]}" </dev/null
    done <<< "$INSTANCES"
    echo ""; echo "[안내] 전체 인스턴스 점검 완료. 리포트 파일 목록:"
    ls -1t /tmp/nginx_precheck_*_pid*.txt 2>/dev/null | head -n "$N_INST" | sed 's/^/       /'
    exit 0
  elif [ "$N_INST" -eq 1 ]; then
    IFS=$'\x1f' read -r NGINX_BIN C1 P1 PRECHECK_PID <<< "$INSTANCES"
    [ -z "$NGINX_CONF" ] && NGINX_CONF="$C1"
    [ -z "$NGINX_PREFIX" ] && NGINX_PREFIX="$P1"
  fi
fi
CONF_ARG="$NGINX_CONF"   # 명령줄 -c 로 지정된 설정 (인스턴스 구분용)

TS="$(date +%Y%m%d_%H%M%S)"
REPORT="/tmp/nginx_precheck_$(hostname -s 2>/dev/null || echo host)_${TS}${PRECHECK_PID:+_pid$PRECHECK_PID}.txt"
WORK="$(mktemp -d /tmp/nginx_precheck.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

CNT_RISK=0; CNT_WARN=0; CNT_OK=0; CNT_INFO=0

if [ -t 1 ]; then
  C_RED=$'\e[1;31m'; C_YEL=$'\e[1;33m'; C_GRN=$'\e[1;32m'; C_BLU=$'\e[1;36m'; C_RST=$'\e[0m'
else
  C_RED=""; C_YEL=""; C_GRN=""; C_BLU=""; C_RST=""
fi

log()     { printf '%s\n' "$*" | tee -a "$REPORT" >/dev/null; printf '%s\n' "$*"; }
_out()    { printf '%s%s%s %s\n' "$1" "$2" "$C_RST" "$3"; printf '%s %s\n' "$2" "$3" >> "$REPORT"; }
risk()    { CNT_RISK=$((CNT_RISK+1)); _out "$C_RED" "[위험]" "$*"; }
warn()    { CNT_WARN=$((CNT_WARN+1)); _out "$C_YEL" "[주의]" "$*"; }
ok()      { CNT_OK=$((CNT_OK+1));     _out "$C_GRN" "[양호]" "$*"; }
info()    { CNT_INFO=$((CNT_INFO+1)); _out "$C_BLU" "[정보]" "$*"; }
detail()  { printf '        %s\n' "$*"; printf '        %s\n' "$*" >> "$REPORT"; }
section() { log ""; log "=================================================================="; log " $*"; log "=================================================================="; }

# a <= b ?
ver_le() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$1" ]; }
# 브랜치 (1.30.6 → 1.30)
br() { printf '%s' "$1" | cut -d. -f1-2; }

# 대시보드에서 받은 CVE 목록의 최신 버전 기준 (# LATEST=1.30.6) 이 있으면 그 값을 사용 (홀수 = mainline 은 버림)
if [ -n "${PRECHECK_CVE_DB:-}" ] && [ -r "$PRECHECK_CVE_DB" ]; then
  L="$(sed -n 's/^# LATEST=//p' "$PRECHECK_CVE_DB" | head -n1 | tr ',' ' ')"
  if printf '%s' "$L" | grep -qE '^ *[0-9]+\.[0-9]+\.[0-9]+( +[0-9]+\.[0-9]+\.[0-9]+)* *$'; then
    L2="$(for v in $L; do [ $(( $(printf '%s' "$v" | cut -d. -f2) % 2 )) -eq 0 ] && printf '%s ' "$v"; done | xargs)"
    LATEST_BRANCHES="${L2:-$(printf '%s' "$L" | xargs)}"
  fi
fi

: > "$REPORT"
log "Nginx 패치 전 보안 사전 점검  |  호스트: $(hostname)  |  일시: $(date '+%F %T')"

if [ "$(id -u)" -ne 0 ]; then
  warn "root 권한이 아닙니다(sudo 없음). 로그/설정/프로세스 정보를 못 읽어 결과가 불완전할 수 있습니다."
fi

# =====================================================================
section "[1] 버전 및 설치 방식 확인"
# =====================================================================
[ -n "${PRECHECK_PID:-}" ] && info "실행 중인 Nginx 프로세스 자동 탐지: 마스터 PID $PRECHECK_PID"
if [ -z "$NGINX_BIN" ]; then
  warn "실행 중인 nginx 프로세스를 찾지 못해 설치 경로에서 찾습니다. (Nginx 가 꺼져 있거나 프로세스명이 다를 수 있음)"
  for c in nginx /usr/sbin/nginx /usr/local/nginx/sbin/nginx /opt/nginx/sbin/nginx /usr/local/openresty/nginx/sbin/nginx; do
    if command -v "$c" >/dev/null 2>&1; then NGINX_BIN="$(command -v "$c")"; break; fi
  done
fi
if [ -z "$NGINX_BIN" ] || [ ! -x "$NGINX_BIN" ]; then
  risk "nginx 실행파일을 찾지 못했습니다. Nginx 를 기동한 상태에서 다시 실행하거나 -b 로 경로를 지정하세요. (예: -b /usr/local/nginx/sbin/nginx)"
  exit 1
fi
# nginx 호출 래퍼: 실제 인스턴스와 같은 prefix·설정 파일로 실행
ng() {
  local a=()
  [ -n "$NGINX_PREFIX" ] && a+=(-p "$NGINX_PREFIX")
  [ -n "$NGINX_CONF" ] && a+=(-c "$NGINX_CONF")
  "$NGINX_BIN" "${a[@]}" "$@"
}

VER_LINE="$("$NGINX_BIN" -v 2>&1 | head -n1)"
VER="$(printf '%s' "$VER_LINE" | grep -oE 'nginx/[0-9]+\.[0-9]+\.[0-9]+' | head -n1 | cut -d/ -f2)"
if [ -z "$VER" ]; then   # OpenResty 등: openresty/1.25.3.1 → nginx 1.25.3 기반
  VER="$(printf '%s' "$VER_LINE" | grep -oE '[A-Za-z]+/[0-9]+\.[0-9]+\.[0-9]+' | head -n1 | cut -d/ -f2)"
  [ -n "$VER" ] && info "nginx 파생 배포판(OpenResty 등)으로 보입니다. 앞의 세 자리($VER)를 nginx 버전으로 보고 판정합니다."
fi
VFULL="$("$NGINX_BIN" -V 2>&1)"

server_ips() {
  local ips=""
  if hostname -I >/dev/null 2>&1; then
    ips="$(hostname -I 2>/dev/null)"
  elif command -v ip >/dev/null 2>&1; then
    ips="$(ip -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | tr '\n' ' ')"
  elif command -v ifconfig >/dev/null 2>&1; then
    ips="$(ifconfig 2>/dev/null | awk '/inet6? /{a=$2; sub(/^addr:/,"",a); print a}' | tr '\n' ' ')"
  fi
  printf '%s\n' $ips | grep -vE '^(127\.|::1$|fe80:|169\.254\.)' | awk 'index($0,":")==0{v4=v4" "$0; next} {v6=v6" "$0} END{print v4 v6}' | sed 's/^ *//'
}
SERVER_IPS="$(server_ips)"
info "서버 IP: ${SERVER_IPS:-확인 불가}"
info "실행파일: $NGINX_BIN"
info "버전 정보: ${VER_LINE:-확인 불가}"
if [ -z "$VER" ]; then
  risk "버전을 해석하지 못했습니다. 수동 확인이 필요합니다."
  exit 1
fi

# 설정 파일: -c → nginx -V 의 --conf-path (상대 경로면 --prefix 기준)
PREFIX_V="$(printf '%s\n' "$VFULL" | grep -oE -- '--prefix=[^ ]+' | head -n1 | cut -d= -f2-)"
[ -z "$NGINX_PREFIX" ] && NGINX_PREFIX_EFF="${PREFIX_V:-/usr/local/nginx}" || NGINX_PREFIX_EFF="$NGINX_PREFIX"
if [ -z "$NGINX_CONF" ]; then
  CP="$(printf '%s\n' "$VFULL" | grep -oE -- '--conf-path=[^ ]+' | head -n1 | cut -d= -f2-)"
  NGINX_CONF_EFF="${CP:-conf/nginx.conf}"
else
  NGINX_CONF_EFF="$NGINX_CONF"
fi
[[ "$NGINX_CONF_EFF" != /* ]] && NGINX_CONF_EFF="${NGINX_PREFIX_EFF%/}/$NGINX_CONF_EFF"
info "메인 설정 파일: $NGINX_CONF_EFF"
[ -n "$CONF_ARG" ] && info "인스턴스 구분: -c $CONF_ARG"

# 설치 방식 (패키지라면 버전 숫자와 실제 보안수정 반영 여부가 다를 수 있음)
PKG_TYPE="source"; CHANGELOG="$WORK/changelog.txt"; : > "$CHANGELOG"
if command -v rpm >/dev/null 2>&1 && rpm -qf "$NGINX_BIN" >/dev/null 2>&1; then
  PKG_TYPE="rpm"
  PKG_NAME="$(rpm -qf "$NGINX_BIN")"
  rpm -q --changelog "$(rpm -qf --qf '%{NAME}' "$NGINX_BIN")" > "$CHANGELOG" 2>/dev/null
  info "설치 방식: RPM 패키지 ($PKG_NAME)"
elif command -v dpkg >/dev/null 2>&1 && dpkg -S "$NGINX_BIN" >/dev/null 2>&1; then
  PKG_TYPE="deb"
  PKG_NAME="$(dpkg -S "$NGINX_BIN" 2>/dev/null | cut -d: -f1 | head -n1)"
  for f in /usr/share/doc/nginx*/changelog.Debian.gz; do
    [ -f "$f" ] && zcat "$f" >> "$CHANGELOG" 2>/dev/null
  done
  info "설치 방식: DEB 패키지 ($PKG_NAME)"
else
  info "설치 방식: 소스 설치(또는 패키지 정보 없음) → 버전 숫자 기준으로 판정합니다."
fi
[ "$PKG_TYPE" != "source" ] && warn "패키지 설치본은 버전 숫자가 낮아도 배포판이 보안수정을 백포트했을 수 있습니다. [2]에서 changelog 반영 여부를 함께 표시합니다."

# 브랜치 판정: nginx.org 는 mainline(홀수)·stable(짝수) 두 브랜치만 보안 수정을 냄. 이 점검은 stable 을 기준으로 봄
LATEST_SAME=""
for v in $LATEST_BRANCHES; do [ "$(br "$v")" = "$(br "$VER")" ] && LATEST_SAME="$v"; done
NEWEST="$(printf '%s\n' $LATEST_BRANCHES | sort -V | tail -n1)"
LATEST_SHOW="$(printf '%s' "$LATEST_BRANCHES" | sed 's/ / \/ /g')"
if [ -n "$LATEST_SAME" ]; then
  if ver_le "$LATEST_SAME" "$VER"; then
    ok "Nginx $VER : $(br "$VER") 브랜치 최신($LATEST_SAME) 이상입니다."
  else
    risk "Nginx $VER : $(br "$VER") 브랜치 최신 $LATEST_SAME 미만입니다. 아래 [2]에서 해당 CVE를 확인하세요."
  fi
elif ver_le "$NEWEST" "$VER"; then
  ok "Nginx $VER : stable 최신($LATEST_SHOW)보다 새 버전(mainline)입니다. mainline 은 그 브랜치의 최신인지 따로 확인하세요."
else
  m="지원 종료(EOL) 브랜치 Nginx $(br "$VER").x 입니다. nginx.org 는 stable($LATEST_SHOW)과 최신 mainline 브랜치에만 보안 수정을 냅니다."
  if [ "$PKG_TYPE" = "source" ]; then risk "$m stable 브랜치($LATEST_SHOW)로 교체가 필요합니다."
  else warn "$m 배포판 패키지는 배포판이 보안 수정을 따로 백포트할 수 있으니 [2]의 changelog 표시와 배포판 보안 공지를 확인하세요."; fi
fi

# 빌드에 포함된 모듈 (판단 참고용)
MODS="$(printf '%s\n' "$VFULL" | grep -oE -- '--with-[a-z0-9_]+(=dynamic)?' | sed 's/^--with-//' | tr '\n' ' ')"
info "빌드 옵션(--with-*): $(printf '%s' "$MODS" | wc -w | tr -d ' ')개"
[ -n "$MODS" ] && detail "$MODS"

# 실제로 읽는 설정 전체 수집: nginx -T (include 포함). 실패하면 설정 파일의 include 를 직접 따라감
# 결과: $ALLCONF  한 줄 = 파일:줄번호:내용(주석 제거),  $BODY = 내용만
ALLCONF="$WORK/allconf.txt"; BODY="$WORK/body.txt"; : > "$ALLCONF"
if ng -T > "$WORK/dump.txt" 2> "$WORK/dump.err" && grep -q '^# configuration file ' "$WORK/dump.txt"; then
  CONF_METHOD="nginx -T"
  awk '/^# configuration file .*:$/ { f=$0; sub(/^# configuration file /,"",f); sub(/:$/,"",f); n=0; next }
       f != "" { n++; l=$0; sub(/[ \t]*#.*$/,"",l); if (l ~ /[^ \t]/) print f ":" n ":" l }' "$WORK/dump.txt" > "$ALLCONF"
else
  CONF_METHOD="include 직접 추적 (nginx -T 실패: $(head -n1 "$WORK/dump.err" 2>/dev/null | cut -c1-120))"
  cat_conf() {   # $1 파일, $2 깊이
    local f="$1" d="$2" inc g base
    [ "$d" -gt 10 ] || [ ! -r "$f" ] && return
    awk -v f="$f" '{ l=$0; sub(/[ \t]*#.*$/,"",l); if (l ~ /[^ \t]/) print f ":" NR ":" l }' "$f"
    base="$(dirname "$NGINX_CONF_EFF")"
    sed -n 's/^[ \t]*include[ \t]\+\([^;]*\);.*/\1/p' "$f" | while read -r inc; do
      [[ "$inc" != /* ]] && inc="$base/$inc"
      # shellcheck disable=SC2086
      for g in $inc; do [ -f "$g" ] && cat_conf "$g" $((d+1)); done
    done
  }
  cat_conf "$NGINX_CONF_EFF" 0 > "$ALLCONF"
fi
# 한 줄에 여러 지시어를 적은 설정(예: server { listen 80; location / { proxy_pass ...; } })도 읽도록
# ; { } 뒤에서 나눠 지시어마다 한 줄로 (파일:줄번호는 그대로 유지)
awk '{ if (match($0, /^[^:]*:[0-9]+:/)) { pre = substr($0, 1, RLENGTH); c = substr($0, RLENGTH + 1)
         gsub(/[;{}]/, "&\n", c); n = split(c, a, "\n")
         for (i = 1; i <= n; i++) { t = a[i]; sub(/^[ \t]+/, "", t); if (t != "") print pre t } } }' "$ALLCONF" > "$WORK/allconf2.txt"
mv "$WORK/allconf2.txt" "$ALLCONF"
sed 's/^[^:]*:[0-9]*://' "$ALLCONF" > "$BODY"
CONF_FILES="$(cut -d: -f1 "$ALLCONF" | awk '!s[$0]++')"
if [ -s "$ALLCONF" ]; then
  info "점검한 설정 파일: $(printf '%s\n' "$CONF_FILES" | grep -c .)개 (확인 방법: $CONF_METHOD)"
  printf '%s\n' "$CONF_FILES" | head -n 20 | while read -r f; do detail "$f"; done
else
  warn "메인 설정 파일을 읽지 못했습니다: $NGINX_CONF_EFF  (설정 기반 점검을 건너뜁니다)"
fi
cfg() { grep -E "$1" "$ALLCONF"; }      # 파일:줄:내용 으로 보여 줄 때
has() { grep -qE "$1" "$BODY"; }        # 설정에 있는지만

# 실행 계정: 워커 프로세스의 계정 (마스터는 보통 root)
RUN_USER=""
if [ -n "${PRECHECK_PID:-}" ]; then
  RUN_USER="$(ps -o user= --ppid "$PRECHECK_PID" 2>/dev/null | sort | uniq -c | sort -rn | awk 'NR==1{print $2}')"
fi
if [ -z "$RUN_USER" ]; then
  RUN_USER="$(sed -n 's/^[ \t]*user[ \t]\+\([^ \t;]*\).*/\1/p' "$BODY" | head -n1)"
  [ -z "$RUN_USER" ] && id nobody >/dev/null 2>&1 && RUN_USER="nobody"
fi
# 마스터 프로세스 계정: 보통 root(포트를 연 뒤 워커만 user 계정으로 낮춤). web 처럼 일반 계정으로 직접 기동하기도 함
MASTER_USER=""
[ -n "${PRECHECK_PID:-}" ] && MASTER_USER="$(ps -o user= -p "$PRECHECK_PID" 2>/dev/null | tr -d ' ')"
info "실행 계정: ${RUN_USER:-확인 불가} (워커 프로세스)${MASTER_USER:+ · 마스터 프로세스: $MASTER_USER}"

# 설정에서 쓰는 기능 (CVE 해당 판정용). 이름은 CVE 목록의 "필요 기능" 칸과 같음
has_feat() {
  case "$1" in
    core) return 0 ;;
    windows) return 1 ;;
    ssl) has '^[ \t]*(ssl_certificate[ \t]|listen[ \t].*[ \t]ssl([ \t;]|$))' ;;
    http2) has '^[ \t]*(listen[ \t].*[ \t]http2([ \t;]|$)|http2[ \t]+on)' ;;
    http3) has '^[ \t]*(listen[ \t].*[ \t]quic([ \t;]|$)|http3[ \t]+on)' ;;
    spdy) has '^[ \t]*listen[ \t].*[ \t]spdy([ \t;]|$)' ;;
    mp4) has '^[ \t]*mp4[ \t]*;' ;;
    slice) has '^[ \t]*slice[ \t]' ;;
    ssi) has '^[ \t]*ssi[ \t]+on' ;;
    dav) has '^[ \t]*dav_methods[ \t]' ;;
    charset) has '^[ \t]*(charset|source_charset)[ \t]' ;;
    scgi) has '^[ \t]*(scgi_pass|uwsgi_pass)[ \t]' ;;
    mail) has '^[ \t]*mail[ \t]*\{' ;;
    stream_ocsp) has '^[ \t]*stream[ \t]*\{' && has '^[ \t]*ssl_ocsp[ \t]+(on|leaf)' ;;
    ocsp) has '^[ \t]*(ssl_stapling[ \t]+on|ssl_ocsp[ \t]+(on|leaf))' ;;
    resolver) has '^[ \t]*resolver[ \t]' ;;
    alias) has '^[ \t]*alias[ \t]' && has '^[ \t]*rewrite[ \t]' ;;
    map) has '^[ \t]*map[ \t]' ;;
    rewrite) has '^[ \t]*(rewrite|return|set|if)([ \t(]|$)' ;;
    aio) has '^[ \t]*aio[ \t]+(on|threads)' ;;
    proxy_ssl) has '(proxy_pass[ \t]+https://|^[ \t]*proxy_ssl_)' ;;
    proxy) has '^[ \t]*proxy_pass[ \t]' ;;
    grpc) has '(^[ \t]*grpc_pass[ \t]|proxy_http_version[ \t]+2)' ;;
    *) return 0 ;;
  esac
}
feat_label() {
  case "$1" in
    core) echo "공통" ;; windows) echo "Windows 전용" ;; ssl) echo "SSL/TLS 사용" ;;
    http2) echo "HTTP/2 사용" ;; http3) echo "HTTP/3·QUIC 사용" ;; spdy) echo "SPDY 사용" ;;
    mp4) echo "mp4 모듈 사용" ;; slice) echo "slice 모듈 사용" ;; ssi) echo "SSI 사용" ;;
    dav) echo "WebDAV 사용" ;; charset) echo "charset 사용" ;; scgi) echo "scgi·uwsgi 사용" ;;
    mail) echo "mail 프록시 사용" ;; stream_ocsp) echo "stream OCSP 사용" ;; ocsp) echo "OCSP 사용" ;;
    resolver) echo "resolver 사용" ;; alias) echo "alias와 rewrite 사용" ;; map) echo "map 사용" ;;
    rewrite) echo "rewrite·return·if 사용" ;; aio) echo "aio 사용" ;; proxy_ssl) echo "HTTPS 백엔드 프록시" ;;
    proxy) echo "proxy_pass 사용" ;; grpc) echo "gRPC·HTTP2 백엔드 프록시" ;; *) echo "$1" ;;
  esac
}
# 영향 구간(;로 구분, a-b 또는 한 버전)에 드는가
in_ranges() {
  local v="$1" r a b R
  IFS=';' read -ra R <<< "$2"
  for r in "${R[@]}"; do
    a="${r%%-*}"; b="${r##*-}"
    ver_le "$a" "$v" && ver_le "$v" "$b" && return 0
  done
  return 1
}
# 수정 버전(예: 1.31.7+;1.30.6+): 같은 브랜치의 수정 버전 이상이거나, 가장 높은 수정 버전 이상이면 수정됨
fixed_by() {
  local v="$1" g G top
  IFS=';' read -ra G <<< "$2"
  top="$(printf '%s\n' "${G[@]%+}" | grep -E '^[0-9]' | sort -V | tail -n1)"
  for g in "${G[@]}"; do
    g="${g%+}"; [ -z "$g" ] && continue
    ver_le "$g" "$v" || continue
    { [ "$(br "$g")" = "$(br "$v")" ] || [ "$g" = "$top" ]; } && return 0
  done
  return 1
}

# =====================================================================
section "[2] 버전별 해당 CVE 판정 (nginx.org 보안 공지 기준)"
# =====================================================================
# 형식: CVE|등급(nginx 원문 major/medium/minor/low)|필요 기능|영향 구간|수정 버전|제목
CVE_DB="$WORK/cve.txt"
cat > "$CVE_DB" <<'EOF'
# --- CVE_DB 시작 (nginx.org 보안 공지, tools/gen_nginx_cve.py 로 생성) ---
CVE-2026-15176|medium|alias|0.1.29-1.31.6|1.31.7+;1.30.6+|Buffer overflow when using alias with rewrite
CVE-2026-93479|medium|core|1.31.2-1.31.6;1.30.0-1.30.5|1.31.7+;1.30.6+|Buffer overflow in script evaluation
CVE-2026-95101|medium|http3|1.25.0-1.31.6|1.31.7+;1.30.6+|Request body injection in HTTP/3
CVE-2026-97629|medium|ssl|1.23.2-1.31.6|1.31.7+;1.30.6+|Session forgery when using TLS session tickets
CVE-2026-97205|medium|aio|0.8.11-1.31.6|1.31.7+;1.30.6+|Use-after-free when using asynchronous file I/O (AIO)
CVE-2026-90439|medium|http3|1.29.2-1.31.5|1.31.6+;1.30.5+|Buffer overflow when using ngx_http_v3_module
CVE-2026-42533|major|map|0.9.6-1.31.2|1.31.3+;1.30.4+|Buffer overflow when using map and regex
CVE-2026-60005|medium|slice|1.15.8-1.31.2|1.31.3+;1.30.4+|Memory disclosure when using ngx_http_slice_module
CVE-2026-56434|medium|ssi|0.8.11-1.31.2|1.31.3+;1.30.4+|Use-after-free when using ngx_http_ssi_module
CVE-2026-42530|major|http3|1.31.0-1.31.1|1.31.2+|Use-after-free in HTTP/3
CVE-2026-42055|medium|grpc|1.13.10-1.31.1|1.31.2+;1.30.3+|Buffer overflow in the ngx_http_proxy_v2_module and ngx_http_grpc_module
CVE-2026-48142|low|charset|0.3.50-1.31.1|1.31.2+;1.30.3+|Buffer overread in the ngx_http_charset_module
CVE-2026-9256|medium|rewrite|0.1.17-1.31.0|1.31.1+;1.30.2+|Buffer overflow in the ngx_http_rewrite_module
CVE-2026-42926|medium|proxy|1.29.4-1.30.0|1.31.0+;1.30.1+|HTTP/2 request injection in the ngx_http_proxy_module
CVE-2026-42945|medium|rewrite|0.6.27-1.30.0|1.31.0+;1.30.1+|Buffer overflow in the ngx_http_rewrite_module
CVE-2026-42946|medium|scgi|0.8.42-1.30.0|1.31.0+;1.30.1+|Buffer overread in the ngx_http_scgi_module and ngx_http_uwsgi_module
CVE-2026-42934|low|charset|0.3.50-1.30.0|1.31.0+;1.30.1+|Buffer overread in the ngx_http_charset_module
CVE-2026-40460|medium|http3|1.25.0-1.30.0|1.31.0+;1.30.1+|HTTP/3 address spoofing
CVE-2026-40701|medium|ocsp|1.19.0-1.30.0|1.31.0+;1.30.1+|resolver use-after-free in OCSP
CVE-2026-27654|medium|dav|0.5.13-1.29.6|1.29.7+;1.28.3+|Buffer overflow in ngx_http_dav_module
CVE-2026-27784|medium|mp4|1.1.19-1.29.6|1.29.7+;1.28.3+|Buffer overflow in the ngx_http_mp4_module
CVE-2026-32647|medium|mp4|1.1.19-1.29.6|1.29.7+;1.28.3+|Buffer overflow in the ngx_http_mp4_module
CVE-2026-27651|low|mail|0.5.15-1.29.6|1.29.7+;1.28.3+|NULL pointer dereference while using CRAM-MD5 or APOP
CVE-2026-28753|medium|mail|0.6.27-1.29.6|1.29.7+;1.28.3+|Injection in auth_http and XCLIENT
CVE-2026-28755|medium|stream_ocsp|1.27.2-1.29.6|1.29.7+;1.28.3+|OCSP result bypass in stream
CVE-2026-1642|medium|proxy_ssl|1.3.0-1.29.4|1.29.5+;1.28.2+|SSL upstream injection
CVE-2025-53859|low|mail|0.7.22-1.29.0|1.29.1+|Buffer overread in the ngx_mail_smtp_module
CVE-2025-23419|medium|ssl|1.11.4-1.27.3|1.27.4+;1.26.3+|SSL session reuse vulnerability
CVE-2024-7347|low|mp4|1.5.13-1.27.0|1.27.1+;1.26.2+|Buffer overread in the ngx_http_mp4_module
CVE-2024-32760|medium|http3|1.25.0-1.25.5;1.26.0|1.27.0+;1.26.1+|Buffer overwrite in HTTP/3
CVE-2024-31079|medium|http3|1.25.0-1.25.5;1.26.0|1.27.0+;1.26.1+|Stack overflow and use-after-free in HTTP/3
CVE-2024-35200|medium|http3|1.25.0-1.25.5;1.26.0|1.27.0+;1.26.1+|NULL pointer dereference in HTTP/3
CVE-2024-34161|medium|http3|1.25.0-1.25.5;1.26.0|1.27.0+;1.26.1+|Memory disclosure in HTTP/3
CVE-2024-24989|major|http3|1.25.3|1.25.4+|NULL pointer dereference in HTTP/3
CVE-2024-24990|major|http3|1.25.0-1.25.3|1.25.4+|Use-after-free in HTTP/3
CVE-2022-41741|medium|mp4|1.1.3-1.23.1;1.0.7-1.0.15|1.23.2+;1.22.1+|Memory corruption in the ngx_http_mp4_module
CVE-2022-41742|medium|mp4|1.1.3-1.23.1;1.0.7-1.0.15|1.23.2+;1.22.1+|Memory disclosure in the ngx_http_mp4_module
CVE-2021-23017|medium|resolver|0.6.18-1.20.0|1.21.0+;1.20.1+|1-byte memory overwrite in resolver
CVE-2019-9511|medium|http2|1.9.5-1.17.2|1.17.3+;1.16.1+|Excessive CPU usage in HTTP/2 with small window updates
CVE-2019-9513|low|http2|1.9.5-1.17.2|1.17.3+;1.16.1+|Excessive CPU usage in HTTP/2 with priority changes
CVE-2019-9516|low|http2|1.9.5-1.17.2|1.17.3+;1.16.1+|Excessive memory usage in HTTP/2 with zero length headers
CVE-2018-16843|low|http2|1.9.5-1.15.5|1.15.6+;1.14.1+|Excessive memory usage in HTTP/2
CVE-2018-16844|low|http2|1.9.5-1.15.5|1.15.6+;1.14.1+|Excessive CPU usage in HTTP/2
CVE-2018-16845|medium|mp4|1.1.3-1.15.5;1.0.7-1.0.15|1.15.6+;1.14.1+|Memory disclosure in the ngx_http_mp4_module
CVE-2017-7529|medium|core|0.5.6-1.13.2|1.13.3+;1.12.1+|Integer overflow in the range filter
CVE-2016-4450|medium|core|1.3.9-1.11.0|1.11.1+;1.10.1+|NULL pointer dereference while writing client request body
CVE-2016-0742|medium|resolver|0.6.18-1.9.9|1.9.10+;1.8.1+|Invalid pointer dereference in resolver
CVE-2016-0746|medium|resolver|0.6.18-1.9.9|1.9.10+;1.8.1+|Use-after-free during CNAME response processing in resolver
CVE-2016-0747|medium|resolver|0.6.18-1.9.9|1.9.10+;1.8.1+|Insufficient limits of CNAME resolution in resolver
CVE-2014-3616|medium|ssl|0.5.6-1.7.4|1.7.5+;1.6.2+|SSL session reuse vulnerability
CVE-2014-3556|medium|mail|1.5.6-1.7.3|1.7.4+;1.6.1+|STARTTLS command injection
CVE-2014-0133|major|spdy|1.3.15-1.5.11|1.5.12+;1.4.7+|SPDY heap buffer overflow
CVE-2014-0088|major|spdy|1.5.10|1.5.11+|SPDY memory corruption
CVE-2013-4547|medium|core|0.8.41-1.5.6|1.5.7+;1.4.4+|Request line parsing vulnerability
CVE-2013-2070|medium|core|1.1.4-1.2.8;1.3.9-1.4.0|1.5.0+;1.4.1+;1.2.9+|Memory disclosure with specially crafted HTTP backend responses
CVE-2013-2028|major|core|1.3.9-1.4.0|1.5.0+;1.4.1+|Stack-based buffer overflow with specially crafted request
CVE-2011-4963|medium|windows|0.7.52-1.3.0|1.3.1+;1.2.1+|Vulnerabilities with Windows directory aliases
CVE-2012-2089|major|mp4|1.1.3-1.1.18;1.0.7-1.0.14|1.1.19+;1.0.15+|Buffer overflow in the ngx_http_mp4_module
CVE-2012-1180|major|core|0.1.0-1.1.16|1.1.17+;1.0.14+|Memory disclosure with specially crafted backend responses
CVE-2011-4315|medium|resolver|0.6.18-1.1.7|1.1.8+;1.0.10+|Buffer overflow in resolver
CVE-2010-2266|major|windows|0.7.52-0.8.40|0.8.41+;0.7.67+|Vulnerabilities with invalid UTF-8 sequence on Windows
CVE-2010-2263|major|windows|0.7.52-0.8.39|0.8.40+;0.7.66+|Vulnerabilities with Windows file default stream
CVE-2009-3555|major|core|0.1.0-0.8.22|0.8.23+;0.7.64+|The renegotiation vulnerability in SSL protocol
CVE-2009-3898|minor|core|0.1.0-0.8.16|0.8.17+;0.7.63+|Directory traversal vulnerability
CVE-2009-2629|major|core|0.1.0-0.8.14|0.8.15+;0.7.62+;0.6.39+;0.5.38+|Buffer underflow vulnerability
CVE-2009-3896|major|core|0.1.0-0.8.13|0.8.14+;0.7.62+;0.6.39+;0.5.38+|Null pointer dereference vulnerability
# --- CVE_DB 끝 ---
EOF
CVE_SRC="스크립트 내장본 (2026-11-10 기준, $(grep -c '^CVE-' "$CVE_DB" | tr -d ' ')건)"
if [ -n "${PRECHECK_CVE_DB:-}" ] && [ -r "$PRECHECK_CVE_DB" ]; then
  grep -E '^CVE-[0-9]{4}-[0-9]{4,7}\|(major|medium|minor|low)\|[a-z0-9_]+\|[0-9.;-]+\|[0-9.;+]*\|[^|]*$' "$PRECHECK_CVE_DB" > "$WORK/cve_ext.txt"
  if [ -s "$WORK/cve_ext.txt" ]; then
    mv "$WORK/cve_ext.txt" "$CVE_DB"
    GEN="$(sed -n 's/^# GENERATED=//p' "$PRECHECK_CVE_DB" | head -n1 | tr -cd '[:alnum:] :._-')"
    CVE_SRC="대시보드 자동 업데이트본 (생성 ${GEN:-?}, $(wc -l < "$CVE_DB" | tr -d ' ')건)"
  else
    warn "지정한 CVE 목록 파일($PRECHECK_CVE_DB)에 올바른 줄이 없어 스크립트 내장 목록을 사용합니다."
  fi
fi
info "CVE 목록 출처: $CVE_SRC"

N_APPLY=0; N_SKIP=0; N_BP=0
while IFS='|' read -r cve sev feat vuln good desc; do
  case "$cve" in CVE-*) ;; *) continue ;; esac
  in_ranges "$VER" "$vuln" || continue
  fixed_by "$VER" "$good" && continue
  case "$sev" in major) nsev=high ;; medium) nsev=moderate ;; *) nsev=low ;; esac
  label="$(feat_label "$feat")"
  if ! has_feat "$feat"; then
    N_SKIP=$((N_SKIP+1))
    printf '[미해당] %s (%s) - 필요 모듈(%s) 미사용\n' "$cve" "$nsev" "$label" >> "$REPORT"
    continue
  fi
  N_APPLY=$((N_APPLY+1))
  aff="$(printf '%s' "$vuln" | awk -F';' '{for(i=1;i<=NF;i++){r=$i; if (r !~ /-/) r=r "-" r; sub(/-/,"~",r); printf "%s%s", (i>1?" / ":""), r}}')"
  bp=""
  if [ "$PKG_TYPE" != "source" ] && grep -q "$cve" "$CHANGELOG"; then
    bp=" → 패키지 changelog에 수정 기록 있음(백포트 반영 추정)"; N_BP=$((N_BP+1))
  fi
  msg="$cve [$nsev] $desc (영향: $aff, 조건: $label)$bp"
  if [ -n "$bp" ]; then info "$msg"
  else
    case "$nsev" in
      high) risk "$msg" ;;
      moderate) warn "$msg" ;;
      *) info "$msg" ;;
    esac
  fi
done < "$CVE_DB"
log ""
log "  → 해당 CVE: ${N_APPLY}건 (그중 패키지 백포트 추정 ${N_BP}건) / 기능 미사용으로 미해당: ${N_SKIP}건 (미해당 목록은 리포트 파일에 기록)"
[ "$N_APPLY" -eq 0 ] && ok "이 스크립트의 CVE 목록 기준으로 해당하는 CVE 가 없습니다."

# =====================================================================
section "[3] 위험 설정 점검 (nginx 가 실제로 읽는 설정 전체)"
# =====================================================================
show() { while IFS= read -r line; do detail "$line"; done; }

# 실행 계정의 다른 프로세스를 "누가 띄웠는지"로 나눔 (부모 프로세스를 거슬러 올라가며 확인)
#   srv   : 서버 프로세스(PRECHECK_PID 또는 서버 프로그램)가 띄운 것 → 웹쉘·리버스쉘의 전형적인 모습
#   login : sshd/su/sudo/login 에서 시작해 터미널이 붙어 있는 것 → 사람이 그 계정으로 로그인한 세션
#   other : 그 밖 (부모가 이미 끝나 init 에 붙은 백그라운드 프로세스 등) → 출처 확인 필요
# 사용: split_user_procs 계정 '제외할 명령줄 정규식' '서버 프로그램 이름 정규식(ps comm)'
# 결과: $WORK/ps_srv, $WORK/ps_login, $WORK/ps_other (한 줄: PID PPID 터미널 실행시간 명령줄 ← 시작한 곳)
split_user_procs() {
  : > "$WORK/ps_srv"; : > "$WORK/ps_login"; : > "$WORK/ps_other"
  ps -u "$1" -o pid=,ppid=,tty=,etime=,args= 2>/dev/null | grep -vE "$2" | while read -r pid ppid tty etime args; do
    [ "$pid" = "$$" ] && continue
    case "$args" in *"ps -u"*|grep\ *|*"<defunct>"*) continue ;; esac   # 점검 명령 자신, 이미 끝난 좀비 프로세스는 제외
    kind=other; via=""; a="$ppid"; n=0
    while [ -n "$a" ] && [ "$a" -gt 1 ] 2>/dev/null && [ "$n" -lt 40 ]; do
      c="$(ps -o comm= -p "$a" 2>/dev/null)"
      if [ "$a" = "${PRECHECK_PID:-none}" ] || printf '%s' "$c" | grep -qxE "$3"; then kind=srv; via="$c($a)"; break; fi
      case "$c" in sshd|sshd-session|sshd-auth|su|sudo|login) kind=login; via="$c($a)"; break ;; esac
      a="$(ps -o ppid= -p "$a" 2>/dev/null | tr -d ' ')"; n=$((n+1))
    done
    # 로그인에서 시작했어도 터미널이 없으면(백그라운드로 떼어 둔 것) 확인 필요로 분류
    [ "$kind" = login ] && [ "$tty" = "?" ] && kind=other
    printf '%s %s %s %s %s  <- %s\n' "$pid" "$ppid" "$tty" "$etime" "$args" "${via:-시작한 곳 확인 불가(부모 종료)}" >> "$WORK/ps_$kind"
  done
}
# 위 결과를 리포트에 기록. $1 = 계정 설명(예: "WildFly 실행계정(was)"), $2 = 서버 이름(예: "WildFly")
report_user_procs() {
  local any=0
  if [ -s "$WORK/ps_srv" ]; then any=1
    risk "$1 으로 $2 프로세스가 띄운 다른 프로세스 (리버스쉘/웹쉘 의심)"; cut -c1-220 "$WORK/ps_srv" | show
  fi
  if [ -s "$WORK/ps_other" ]; then any=1
    warn "$1 으로 실행 중인 다른 프로세스 (백그라운드 실행 — 채굴기 등 출처 확인 필요)"; cut -c1-220 "$WORK/ps_other" | show
  fi
  if [ -s "$WORK/ps_login" ]; then any=1
    info "$1 으로 로그인한 터미널 세션 (관리자 작업인지 확인: last ${RUN_USER} / /var/log/secure)"; cut -c1-220 "$WORK/ps_login" | show
  fi
  [ "$any" -eq 0 ] && ok "$1 의 비정상 프로세스 없음"
}

# OS 로그인·권한 기록에서 침해 흔적 찾기.  사용: check_auth_log 실행계정
#   읽는 곳: /var/log/secure* (RHEL/Rocky) 또는 /var/log/auth.log* (Debian/Ubuntu) 중 최근 RECENT_DAYS 일 안에 바뀐 파일
#            (둘 다 없으면 journalctl 의 auth/authpriv 기록)
#   [위험] 같은 IP 에서 1시간 안에 로그인 실패 AUTH_FAIL_MIN 회 이상 → 그 IP 로 로그인 성공 (비밀번호 맞히기 공격 성공 의심)
#   [주의] 실패가 많았던 IP 에서 로그인 성공(1시간 안은 아님) / 실행 계정으로 SSH 직접 로그인 / 실행 계정의 sudo / 계정 생성·변경
#   [정보] su 로 실행 계정 전환 기록, 로그인 실패가 많은 IP 상위 5개
AUTH_FAIL_MIN=10
check_auth_log() {
  local u="$1" A="$WORK/auth.txt" files src n any=0
  : > "$A"
  # 오래된 파일부터 (secure-20261026 → secure, auth.log.2.gz → auth.log) 읽어야 시간 순서가 맞음
  files="$(find /var/log -maxdepth 1 -type f \( -name 'secure*' -o -name 'auth.log*' \) -mtime "-$RECENT_DAYS" -printf '%T@ %p\n' 2>/dev/null | sort -n | cut -d' ' -f2-)"
  if [ -n "$files" ]; then
    printf '%s\n' "$files" | while IFS= read -r f; do zcat -f -- "$f" 2>/dev/null; done > "$A"
    n="$(printf '%s\n' "$files" | wc -l)"
    src="$(printf '%s\n' "$files" | tail -n 1)$( [ "$n" -gt 1 ] && echo " 외 $((n-1))개")"
  elif command -v journalctl >/dev/null 2>&1; then
    journalctl -q --no-pager -o short --since "$(date -d "-$RECENT_DAYS days" +%F 2>/dev/null)" SYSLOG_FACILITY=4 SYSLOG_FACILITY=10 > "$A" 2>/dev/null
    src="journalctl (auth/authpriv)"
  fi
  if [ ! -s "$A" ]; then
    info "OS 로그인 기록(/var/log/secure, /var/log/auth.log, journal)을 읽지 못해 로그인 기록 점검을 건너뜁니다. (root 권한 필요)"
    return
  fi
  info "점검 대상 OS 로그인 기록 (최근 ${RECENT_DAYS}일): $src"

  # 한 번 훑으며: IP 별 로그인 실패(최근 AUTH_FAIL_MIN 개 시각 기억) / 로그인 성공을 실패 기록과 대조
  awk -v min="$AUTH_FAIL_MIN" -v u="$u" -v w="$WORK" '
    function ts(   m, c) {   # "Nov 10 10:15:22 ..." 또는 "2026-11-10T10:15:22..." → 초 (연도 없음, 비교용)
      if ($1 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T/)
        return ((substr($1,6,2)+0)*31 + substr($1,9,2))*86400 + substr($1,12,2)*3600 + substr($1,15,2)*60 + substr($1,18,2)
      m = index("JanFebMarAprMayJunJulAugSepOctNovDec", $1)
      if (!m || split($3, c, ":") < 3) return -1
      return (((m+2)/3)*31 + $2)*86400 + c[1]*3600 + c[2]*60 + c[3]
    }
    function ipof(   s) { if (match($0, / from [0-9a-fA-F.:]+ port /)) return substr($0, RSTART+6, RLENGTH-12); return "" }
    /sshd[^:]*: Failed / {
      ip = ipof(); if (ip == "") next
      t = ts(); k = cnt[ip]++ % min; r[ip, k] = t; next
    }
    /sshd[^:]*: Accepted / {
      ip = ipof(); usr = ""
      if (match($0, / for [^ ]+ from /)) usr = substr($0, RSTART+5, RLENGTH-11)
      line = substr($0, 1, 200)
      if (u != "" && usr == u) print line > (w "/auth_direct")
      if (ip != "" && (ip in cnt) && cnt[ip] >= min) {
        t = ts(); old = r[ip, cnt[ip] % min]   # 최근 min 개 실패 중 가장 오래된 것
        if (t >= 0 && old >= 0 && old <= t && t - old <= 3600)
          print line "  ← 직전 1시간 안에 이 IP 로그인 실패 " min "회 이상" > (w "/auth_brute")
        else
          print line "  ← 이 IP 로그인 실패 누적 " cnt[ip] "회" > (w "/auth_manyfail")
      }
    }
    END { for (ip in cnt) print cnt[ip], ip > (w "/auth_fails") }
  ' "$A"

  if [ -s "$WORK/auth_brute" ]; then any=1
    risk "로그인 실패가 몰린 직후 같은 IP 에서 로그인 성공 (비밀번호 맞히기 공격 성공 의심 → 해당 계정 비밀번호 변경·접속 기록 확인)"
    tail -n 10 "$WORK/auth_brute" | show
  fi
  if [ -s "$WORK/auth_manyfail" ]; then any=1
    warn "로그인 실패가 많았던 IP 에서 로그인 성공 (점프 서버처럼 여러 사람이 쓰는 IP 인지 확인)"
    tail -n 10 "$WORK/auth_manyfail" | show
  fi
  if [ -n "$u" ] && [ "$u" != "root" ]; then
    if [ -s "$WORK/auth_direct" ]; then any=1
      warn "실행계정($u)으로 SSH 직접 로그인한 기록 (서비스 계정은 보통 직접 로그인하지 않음 → 누가 접속했는지 확인)"
      tail -n 10 "$WORK/auth_direct" | show
    fi
    grep -E "sudo(\[[0-9]+\])?: +${u} : " "$A" | tail -n 10 > "$WORK/auth_sudo"
    if [ -s "$WORK/auth_sudo" ]; then any=1
      warn "실행계정($u)이 sudo 를 사용(시도)한 기록 (웹 실행 계정의 권한 상승 시도일 수 있음)"
      cut -c1-220 "$WORK/auth_sudo" | show
    fi
    grep -E "su(-l)?(\[[0-9]+\])?: .*session opened for user ${u}[( ]" "$A" | tail -n 5 > "$WORK/auth_su"
    if [ -s "$WORK/auth_su" ]; then
      info "su 로 실행계정($u)에 전환한 기록 (최근 5건, 관리자 작업인지 확인)"
      cut -c1-220 "$WORK/auth_su" | show
    fi
  fi
  grep -E "(useradd|userdel|usermod|groupadd|chpasswd)(\[[0-9]+\])?: |password changed for " "$A" | tail -n 10 > "$WORK/auth_acct"
  if [ -s "$WORK/auth_acct" ]; then any=1
    warn "계정 생성·변경·비밀번호 변경 기록 (최근 10건, 관리자 작업인지 확인 — 침입자가 뒷문 계정을 만들기도 함)"
    cut -c1-220 "$WORK/auth_acct" | show
  fi
  if [ -s "$WORK/auth_fails" ]; then
    info "로그인 실패가 많은 IP 상위 5개 (전체 $(awk '{s+=$1} END {print s}' "$WORK/auth_fails")회, 형식: 횟수 IP)"
    sort -rn "$WORK/auth_fails" | head -n 5 | show
  fi
  if [ "$any" -eq 0 ]; then ok "OS 로그인 기록에 로그인 공격 성공·실행계정 직접 로그인/sudo·계정 변경 흔적 없음"; fi
}

if [ -s "$ALLCONF" ]; then
# 3-1 버전 노출
if has '^[ \t]*server_tokens[ \t]+off'; then
  ok "server_tokens off (응답 헤더·오류 페이지에 버전 숨김)"
else
  warn "server_tokens 가 off 가 아님 (기본값 on) → 응답 헤더(Server)·오류 페이지에 Nginx 버전 노출. http 블록에 server_tokens off; 권장"
  cfg '^[^:]*:[0-9]+:[ \t]*server_tokens[ \t]' | head -n 5 | show
fi

# 3-2 디렉터리 목록
if has '^[ \t]*autoindex[ \t]+on'; then
  warn "autoindex on → 디렉터리 파일 목록이 웹에 노출됨. 필요한 위치가 아니면 제거"
  cfg ':[ \t]*autoindex[ \t]+on' | head -n 10 | show
else
  ok "디렉터리 목록(autoindex) 노출 설정 없음"
fi

# 3-3 TLS 프로토콜 / 암호
if has_feat ssl; then
  if has '^[ \t]*ssl_protocols[ \t].*SSLv[23]'; then
    risk "ssl_protocols 에 SSLv2/SSLv3 포함 → POODLE 등 알려진 공격에 취약. TLSv1.2 TLSv1.3 만 사용 권장"
    cfg ':[ \t]*ssl_protocols[ \t]' | show
  elif has '^[ \t]*ssl_protocols[ \t].*TLSv1(\.1)?([ \t;]|$)'; then
    warn "ssl_protocols 에 TLSv1.0/1.1 포함 → 더 이상 안전하지 않은 프로토콜. TLSv1.2 TLSv1.3 만 사용 권장"
    cfg ':[ \t]*ssl_protocols[ \t]' | show
  elif has '^[ \t]*ssl_protocols[ \t]'; then
    ok "ssl_protocols 에 구형 프로토콜(SSLv3·TLSv1.0·1.1) 없음"
  else
    info "ssl_protocols 를 지정하지 않아 버전별 기본값을 사용 중 → TLSv1.2 TLSv1.3 으로 명시 권장"
  fi
  if grep -E '^[ \t]*ssl_ciphers[ \t]' "$BODY" | grep -qE "(^|[ :'\"])(RC4|DES|3DES|NULL|EXPORT|EXP|MD5|aNULL|eNULL|ADH)(-|:|'|\"|;| |$)"; then
    warn "ssl_ciphers 에 약한 암호(RC4·DES·NULL·EXPORT·MD5 등)가 허용되어 있음 (앞에 ! 를 붙여 제외했는지 확인)"
    cfg ':[ \t]*ssl_ciphers[ \t]' | head -n 5 | show
  fi
else
  info "SSL/TLS 설정 없음 (HTTPS 를 앞단 장비에서 처리하는지 확인)"
fi

# 3-4 location 블록 분석: alias 경로 탐색, stub_status 노출, PHP 실행 위험
awk '
  function emit(i) {
    if ((L_mod[i] == "" || L_mod[i] == "^~") && L_alias[i] != "" && L_path[i] !~ /\/$/ && L_alias[i] ~ /\/$/)
      print "ALIAS\t" L_at[i] "\tlocation " L_path[i] " { alias " L_alias[i] "; }"
    if (L_stub[i] && !L_acl[i]) print "STUB\t" L_at[i] "\tlocation " L_path[i]
    if (L_mod[i] ~ /~/ && L_path[i] ~ /php/ && L_fcgi[i] && !L_try[i] && !L_split[i])
      print "PHP\t" L_at[i] "\tlocation " L_mod[i] " " L_path[i]
  }
  {
    at = $0; sub(/:[^:]*$/, "", at)                      # 파일:줄
    s = $0; sub(/^[^:]*:[0-9]+:/, "", s)
    if (match(s, /^[ \t]*location[ \t]+/)) {
      rest = substr(s, RSTART + RLENGTH); mod = ""
      if (match(rest, /^(=|~\*|~|\^~)/)) { mod = substr(rest, 1, RLENGTH); rest = substr(rest, RLENGTH + 1); sub(/^[ \t]+/, "", rest) }
      split(rest, a, /[ \t{]/)
      sp++; L_mod[sp] = mod; L_path[sp] = a[1]; L_at[sp] = at; L_depth[sp] = depth + 1
      L_alias[sp] = ""; L_stub[sp] = 0; L_acl[sp] = 0; L_fcgi[sp] = 0; L_try[sp] = 0; L_split[sp] = 0
    }
    if (sp > 0) {
      if (s ~ /^[ \t]*alias[ \t]/) { v = s; sub(/^[ \t]*alias[ \t]+/, "", v); sub(/[ \t]*;.*/, "", v); gsub(/["\047]/, "", v); L_alias[sp] = v }
      if (s ~ /^[ \t]*stub_status/) L_stub[sp] = 1
      if (s ~ /^[ \t]*(allow|deny|auth_basic|auth_request|satisfy)[ \t]/) L_acl[sp] = 1
      if (s ~ /^[ \t]*fastcgi_pass[ \t]/) L_fcgi[sp] = 1
      if (s ~ /^[ \t]*try_files[ \t].*=404/) L_try[sp] = 1
      if (s ~ /^[ \t]*fastcgi_split_path_info[ \t]/) L_split[sp] = 1
    }
    t = s; o = gsub(/\{/, "{", t); c = gsub(/\}/, "}", t); depth += o - c
    while (sp > 0 && depth < L_depth[sp]) { emit(sp); sp-- }
  }
  END { while (sp > 0) { emit(sp); sp-- } }' "$ALLCONF" > "$WORK/loc.txt"
if grep -q '^ALIAS' "$WORK/loc.txt"; then
  risk "alias 경로 탐색 위험: location 끝에 / 가 없는데 alias 끝에 / 가 있음 → /경로../ 요청으로 상위 폴더 파일 읽기 가능 (location 과 alias 끝의 / 를 맞출 것)"
  grep '^ALIAS' "$WORK/loc.txt" | cut -f2- | tr '\t' ' ' | head -n 10 | show
else
  ok "alias 경로 탐색(off-by-slash) 위험 설정 없음"
fi
if grep -q '^STUB' "$WORK/loc.txt"; then
  warn "stub_status(서버 상태 페이지)에 접근 제한(allow/deny)이 없음 → 상위 server 블록에서 제한하지 않았다면 외부에 연결 수 등 노출"
  grep '^STUB' "$WORK/loc.txt" | cut -f2- | tr '\t' ' ' | show
fi
if grep -q '^PHP' "$WORK/loc.txt"; then
  warn "PHP location 에 try_files ... =404 / fastcgi_split_path_info 가 없음 → 업로드한 이미지 등이 PHP 로 실행될 수 있음 (php.ini cgi.fix_pathinfo=0 이면 위험 낮음)"
  grep '^PHP' "$WORK/loc.txt" | cut -f2- | tr '\t' ' ' | show
fi

# 3-5 WebDAV 쓰기 메서드
if has '^[ \t]*dav_methods[ \t]+.*(PUT|DELETE|MKCOL|COPY|MOVE)'; then
  warn "WebDAV 쓰기 메서드(PUT/DELETE 등) 허용 → 인증·접근 제한이 없으면 파일 업로드(웹쉘) 통로"
  cfg ':[ \t]*dav_methods[ \t]' | show
fi

# 3-6 프록시 대상에 요청 값(Host 헤더 등)을 그대로 사용 → SSRF / 오픈 프록시
if has '^[ \t]*proxy_pass[ \t]+(https?://)?\$(host|http_host|arg_[a-z0-9_]+|uri|request_uri|http_[a-z0-9_]+)'; then
  warn "proxy_pass 대상에 요청 값(\$host·\$http_host·\$arg_ 등)을 그대로 사용 → 외부에서 임의 서버로 요청을 보내게 하는 SSRF·오픈 프록시 위험"
  cfg ':[ \t]*proxy_pass[ \t]+(https?://)?\$' | head -n 10 | show
fi

# 3-7 실행 계정
if [ "$RUN_USER" = "root" ]; then
  risk "워커 프로세스가 root 로 실행됨 → 취약점 악용 시 서버 전체 장악. user 지시어로 전용 계정(nginx·www-data 등) 사용"
elif [ -n "$RUN_USER" ]; then
  ok "워커 프로세스 실행 계정: $RUN_USER"
fi

# 3-8 설정·인증서 키 파일 권한
# 마스터가 root 인데 설정이 워커 계정 소유 → 워커 탈취 시 설정을 바꿔 root 마스터가 읽게 함(권한 상승 통로) = 위험
# 마스터·워커가 모두 같은 일반 계정(web 등)으로 기동 → 그 계정 소유는 이 구성에서 일반적, 권한 상승 통로 아님 = 정보
BADP=""; SAMEP=""
while read -r f; do
  [ -f "$f" ] || continue
  m="$(stat -c '%a %U' "$f" 2>/dev/null)"; perm="${m%% *}"; own="${m#* }"
  if [ $(( 8#$perm & 8#002 )) -ne 0 ]; then BADP="$BADP$f ($perm $own, 누구나 수정 가능)"$'\n'
  elif [ "$own" != "root" ] && [ -n "$RUN_USER" ] && [ "$own" = "$RUN_USER" ]; then
    if [ -n "$MASTER_USER" ] && [ "$MASTER_USER" = "$RUN_USER" ]; then SAMEP="$SAMEP$f ($perm $own)"$'\n'
    else BADP="$BADP$f ($perm $own, 웹 실행계정 소유${MASTER_USER:+ — 마스터는 $MASTER_USER})"$'\n'; fi
  fi
done <<< "$CONF_FILES"
if [ -n "$BADP" ]; then
  risk "설정 파일을 웹 실행계정이나 다른 사용자가 수정할 수 있음 → 설정 변조로 웹쉘·프록시 악용 가능(마스터가 root 면 권한 상승 통로). root 소유 + 644 권장"
  printf '%s' "$BADP" | show
  [ -z "$MASTER_USER" ] && detail "→ nginx 가 실행 중이 아니라 마스터 프로세스 계정을 확인하지 못했습니다. 일반 계정으로 직접 기동하는 구성이면 위험이 낮을 수 있습니다."
fi
if [ -n "$SAMEP" ]; then
  info "nginx 를 실행 계정($RUN_USER)으로 직접 기동하는 구성(마스터·워커 모두 $RUN_USER) — 설정 파일이 같은 계정 소유인 것은 이 구성에서 일반적이며 권한 상승 통로가 아닙니다. 다만 $RUN_USER 계정이 탈취되면 설정을 바꿔 트래픽 가로채기·프록시 악용이 가능하므로, 더 강화하려면 root 소유 644(읽기만 허용) + 설정 변경은 sudo 로"
  printf '%s' "$SAMEP" | show
fi
[ -z "$BADP" ] && [ -z "$SAMEP" ] && ok "설정 파일 권한 이상 없음 (누구나 수정 가능·웹 실행계정 소유 파일 없음)"
KEYS="$(sed -n 's/^[ \t]*ssl_certificate_key[ \t]\+\([^; \t]*\).*/\1/p' "$BODY" | tr -d "\"'" | sort -u)"
BADK=""
while read -r k; do
  [ -n "$k" ] && [ -f "$k" ] || continue
  perm="$(stat -c '%a' "$k" 2>/dev/null)"
  [ $(( 8#$perm & 8#004 )) -ne 0 ] && BADK="$BADK$k ($perm)"$'\n'
done <<< "$KEYS"
if [ -n "$BADK" ]; then
  warn "인증서 개인키 파일을 누구나 읽을 수 있음 → 키 유출 시 HTTPS 통신 가로채기 가능. 600(또는 640) 권장"
  printf '%s' "$BADK" | show
fi

# 3-9 열린 포트 (참고)
if [ -n "${PRECHECK_PID:-}" ] && command -v ss >/dev/null 2>&1; then
  LISTEN="$(ss -ltnpH 2>/dev/null | grep -E "pid=$PRECHECK_PID," | awk '{print $4}' | sort -u)"
  if [ -n "$LISTEN" ]; then info "이 Nginx 가 열어 둔 포트"; printf '%s\n' "$LISTEN" | show; fi
fi
fi

# =====================================================================
section "[4] 침해 흔적 점검 (이미 해킹당했는지)"
# =====================================================================
# 4-1 접근 로그 수집
LOGS="$WORK/logs.txt"; : > "$LOGS"
if [ -n "$LOG_PATHS" ]; then
  for p in $LOG_PATHS; do
    # shellcheck disable=SC2086
    ls -d -- $p 2>/dev/null
  done >> "$LOGS"
  info "접근 로그 경로를 -l 옵션 값으로 사용: $LOG_PATHS"
else
  # (a) 설정의 access_log (off·syslog 제외, $변수는 와일드카드로)
  sed -n 's/^[ \t]*access_log[ \t]\+\([^ \t;]*\).*/\1/p' "$BODY" | tr -d "\"'" | sort -u | while read -r p; do
    case "$p" in off|syslog:*|memory:*|'') continue ;; esac
    p="$(printf '%s' "$p" | sed 's/\$[A-Za-z_][A-Za-z0-9_]*/*/g')"
    [[ "$p" != /* ]] && p="${NGINX_PREFIX_EFF%/}/$p"
    # shellcheck disable=SC2086
    ls -d -- $p $p.* $p-* 2>/dev/null
  done >> "$LOGS"
  # (b) 이 인스턴스(마스터 + 워커)가 실제로 열고 있는 로그 파일 (다른 nginx 인스턴스의 로그는 섞지 않음)
  if [ -n "${PRECHECK_PID:-}" ]; then IPIDS="$PRECHECK_PID $(ps -o pid= --ppid "$PRECHECK_PID" 2>/dev/null | tr '\n' ' ')"
  else IPIDS="$(pgrep -x nginx 2>/dev/null | tr '\n' ' ')"; fi
  for pid in $IPIDS; do
    for fd in /proc/"$pid"/fd/*; do readlink "$fd" 2>/dev/null; done
  done | grep -E '^/' | grep -iE 'log' | grep -vE '^/(dev|proc)/|\(deleted\)$' | sort -u | while read -r f; do
    [ -f "$f" ] || continue
    case "$(basename "$f")" in *error*) continue ;; esac
    echo "$f"
    # 같은 이름으로 회전된 파일(access.log.1, access.log.2.gz)
    ls -d -- "$f".* "$f"-* 2>/dev/null
  done >> "$LOGS"
  # (c) 위에서 못 찾았을 때만 기본 경로
  if ! grep -q . "$LOGS"; then
    for d in /var/log/nginx /usr/local/nginx/logs /opt/nginx/logs; do
      [ -d "$d" ] && find "$d" -type f -name '*access*' 2>/dev/null
    done >> "$LOGS"
  fi
fi
sort -u "$LOGS" | while read -r f; do
  [ -f "$f" ] || continue
  [[ "$f" == "$WORK"* || "$f" == "$REPORT" ]] && continue
  case "$(basename "$f")" in *error*|*.pid) continue ;; esac
  echo "$f"
done > "$WORK/logs2.txt"
mv "$WORK/logs2.txt" "$LOGS"

if [ ! -s "$LOGS" ]; then
  warn "접근 로그 파일을 찾지 못했습니다. 로그 기반 점검을 건너뜁니다."
  detail "→ 로그 위치 확인 후 -l 옵션(에이전트는 설정 파일의 NGINX_LOG_PATHS)으로 지정하세요. 예: sudo bash $0 -l '/logs/nginx/access*'"
else
  info "점검 대상 접근 로그: $(wc -l < "$LOGS")개 (회전된 .gz 포함)"
  head -n 10 "$LOGS" | show
  zg() { while read -r f; do zgrep -hE "$1" "$f" 2>/dev/null; done < "$LOGS"; }

  zg '(\.%2e|%2e\.|%2e%2e|%252e|\.\./|\.\.%2f|%c0%ae)' > "$WORK/trav.txt"
  T_ALL=$(wc -l < "$WORK/trav.txt"); T_200=$(grep -cE '" 200 ' "$WORK/trav.txt")
  if [ "$T_200" -gt 0 ]; then
    risk "경로 탐색 시도 중 200(성공) 응답 ${T_200}건 → 침해 가능성. 즉시 상세 분석 필요"
    grep -E '" 200 ' "$WORK/trav.txt" | head -n 5 | show
  elif [ "$T_ALL" -gt 0 ]; then warn "경로 탐색 시도 ${T_ALL}건 (성공 응답 없음) → 스캔 대상이 되고 있음"
  else ok "경로 탐색 시도 흔적 없음"; fi

  zg '(cmd=|exec=|shell=|passthru|system\(|base64_decode|/bin/(ba)?sh|wget(%20|\+)|curl(%20|\+)|whoami|/etc/passwd|uname(%20|\+)-a|\$\{jndi:|%24%7Bjndi)' > "$WORK/shell.txt"
  S_200=$(grep -cE '" 200 ' "$WORK/shell.txt")
  if [ "$S_200" -gt 0 ]; then
    risk "명령실행/웹쉘/JNDI 주입 의심 요청 중 200 응답 ${S_200}건"
    grep -E '" 200 ' "$WORK/shell.txt" | head -n 5 | show
  elif [ -s "$WORK/shell.txt" ]; then warn "명령실행/웹쉘/JNDI 주입 의심 요청 $(wc -l < "$WORK/shell.txt")건 (성공 응답 없음)"
  else ok "명령실행/웹쉘/JNDI 주입 의심 요청 흔적 없음"; fi

  cat "$WORK/trav.txt" "$WORK/shell.txt" | awk '{print $1}' | sort | uniq -c | sort -rn | head -n 5 > "$WORK/topip.txt"
  [ -s "$WORK/topip.txt" ] && { info "의심 요청 상위 IP (차단 검토용)"; show < "$WORK/topip.txt"; }
fi

# 4-2 웹 루트(root·alias) 수집 → 웹쉘 의심 파일
ROOTS="$WORK/roots.txt"
# 설정의 root·alias 값 (따옴표·끝 공백 제거)
sed -n 's/^[ \t]*\(root\|alias\)[ \t]\+\([^;]*\);.*/\2/p' "$BODY" | tr -d "\"'" | sed 's/[ \t]*$//' > "$WORK/rootdirs.txt"
N_ROOTDIR=$(grep -c . "$WORK/rootdirs.txt")
N_VARROOT=$(grep -c '\$' "$WORK/rootdirs.txt")
{ cat "$WORK/rootdirs.txt"
  # root 를 한 번도 지정하지 않으면 nginx 기본값 "root html;" (설치 폴더 기준) 을 씀
  grep -qE '^[ \t]*root[ \t]' "$BODY" || echo "html"; } | while read -r d; do
  case "$d" in *'$'*) continue ;; esac
  [[ "$d" != /* ]] && d="${NGINX_PREFIX_EFF%/}/$d"
  [ -d "$d" ] && echo "${d%/}"
done | sort -u > "$ROOTS"
# 요청을 뒤쪽 서버로 넘기기만 하는 설정인가 (root·alias 없이 proxy_pass 등만 있음)
PROXY_ONLY=0
if [ "$N_ROOTDIR" -eq 0 ] && has '^[ \t]*(proxy_pass|fastcgi_pass|uwsgi_pass|scgi_pass|grpc_pass)[ \t]'; then PROXY_ONLY=1; fi
if [ ! -s "$ROOTS" ] && [ "$PROXY_ONLY" -eq 1 ]; then
  info "프록시 전용 서버 — root·alias 설정 없이 요청을 뒤쪽 서버로 넘기기만 하므로 이 서버에는 웹 파일 점검 대상이 없습니다. (웹쉘 점검은 뒤쪽 WAS 서버 결과에서 확인)"
  cfg ':[ \t]*(proxy_pass|fastcgi_pass|uwsgi_pass|scgi_pass|grpc_pass)[ \t]' | head -n 5 | show
elif [ ! -s "$ROOTS" ] && [ "$N_ROOTDIR" -gt 0 ] && [ "$N_VARROOT" -eq "$N_ROOTDIR" ]; then
  warn "웹 루트(root·alias) 폴더를 찾지 못했습니다. 파일 기반 점검을 건너뜁니다. (경로가 모두 \$변수라 실제 폴더를 알 수 없음)"
  head -n 5 "$WORK/rootdirs.txt" | show
elif [ ! -s "$ROOTS" ]; then
  warn "웹 루트(root·alias) 폴더를 찾지 못했습니다. 파일 기반 점검을 건너뜁니다."
  [ -s "$WORK/rootdirs.txt" ] && { detail "→ 설정에는 있으나 실제로 없는(또는 읽을 수 없는) 폴더:"; head -n 5 "$WORK/rootdirs.txt" | show; }
else
  info "점검 대상 웹 루트: $(tr '\n' ' ' < "$ROOTS")"
  : > "$WORK/ws.txt"
  while read -r d; do
    find "$d" -xdev -type f \( -name '*.php' -o -name '*.php[0-9]' -o -name '*.phtml' -o -name '*.jsp' -o -name '*.jspx' -o -name '*.asp' -o -name '*.aspx' -o -name '*.cgi' -o -name '*.pl' -o -name '*.py' -o -name '*.sh' \) -print0 2>/dev/null | \
      xargs -0 -r grep -lE 'eval\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)|assert\s*\(\s*\$_(POST|GET|REQUEST)|(shell_exec|passthru|proc_open|popen)\s*\(|system\s*\(\s*\$_|Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder|WScript\.Shell' 2>/dev/null >> "$WORK/ws.txt"
  done < "$ROOTS"
  if [ -s "$WORK/ws.txt" ]; then
    risk "웹쉘 의심 코드 패턴 포함 파일 $(wc -l < "$WORK/ws.txt")개 (오탐 가능, 내용 확인 필수)"
    head -n 20 "$WORK/ws.txt" | show
  else
    ok "웹쉘 의심 코드 패턴 파일 없음 (패턴 우회형 웹쉘은 탐지 못함 → KISA 휘슬 병행 권장)"
  fi
  : > "$WORK/recent.txt"
  while read -r d; do
    find "$d" -xdev -type f \( -name '*.php' -o -name '*.php[0-9]' -o -name '*.phtml' -o -name '*.jsp' -o -name '*.cgi' -o -name '*.pl' -o -name '*.py' -o -name '*.sh' \) -mtime "-$RECENT_DAYS" 2>/dev/null >> "$WORK/recent.txt"
  done < "$ROOTS"
  if [ -s "$WORK/recent.txt" ]; then
    warn "최근 ${RECENT_DAYS}일 내 변경된 스크립트 파일 $(wc -l < "$WORK/recent.txt")개 → 배포 이력과 대조 필요"
    head -n 20 "$WORK/recent.txt" | while read -r f; do detail "$(ls -l --time-style=+%F_%T "$f" 2>/dev/null)"; done
  else
    ok "최근 ${RECENT_DAYS}일 내 변경된 스크립트 파일 없음"
  fi
  if [ -n "$RUN_USER" ] && [ "$RUN_USER" != "root" ] && id "$RUN_USER" >/dev/null 2>&1; then
    W=$(while read -r d; do find "$d" -xdev -user "$RUN_USER" 2>/dev/null; done < "$ROOTS" | wc -l)
    if [ "$W" -gt 0 ]; then warn "웹 루트 내 웹 실행계정($RUN_USER) 소유 파일/디렉터리 ${W}개 → 업로드 경로 외에는 소유권 회수 검토"
    else ok "웹 루트 내 웹 실행계정 소유 파일 없음"; fi
  fi
fi

# 4-3 웹 실행계정의 의심 프로세스 / 크론 / 임시파일 / 외부 연결
if [ -n "$RUN_USER" ] && [ "$RUN_USER" != "root" ] && id "$RUN_USER" >/dev/null 2>&1; then
  # 누가 띄웠는지로 나눔: Nginx(또는 php-fpm)가 띄운 것 = 위험, 사람의 로그인 터미널 = 정보, 그 밖 = 주의
  split_user_procs "$RUN_USER" 'nginx|php-fpm' 'nginx|php-fpm.*'
  report_user_procs "웹 실행계정($RUN_USER)" "Nginx"

  CR="$(crontab -l -u "$RUN_USER" 2>/dev/null | grep -vE '^\s*(#|$)')"
  if [ -n "$CR" ]; then risk "웹 실행계정($RUN_USER)에 크론 작업 등록됨 (지속성 확보 의심)"; printf '%s\n' "$CR" | show
  else ok "웹 실행계정 크론 작업 없음"; fi

  TMPF="$(find /tmp /var/tmp /dev/shm -xdev -user "$RUN_USER" -type f 2>/dev/null | head -n 20)"
  if [ -n "$TMPF" ]; then warn "임시 디렉터리에 웹 실행계정 소유 파일 존재 → 실행파일/스크립트 여부 확인"; printf '%s\n' "$TMPF" | show
  else ok "임시 디렉터리에 웹 실행계정 소유 파일 없음"; fi

  if command -v ss >/dev/null 2>&1; then
    PIDS="$(pgrep -u "$RUN_USER" | paste -sd'|' -)"
    if [ -n "$PIDS" ]; then
      CONN="$(ss -tnpH state established 2>/dev/null | grep -E "pid=($PIDS)," | awk '{print $3" -> "$4}' | sort | uniq -c | sort -rn | head -n 15)"
      if [ -n "$CONN" ]; then
        info "웹 실행계정 프로세스의 연결 목록 (프록시 백엔드 외의 외부 IP가 있으면 의심)"
        printf '%s\n' "$CONN" | show
      fi
    fi
  fi
elif [ "$RUN_USER" = "root" ]; then
  info "실행 계정이 root 라 계정 기준 의심 프로세스/크론 점검은 생략합니다. (전용 계정으로 바꾸면 점검 가능)"
fi

# 4-5 OS 로그인 기록 (/var/log/secure 등): 로그인 공격 성공, 웹 실행 계정의 직접 로그인·sudo, 계정 생성
check_auth_log "$RUN_USER"

# =====================================================================
section "점검 요약"
# =====================================================================
log "  [위험] ${CNT_RISK}건   [주의] ${CNT_WARN}건   [양호] ${CNT_OK}건   [정보] ${CNT_INFO}건"
log ""
log "  ※ 이 결과는 '알려진 패턴' 기준이며 안전을 보증하지 않습니다."
log "    - [위험] 중 침해 흔적(로그 200 응답, 웹쉘, 비정상 프로세스)이 있으면 설정 보완보다 침해사고 대응이 우선입니다."
log "    - CVE 판정은 nginx.org 보안 공지의 버전 기준이며, 패키지 설치본은 배포판 보안 공지로 최종 확인하세요."
log "    - 근본 대책은 stable 최신($LATEST_SHOW) 이상(또는 보안수정이 반영된 배포판 패키지)으로의 업그레이드입니다."
log ""
log "  리포트 파일: $REPORT"
