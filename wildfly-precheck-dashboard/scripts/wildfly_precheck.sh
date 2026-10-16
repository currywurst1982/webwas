#!/usr/bin/env bash
# =====================================================================
#  wildfly_precheck.sh
#  WildFly 서버 - 패치 전 보안 사전 점검 스크립트 (기준: 공식 최신 Final 41.0.1.Final)
#
#  - 읽기 전용: 설정 변경/파일 삭제/서비스 재시작을 하지 않습니다.
#  - 점검 항목
#      [1] 버전 / 설치 방식 / 주요 구성요소(jar) 버전 확인
#      [2] 구성요소 버전별 해당 CVE 판정
#          (WildFly 설치 폴더 modules/ 안의 실제 jar 버전을 OSV 취약점 DB 의 영향 구간과 비교)
#      [3] 위험 설정 점검 (관리 콘솔 노출·인증, 쉬운 관리자 비밀번호, 원격 디버그, 파일 권한 등)
#      [4] 침해 흔적 점검 (접근 로그, 배포된 앱 안의 웹쉘 의심 JSP, server.log, 의심 프로세스/연결/크론)
#  - 결과: 화면 출력 + 리포트 파일(/tmp/wildfly_precheck_<호스트>_<시각>[_pid<PID>].txt)
#
#  CVE 데이터 출처: OSV (https://osv.dev) Maven 데이터
#                   https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip
#                   (2026-10-16 내려받음, GitHub Advisory Database 등급 사용)
#                   tools/gen_cve_table.py 로 아래 CVE_DB 블록을 다시 만들 수 있습니다.
#  최신 버전 기준: https://www.wildfly.org/downloads/ 의 최신 Final = 41.0.1.Final
#
#  사용법:  ./wildfly_precheck.sh            ← 옵션 없이 실행 (권장)
#    - 실행 중인 WildFly(java ... jboss-modules.jar) 프로세스를 자동으로 찾아
#      설치 폴더(jboss.home.dir)·서버 폴더(jboss.server.base.dir)·설정 파일(-c)을 따라갑니다.
#    - 인스턴스가 여러 개면 각각 점검하고 리포트를 따로 만듭니다.
#    - root 가 아니면 sudo 로 자동 재실행합니다(비밀번호를 물을 수 있음).
#  선택 옵션: [-H WildFly설치폴더] [-d 일수] [-l '로그경로']
#    -H : WildFly 설치 폴더(JBOSS_HOME) 직접 지정 (WildFly 가 꺼져 있어 자동 탐지가 안 될 때)
#    -d : "최근 변경 파일" 점검 기간(일). 기본 30
#    -l : 접근 로그 경로 직접 지정 (와일드카드 가능, 반드시 작은따옴표로 감쌀 것)
#         예: -l '/logs/wildfly/access_log*'
# =====================================================================

LATEST_FINAL="41.0.1.Final"
JBOSS_HOME_ARG=""
RECENT_DAYS=30
LOG_PATHS=""
ORIG_ARGS=("$@")
while getopts "H:d:l:h" opt; do
  case "$opt" in
    H) JBOSS_HOME_ARG="$OPTARG" ;;
    d) RECENT_DAYS="$OPTARG" ;;
    l) LOG_PATHS="$OPTARG" ;;
    h) sed -n '2,/^# =\{10,\}$/p' "$0"; exit 0 ;;
    *) echo "알 수 없는 옵션입니다. -h 로 사용법을 확인하세요."; exit 1 ;;
  esac
done

SELF="$(readlink -f "$0")"

# --- root 가 아니면 sudo 로 자동 재실행 ----------------------------------
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && [ -z "${PRECHECK_NO_SUDO:-}" ]; then
  echo "[안내] root 권한이 필요해 sudo 로 다시 실행합니다. (비밀번호를 물으면 입력하세요)"
  if sudo -v 2>/dev/null; then
    exec sudo PRECHECK_NO_SUDO=1 bash "$SELF" "${ORIG_ARGS[@]}"
  fi
  echo "[안내] sudo 권한을 얻지 못해 현재 계정 권한으로 계속합니다. (결과가 불완전할 수 있음)"
fi

# --- 실행 중인 WildFly 인스턴스 자동 탐지 --------------------------------
# java 명령줄에 jboss-modules.jar 가 있고, standalone 서버 또는 도메인 호스트 컨트롤러인 프로세스만.
# (도메인 모드의 process-controller 와 각 서버 프로세스는 같은 설치를 공유하므로 제외)
# 출력: PID (한 줄에 하나)
detect_instances() {
  local pid cl
  for pid in $(ps -eo pid=,args= 2>/dev/null | awk '/jboss-modules\.jar/ && !/awk/ {print $1}'); do
    cl="$(tr '\0' ' ' < /proc/"$pid"/cmdline 2>/dev/null)"
    case "$cl" in
      *org.jboss.as.standalone*|*org.jboss.as.host-controller*) echo "$pid" ;;
    esac
  done
}

if [ -z "$JBOSS_HOME_ARG" ] && [ -z "${PRECHECK_PID:-}" ]; then
  INSTANCES="$(detect_instances)"
  N_INST=0; [ -n "$INSTANCES" ] && N_INST="$(printf '%s\n' "$INSTANCES" | wc -l)"
  if [ "$N_INST" -gt 1 ]; then
    echo "[안내] 실행 중인 WildFly 인스턴스 ${N_INST}개를 찾았습니다. 각각 점검합니다."
    i=0
    while read -r pid; do
      i=$((i+1))
      echo ""; echo "################ 인스턴스 ${i}/${N_INST} (PID ${pid}) ################"
      PASS=(-d "$RECENT_DAYS")
      [ -n "$LOG_PATHS" ] && PASS+=(-l "$LOG_PATHS")
      PRECHECK_NO_SUDO=1 PRECHECK_PID="$pid" bash "$SELF" "${PASS[@]}" </dev/null
    done <<< "$INSTANCES"
    echo ""; echo "[안내] 전체 인스턴스 점검 완료. 리포트 파일 목록:"
    ls -1t /tmp/wildfly_precheck_*_pid*.txt 2>/dev/null | head -n "$N_INST" | sed 's/^/       /'
    exit 0
  elif [ "$N_INST" -eq 1 ]; then
    PRECHECK_PID="$INSTANCES"
  fi
fi

TS="$(date +%Y%m%d_%H%M%S)"
REPORT="/tmp/wildfly_precheck_$(hostname -s 2>/dev/null || echo host)_${TS}${PRECHECK_PID:+_pid$PRECHECK_PID}.txt"
WORK="$(mktemp -d /tmp/wildfly_precheck.XXXXXX)"
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
show()    { while IFS= read -r line; do detail "$line"; done; }

# Maven 식 버전 비교: vcmp a b → -1 / 0 / 1
#   숫자 부분(최대 5자리) → 수식어 순위(Alpha<Beta<CR<SNAPSHOT<Final=GA<SP) → 수식어 번호
vcmp() {
  awk -v a="$1" -v b="$2" '
  function parse(v, out,   t, n, i, k, q, qn) {
    v = tolower(v); gsub(/-/, ".", v)
    n = split(v, t, ".")
    k = 0; q = ""; qn = 0
    for (i = 1; i <= n; i++) {
      if (q == "" && t[i] ~ /^[0-9]+$/) { if (k < 5) out[++k] = t[i] + 0; continue }
      if (q == "") { q = t[i]; if (match(q, /[0-9]+$/)) { qn = substr(q, RSTART) + 0; q = substr(q, 1, RSTART - 1) } continue }
      if (t[i] ~ /^[0-9]+$/ && qn == 0) qn = t[i] + 0
    }
    for (i = k + 1; i <= 5; i++) out[i] = 0
    if (q == "" || q ~ /^(final|ga|release)$/) out[6] = 6
    else if (q ~ /^(alpha|a)$/) out[6] = 1
    else if (q ~ /^(beta|b)$/) out[6] = 2
    else if (q ~ /^(milestone|m)$/) out[6] = 3
    else if (q ~ /^(cr|rc)$/) out[6] = 4
    else if (q ~ /^snapshot$/) out[6] = 5
    else if (q ~ /^sp$/) out[6] = 7
    else out[6] = 6
    out[7] = qn
  }
  BEGIN {
    parse(a, x); parse(b, y)
    for (i = 1; i <= 7; i++) { if (x[i] < y[i]) { print -1; exit } if (x[i] > y[i]) { print 1; exit } }
    print 0
  }'
}
vlt() { [ "$(vcmp "$1" "$2")" = "-1" ]; }   # a < b
vle() { [ "$(vcmp "$1" "$2")" != "1" ]; }   # a <= b

# 서버 IP (루프백·링크로컬 제외, IPv4 우선). 대시보드에서 서버를 알아보기 쉽게 표시하는 용도
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

: > "$REPORT"
log "WildFly 패치 전 보안 사전 점검  |  호스트: $(hostname)  |  일시: $(date '+%F %T')"

if [ "$(id -u)" -ne 0 ]; then
  warn "root 권한이 아닙니다(sudo 없음). 로그/설정/프로세스 정보를 못 읽어 결과가 불완전할 수 있습니다."
fi

# =====================================================================
section "[1] 버전 및 설치 방식 확인"
# =====================================================================
# --- 프로세스 명령줄에서 설치 폴더·서버 폴더·설정 파일·바인드 주소 읽기 -----
CMDLINE="$WORK/cmdline.txt"; : > "$CMDLINE"
MODE="standalone"
if [ -n "${PRECHECK_PID:-}" ] && [ -r /proc/"$PRECHECK_PID"/cmdline ]; then
  tr '\0' '\n' < /proc/"$PRECHECK_PID"/cmdline > "$CMDLINE"
  grep -qx 'org.jboss.as.host-controller' "$CMDLINE" && MODE="domain"
  info "실행 중인 WildFly 프로세스 자동 탐지: PID $PRECHECK_PID"
fi
# -Dprop=value 값 읽기 (명령줄에 없으면 빈 값)
sysprop() { grep -E "^-D$1=" "$CMDLINE" | tail -n1 | cut -d= -f2-; }
# standalone.sh 인자(-b, -bmanagement, -c) 읽기: "-b 0.0.0.0" / "-b=0.0.0.0" / "-b0.0.0.0" 모두 처리
cliarg() {
  awk -v o="$1" '
    want {print; want=0; next}
    $0 == o {want=1; next}
    index($0, o "=") == 1 {print substr($0, length(o) + 2); next}
    o == "-b" && $0 ~ /^-b[0-9]/ {print substr($0, 3)}' "$CMDLINE" | tail -n1
}

JBOSS_HOME="${JBOSS_HOME_ARG:-$(sysprop jboss.home.dir)}"
if [ -z "$JBOSS_HOME" ] && [ -n "${PRECHECK_PID:-}" ]; then
  JBOSS_HOME="$(grep -E 'jboss-modules\.jar$' "$CMDLINE" | head -n1 | xargs -r dirname 2>/dev/null)"
fi
if [ -z "$JBOSS_HOME" ]; then
  warn "실행 중인 WildFly 프로세스를 찾지 못해 흔한 설치 경로에서 찾습니다. (WildFly 가 꺼져 있을 수 있음)"
  for c in /opt/wildfly /opt/wildfly/current /usr/share/wildfly /usr/local/wildfly /opt/jboss/wildfly /srv/wildfly; do
    if [ -f "$c/jboss-modules.jar" ]; then JBOSS_HOME="$c"; break; fi
  done
  [ -z "$JBOSS_HOME" ] && JBOSS_HOME="$(ls -d /opt/wildfly-* /usr/local/wildfly-* 2>/dev/null | sort -V | tail -n1)"
fi
JBOSS_HOME="${JBOSS_HOME%/}"
if [ -z "$JBOSS_HOME" ] || [ ! -f "$JBOSS_HOME/jboss-modules.jar" ]; then
  risk "WildFly 설치 폴더를 찾지 못했습니다. WildFly 를 기동한 상태에서 다시 실행하거나 -H 로 경로를 지정하세요. (예: -H /opt/wildfly)"
  exit 1
fi

if [ "$MODE" = "domain" ]; then
  BASE_DIR="$(sysprop jboss.domain.base.dir)"; BASE_DIR="${BASE_DIR:-$JBOSS_HOME/domain}"
  CONF_NAME="$(sysprop jboss.domain.default.config)"; CONF_NAME="${CONF_NAME:-$(cliarg -c)}"; CONF_NAME="${CONF_NAME:-domain.xml}"
else
  BASE_DIR="$(sysprop jboss.server.base.dir)"; BASE_DIR="${BASE_DIR:-$JBOSS_HOME/standalone}"
  CONF_NAME="$(cliarg -c)"; [ -z "$CONF_NAME" ] && CONF_NAME="$(cliarg --server-config)"
  CONF_NAME="${CONF_NAME:-$(sysprop jboss.server.default.config)}"; CONF_NAME="${CONF_NAME:-standalone.xml}"
fi
CONF_DIR="$(sysprop jboss.server.config.dir)"; [ "$MODE" = "domain" ] && CONF_DIR="$(sysprop jboss.domain.config.dir)"
CONF_DIR="${CONF_DIR:-$BASE_DIR/configuration}"
case "$CONF_NAME" in /*) CONFIG="$CONF_NAME" ;; *) CONFIG="$CONF_DIR/$CONF_NAME" ;; esac
LOG_DIR="$(sysprop jboss.server.log.dir)"; LOG_DIR="${LOG_DIR:-$BASE_DIR/log}"

# 인스턴스 구분: 기본값과 다른 서버 폴더·설정 파일만 표시 (같은 설치로 여러 인스턴스를 띄운 경우 구분용)
INST_ID=""
[ "$BASE_DIR" != "$JBOSS_HOME/standalone" ] && [ "$BASE_DIR" != "$JBOSS_HOME/domain" ] && INST_ID="base=$BASE_DIR"
[ "$CONF_NAME" != "standalone.xml" ] && [ "$CONF_NAME" != "domain.xml" ] && INST_ID="${INST_ID:+$INST_ID }config=$CONF_NAME"
[ -n "$INST_ID" ] && info "인스턴스 구분: $INST_ID"

SERVER_IPS="$(server_ips)"
info "서버 IP: ${SERVER_IPS:-확인 불가}"
info "설치 폴더: $JBOSS_HOME"
info "실행 모드: $MODE"
info "메인 설정 파일: $CONFIG"

# --- 버전: version.txt → 제품 정보(MANIFEST/product-conf jar) → wildfly-undertow jar 순서로 확인 -----
VER_LINE=""; WF_VER=""
if [ -f "$JBOSS_HOME/version.txt" ]; then
  VER_LINE="$(head -n1 "$JBOSS_HOME/version.txt")"
  WF_VER="$(printf '%s' "$VER_LINE" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[A-Za-z]+[0-9]*' | head -n1)"
fi
PROD_DIR="$JBOSS_HOME/modules/system/layers/base/org/jboss/as/product/main"
if [ -z "$WF_VER" ] && [ -f "$PROD_DIR/dir/META-INF/MANIFEST.MF" ]; then
  WF_VER="$(sed -n 's/^JBoss-Product-Release-Version: *//p' "$PROD_DIR/dir/META-INF/MANIFEST.MF" | tr -d '\r')"
  VER_LINE="$(sed -n 's/^JBoss-Product-Release-Name: *//p' "$PROD_DIR/dir/META-INF/MANIFEST.MF" | tr -d '\r') $WF_VER"
fi
if [ -z "$WF_VER" ]; then
  WF_VER="$(ls "$PROD_DIR"/wildfly-feature-pack-product-conf-*.jar 2>/dev/null | head -n1 | sed -E 's/.*product-conf-(.*)\.jar$/\1/')"
  [ -n "$WF_VER" ] && VER_LINE="WildFly $WF_VER"
fi
if [ -z "$WF_VER" ]; then
  WF_VER="$(find "$JBOSS_HOME/modules" -name 'wildfly-undertow-[0-9]*.jar' 2>/dev/null | sed -E 's/.*wildfly-undertow-(.*)\.jar$/\1/' | sort -V | tail -n1)"
  [ -n "$WF_VER" ] && VER_LINE="WildFly $WF_VER (wildfly-undertow jar 기준)"
fi
case "$VER_LINE" in *WildFly*|*JBoss*) ;; *) VER_LINE="WildFly ${WF_VER} (${VER_LINE:-버전 파일 없음})" ;; esac
info "버전 정보: ${VER_LINE}"

if [ -z "$WF_VER" ]; then
  risk "버전을 해석하지 못했습니다. 수동 확인이 필요합니다."
  exit 1
fi
if ! printf '%s' "$WF_VER" | grep -qiE '\.Final$'; then
  warn "WildFly $WF_VER 은(는) 정식(Final) 릴리스가 아닙니다. (Alpha/Beta/CR 은 운영 사용 비권장)"
fi
if vle "$LATEST_FINAL" "$WF_VER"; then
  ok "WildFly $WF_VER : 최신 Final($LATEST_FINAL) 이상입니다."
else
  warn "WildFly $WF_VER : 최신 Final($LATEST_FINAL) 미만입니다. 아래 [2]에서 해당 CVE를 확인하세요."
fi
# WildFly 26 이하는 javax(Java EE 8) 계열 → 27 이상(jakarta)으로 올릴 때 애플리케이션 패키지명 변경이 필요
if [ -d "$JBOSS_HOME/modules/system/layers/base/javax/servlet/api" ] && [ ! -d "$JBOSS_HOME/modules/system/layers/base/jakarta/servlet/api" ]; then
  info "Java EE 8(javax) 계열 WildFly 입니다. 최신 버전(jakarta 계열)으로 올릴 때 애플리케이션의 javax → jakarta 변경이 필요합니다."
fi

# 설치 방식
if command -v rpm >/dev/null 2>&1 && rpm -qf "$JBOSS_HOME/jboss-modules.jar" >/dev/null 2>&1; then
  info "설치 방식: RPM 패키지 ($(rpm -qf "$JBOSS_HOME/jboss-modules.jar"))"
elif command -v dpkg >/dev/null 2>&1 && dpkg -S "$JBOSS_HOME/jboss-modules.jar" >/dev/null 2>&1; then
  info "설치 방식: DEB 패키지 ($(dpkg -S "$JBOSS_HOME/jboss-modules.jar" 2>/dev/null | cut -d: -f1 | head -n1))"
elif [ -d "$JBOSS_HOME/.galleon" ] && [ ! -f "$JBOSS_HOME/README.txt" ]; then
  info "설치 방식: Galleon 프로비저닝 (필요한 기능만 골라 만든 설치)"
else
  info "설치 방식: ZIP 배포본 (공식 압축 파일을 푼 설치)"
fi
if [ -d "$JBOSS_HOME/modules/system/layers/base/.overlays" ]; then
  info "패치 오버레이(.overlays) 폴더가 있습니다. 구성요소 버전은 오버레이를 포함해 가장 높은 버전을 기준으로 판정합니다."
fi

# Java
JAVA_BIN=""
[ -n "${PRECHECK_PID:-}" ] && JAVA_BIN="$(readlink /proc/"$PRECHECK_PID"/exe 2>/dev/null)"
[ -z "$JAVA_BIN" ] && JAVA_BIN="$(command -v java 2>/dev/null)"
if [ -n "$JAVA_BIN" ]; then
  info "Java: $("$JAVA_BIN" -version 2>&1 | grep -v JAVA_TOOL_OPTIONS | head -n1) ($JAVA_BIN)"
fi

# 구성요소(jar) 버전 목록: 이름|버전 (같은 이름이 여러 버전이면 가장 높은 버전)
JARS="$WORK/jars.txt"
find "$JBOSS_HOME/modules" -type f -name '*.jar' 2>/dev/null | awk '
  { f = $0; sub(/.*\//, "", f) }
  match(f, /-[0-9]/) { n = substr(f, 1, RSTART - 1); v = substr(f, RSTART + 1); sub(/\.jar$/, "", v); sub(/-resources$/, "", v); print n "|" v "|" $0 }' |
  sort -t'|' -k1,1 -k2,2V | awk -F'|' '{last[$1]=$0} END {for (k in last) print last[k]}' | sort > "$JARS"
printf 'WILDFLY|%s|\n' "$WF_VER" >> "$JARS"
comp_ver() { awk -F'|' -v n="$1" '$1==n {print $2; exit}' "$JARS"; }
# jar 안 pom.properties 의 groupId (못 읽으면 빈 값 → 같은 프로젝트로 간주)
comp_group() {
  local jar; jar="$(awk -F'|' -v n="$1" '$1==n {print $3; exit}' "$JARS")"
  [ -n "$jar" ] || return
  if command -v unzip >/dev/null 2>&1; then
    unzip -p "$jar" 'META-INF/maven/*/pom.properties' 2>/dev/null | sed -n 's/^groupId=//p' | tr -d '\r' | head -n1
  elif command -v python3 >/dev/null 2>&1; then
    python3 -I -c 'import sys,zipfile
try:
    z = zipfile.ZipFile(sys.argv[1])
    for n in z.namelist():
        if n.startswith("META-INF/maven/") and n.endswith("pom.properties"):
            for l in z.read(n).decode("utf-8", "replace").splitlines():
                if l.startswith("groupId="): print(l[8:].strip()); sys.exit(0)
except Exception: pass' "$jar"
  fi
}
info "구성요소(jar) 수: $(($(wc -l < "$JARS") - 1))"
for c in undertow-core wildfly-server wildfly-elytron-base resteasy-core jboss-remoting xnio-api hal-console; do
  v="$(comp_ver "$c")"; [ -n "$v" ] && detail "$c $v"
done

# =====================================================================
section "[2] 구성요소 버전별 해당 CVE 판정 (OSV 기준)"
# =====================================================================
# 형식: CVE|권고ID|등급|구성요소|groupId|시작버전|수정버전|마지막영향버전|설명
#   수정버전이 있으면  시작 <= 버전 < 수정  이면 해당
#   마지막영향버전이 있으면  시작 <= 버전 <= 마지막  이면 해당
#   둘 다 비어 있으면  시작 <= 버전  이면 해당 (OSV 에 수정 버전이 아직 없음)
CVE_DB="$WORK/cve.txt"
cat > "$CVE_DB" <<'EOF'
# --- CVE_DB 시작 (tools/gen_cve_table.py 로 생성) ---
CVE-2015-3198|GHSA-4vwv-x3gp-2j4g|high|WILDFLY||8.1.0.Final|9.0.0.CR2||The Undertow module of WildFly allows source code disclosure
CVE-2016-0793|GHSA-9q87-22gr-r8qf|high|WILDFLY||0|10.0.0.Final||WildFly has incomplete blacklist vulnerability
CVE-2020-10740|GHSA-vrmw-2xhq-hrmp|high|WILDFLY||0|20.0.0.Final||Wildfly Unsafe Deserialization Vulnerability
CVE-2020-1719|GHSA-p9cf-qjxq-vxw6|moderate|WILDFLY||0|20.0.0.Final||Privilege Context Switching Error in wildlfy
CVE-2020-25640|GHSA-jw3v-5ch2-wfmm|moderate|WILDFLY||0|21.0.0.Final||Wildfly logs plaintext passwords
CVE-2020-25689|GHSA-97hp-6q9g-5cw2|moderate|WILDFLY||0|21.0.1||Uncontrolled Resource Consumption in WildFly
CVE-2020-27822|GHSA-qx3p-9mmp-4v8h|moderate|WILDFLY||19.0.0.Final|21.0.2.Final||Wildfly has a memory leak vulnerability
CVE-2020-27822|GHSA-qx3p-9mmp-4v8h|moderate|WILDFLY||22.0.0.Alpha1|22.0.0.Beta1||Wildfly has a memory leak vulnerability
CVE-2021-3536|GHSA-v2wx-jj66-2hp7|low|WILDFLY||0|23.0.2.Final||Cross-site Scripting in Wildfly
CVE-2022-1278|GHSA-fmq7-gh8v-mjvc|high|WILDFLY||0|27.0.0.Beta1||WildFly vulnerable to Insecure Default Initialization of Resource
CVE-2024-4029|GHSA-x7g6-rwhc-g7mj|moderate|WILDFLY||0||24.0.0.Final|Wildfly vulnerable to denial of service
CVE-2025-23366|GHSA-jhvj-f397-8w6q|moderate|hal-console|org.jboss.hal|0|3.7.7.Final||HAL Console has a Cross Site Scripting (XSS) vulnerability of user input
CVE-2025-2901|GHSA-f7jh-m6wp-jm7f|moderate|hal-console|org.jboss.hal|0|3.7.11.Final||HAL Cross Site Scripting (XSS) vulnerability of user input when storing it in a data store
CVE-2020-14297|GHSA-qcch-9268-59jw|moderate|jboss-ejb-client|org.jboss|0|4.0.34.Final||Wildfly EJB Client causes DoS
CVE-2021-20250|GHSA-2259-h742-5vr4|moderate|jboss-ejb-client|org.jboss|0|4.0.39||JBoss EJB Client information disclosure vulnerability
CVE-2020-35510|GHSA-p6j8-hgv5-m35g|high|jboss-remoting|org.jboss.remoting|0|5.0.20.Final||Uncontrolled Resource Consumption in jboss-remoting
CVE-2012-0818|GHSA-wrrh-g7h3-gqmx|moderate|resteasy-client|org.jboss.resteasy|0|2.3.1||Exposure of Sensitive Information to an Unauthorized Actor in RESTEasy
CVE-2014-3490|GHSA-qjpq-5pq3-43rr|high|resteasy-client|org.jboss.resteasy|2.3.1|2.3.8.SP2||Incorrect Privilege Assignment in RESTEasy
CVE-2014-3490|GHSA-qjpq-5pq3-43rr|high|resteasy-client|org.jboss.resteasy|3.0.0|3.0.9.Final||Incorrect Privilege Assignment in RESTEasy
CVE-2016-6345|GHSA-vxhj-3x7p-jxp5|moderate|resteasy-client|org.jboss.resteasy|0|3.0.20.Final||Exposure of Sensitive Information to an Unauthorized Actor in RESTEasy
CVE-2016-6345|GHSA-vxhj-3x7p-jxp5|moderate|resteasy-client|org.jboss.resteasy|3.1.0.Beta1|3.1.0.CR1||Exposure of Sensitive Information to an Unauthorized Actor in RESTEasy
CVE-2016-6347|GHSA-r346-rmrg-qpgh|moderate|resteasy-client|org.jboss.resteasy|0|3.0.20.Final||Improper Neutralization of Input During Web Page Generation in RESTEasy
CVE-2016-6347|GHSA-r346-rmrg-qpgh|moderate|resteasy-client|org.jboss.resteasy|3.1.0.Beta1|3.1.0.CR1||Improper Neutralization of Input During Web Page Generation in RESTEasy
CVE-2016-6348|GHSA-9xfc-j5mf-9w5p|moderate|resteasy-client|org.jboss.resteasy|0|3.0.20.Final||JacksonJsonpInterceptor susceptible to cross-site script inclusion (XSSI) attack
CVE-2020-1695|GHSA-63cq-ppq8-cw6g|high|resteasy-client|org.jboss.resteasy|3.0.0|3.12.0||Improper Input Validation in RESTEasy
CVE-2020-1695|GHSA-63cq-ppq8-cw6g|high|resteasy-client|org.jboss.resteasy|4.0.0|4.6.0||Improper Input Validation in RESTEasy
CVE-2020-25633|GHSA-hr32-mgpm-qf2f|moderate|resteasy-client|org.jboss.resteasy|0|3.14.0.Final||Generation of Error Message Containing Sensitive Information in RESTEasy client
CVE-2020-25633|GHSA-hr32-mgpm-qf2f|moderate|resteasy-client|org.jboss.resteasy|4.0.0|4.5.7.Final||Generation of Error Message Containing Sensitive Information in RESTEasy client
CVE-2020-10688|GHSA-29qj-rvv6-qrmv|moderate|resteasy-core|org.jboss.resteasy|0|3.11.1.Final||Cross-site scripting in RESTEasy
CVE-2020-10688|GHSA-29qj-rvv6-qrmv|moderate|resteasy-core|org.jboss.resteasy|4.0.0|4.5.3.Final||Cross-site scripting in RESTEasy
CVE-2021-20289|GHSA-244r-fcj3-ghjq|moderate|resteasy-core|org.jboss.resteasy|3.0.0|3.16.0||Exposure of class information in RESTEasy
CVE-2021-20289|GHSA-244r-fcj3-ghjq|moderate|resteasy-core|org.jboss.resteasy|4.0.0|4.5.10||Exposure of class information in RESTEasy
CVE-2021-20289|GHSA-244r-fcj3-ghjq|moderate|resteasy-core|org.jboss.resteasy|4.6.0|4.6.1||Exposure of class information in RESTEasy
CVE-2021-20293|GHSA-5h26-c766-g93v|high|resteasy-core|org.jboss.resteasy|0||4.6.0.Final|Cross-Site Scripting
CVE-2023-0482|GHSA-2c6g-pfx3-w7h8|moderate|resteasy-core|org.jboss.resteasy|0|3.15.5.Final||Insecure Temporary File in RESTEasy
CVE-2023-0482|GHSA-2c6g-pfx3-w7h8|moderate|resteasy-core|org.jboss.resteasy|4.0.0.Beta1|4.7.8.Final||Insecure Temporary File in RESTEasy
CVE-2023-0482|GHSA-2c6g-pfx3-w7h8|moderate|resteasy-core|org.jboss.resteasy|5.0.0.Alpha1|5.0.6.Final||Insecure Temporary File in RESTEasy
CVE-2023-0482|GHSA-2c6g-pfx3-w7h8|moderate|resteasy-core|org.jboss.resteasy|6.0.0.Beta1|6.2.3.Final||Insecure Temporary File in RESTEasy
CVE-2014-7839|GHSA-pc54-pchm-xcw6|moderate|resteasy-jaxrs|org.jboss.resteasy|0|3.0.11.Final||XML External Entity Reference in RESTEasy
CVE-2016-6346|GHSA-wxvr-vqfp-9cqw|high|resteasy-jaxrs|org.jboss.resteasy|0|3.0.20.Final||Denial of service in JBoss resteasy
CVE-2017-7561|GHSA-57q5-x8jf-g7h8|high|resteasy-jaxrs|org.jboss.resteasy|3.0.7.Final|3.0.25.Final||Inconsistent Interpretation of HTTP Requests in Red Hat JBoss EAP
CVE-2017-7561|GHSA-57q5-x8jf-g7h8|high|resteasy-jaxrs|org.jboss.resteasy|3.1.4.Final|3.5.0.CR1||Inconsistent Interpretation of HTTP Requests in Red Hat JBoss EAP
CVE-2023-0482|GHSA-2c6g-pfx3-w7h8|moderate|resteasy-multipart-provider|org.jboss.resteasy|0|3.15.5.Final||Insecure Temporary File in RESTEasy
CVE-2023-0482|GHSA-2c6g-pfx3-w7h8|moderate|resteasy-multipart-provider|org.jboss.resteasy|4.0.0.Beta1|4.7.8.Final||Insecure Temporary File in RESTEasy
CVE-2023-0482|GHSA-2c6g-pfx3-w7h8|moderate|resteasy-multipart-provider|org.jboss.resteasy|5.0.0.Alpha1|5.0.6.Final||Insecure Temporary File in RESTEasy
CVE-2023-0482|GHSA-2c6g-pfx3-w7h8|moderate|resteasy-multipart-provider|org.jboss.resteasy|6.0.0.Beta1|6.2.3.Final||Insecure Temporary File in RESTEasy
CVE-2014-7816|GHSA-h6p6-fc4w-cqhx|moderate|undertow-core|io.undertow|1.0.0|1.0.17||Improper Limitation of a Pathname to a Restricted Directory in JBoss Undertow
CVE-2014-7816|GHSA-h6p6-fc4w-cqhx|moderate|undertow-core|io.undertow|1.1.0.Beta1|1.1.0.CR5||Improper Limitation of a Pathname to a Restricted Directory in JBoss Undertow
CVE-2014-7816|GHSA-h6p6-fc4w-cqhx|moderate|undertow-core|io.undertow|1.2.0.Beta1|1.2.0.Beta3||Improper Limitation of a Pathname to a Restricted Directory in JBoss Undertow
CVE-2016-7046|GHSA-3f57-w2rp-72fc|moderate|undertow-core|io.undertow|0|1.3.25.Final||Undertow Uncaught Exception vulnerability
CVE-2016-7046|GHSA-3f57-w2rp-72fc|moderate|undertow-core|io.undertow|1.4.0|1.4.3.Final||Undertow Uncaught Exception vulnerability
CVE-2017-12165|GHSA-5gg7-5wv8-4gcj|high|undertow-core|io.undertow|0|1.3.31||Undertow Request Smuggling vulnerability
CVE-2017-12165|GHSA-5gg7-5wv8-4gcj|high|undertow-core|io.undertow|1.4.0|1.4.17||Undertow Request Smuggling vulnerability
CVE-2017-12165|GHSA-5gg7-5wv8-4gcj|high|undertow-core|io.undertow|2.0.0.Alpha1|2.0.0.Beta1||Undertow Request Smuggling vulnerability
CVE-2017-12196|GHSA-cp7v-vmv7-6x2q|moderate|undertow-core|io.undertow|0|1.4.24.Final||Incorrect Authorization in Undertow
CVE-2017-12196|GHSA-cp7v-vmv7-6x2q|moderate|undertow-core|io.undertow|2.0.0.Alpha1|2.0.2.FInal||Incorrect Authorization in Undertow
CVE-2017-2666|GHSA-mcfm-h73v-635m|moderate|undertow-core|io.undertow|0|1.3.31||Undertow-core vulnerable to HTTP Request Smuggling
CVE-2017-2666|GHSA-mcfm-h73v-635m|moderate|undertow-core|io.undertow|1.4.0|1.4.17||Undertow-core vulnerable to HTTP Request Smuggling
CVE-2017-2670|GHSA-3x7h-5hfr-hvjm|moderate|undertow-core|io.undertow|0|1.3.28||Moderate severity vulnerability that affects io.undertow:undertow-core
CVE-2017-7559|GHSA-rj76-h87p-r3wf|moderate|undertow-core|io.undertow|1.3.0|1.3.31.Final||Undertow vulnerable to Request Smuggling
CVE-2017-7559|GHSA-rj76-h87p-r3wf|moderate|undertow-core|io.undertow|1.4.0|1.4.17.Final||Undertow vulnerable to Request Smuggling
CVE-2017-7559|GHSA-rj76-h87p-r3wf|moderate|undertow-core|io.undertow|2.0.0.Alpha1|2.0.0.Alpha2||Undertow vulnerable to Request Smuggling
CVE-2018-1114|GHSA-gjjx-gqm4-wcgm|moderate|undertow-core|io.undertow|0|1.4.25.Final||Uncontrolled Resource Consumption in Undertow
CVE-2018-1114|GHSA-gjjx-gqm4-wcgm|moderate|undertow-core|io.undertow|2.0.0.Alpha1|2.0.5.Final||Uncontrolled Resource Consumption in Undertow
CVE-2018-14642|GHSA-vf6r-mmhc-3xcm|moderate|undertow-core|io.undertow|0|2.0.19.FINAL||Exposure of Sensitive Information to an Unauthorized Actor in Undertow
CVE-2019-10212|GHSA-8vh8-vc28-m2hf|critical|undertow-core|io.undertow|0|2.0.20||Potential to access user credentials from the log files when debug logging enabled
CVE-2019-14888|GHSA-vjxc-frw4-jmh5|high|undertow-core|io.undertow|0|2.0.29.Final||Undertow vulnerable to Uncontrolled Resource Consumption
CVE-2019-3888|GHSA-jwgx-9mmh-684w|critical|undertow-core|io.undertow|0|2.0.21||Credential exposure through log files in Undertow
CVE-2020-10687|GHSA-p9w3-gwc2-cr49|moderate|undertow-core|io.undertow|0|2.2.0.Final||HTTP Request Smuggling in Undertow
CVE-2020-10705|GHSA-g4cp-h53p-v3v8|high|undertow-core|io.undertow|0|2.1.1.Final||Allocation of Resources Without Limits or Throttling in Undertow
CVE-2020-10719|GHSA-cccf-7xw3-p2vr|moderate|undertow-core|io.undertow|0|2.1.1.Final||HTTP Request Smuggling in Undertow
CVE-2020-1745|GHSA-gv2w-88hx-8m9r|high|undertow-core|io.undertow|0|2.0.30||Improper Authorization in Undertoe
CVE-2020-1757|GHSA-2w73-fqqj-c92p|high|undertow-core|io.undertow|0|2.1.0||Improper Input Validation in Undertow
CVE-2020-27782|GHSA-rhcw-wjcm-9h6g|high|undertow-core|io.undertow|0|2.0.33||Denial of service in Undertow
CVE-2020-27782|GHSA-rhcw-wjcm-9h6g|high|undertow-core|io.undertow|2.1.0|2.1.5||Denial of service in Undertow
CVE-2021-20220|GHSA-qjwc-v72v-fq6r|moderate|undertow-core|io.undertow|0|2.0.34||HTTP request smuggling in Undertow
CVE-2021-20220|GHSA-qjwc-v72v-fq6r|moderate|undertow-core|io.undertow|2.1.0|2.1.6||HTTP request smuggling in Undertow
CVE-2021-3597|GHSA-mfhv-gwf8-4m88|moderate|undertow-core|io.undertow|0|2.0.39.Final||undertow Race Condition vulnerability
CVE-2021-3597|GHSA-mfhv-gwf8-4m88|moderate|undertow-core|io.undertow|2.1.0|2.2.9.Final||undertow Race Condition vulnerability
CVE-2021-3629|GHSA-rf6q-vx79-mjxr|high|undertow-core|io.undertow|0|2.0.40.Final||Undertow Uncontrolled Resource Consumption
CVE-2021-3629|GHSA-rf6q-vx79-mjxr|high|undertow-core|io.undertow|2.1.0|2.2.11.Final||Undertow Uncontrolled Resource Consumption
CVE-2021-3690|GHSA-fj7c-vg2v-ccrm|high|undertow-core|io.undertow|0|2.0.40||Undertow vulnerable to memory exhaustion due to buffer leak
CVE-2021-3690|GHSA-fj7c-vg2v-ccrm|high|undertow-core|io.undertow|2.2.0|2.2.10||Undertow vulnerable to memory exhaustion due to buffer leak
CVE-2021-3859|GHSA-339q-62wm-c39w|high|undertow-core|io.undertow|0|2.2.15||Undertow vulnerable to Denial of Service (DoS) attacks
CVE-2022-2053|GHSA-95rf-557x-44g5|high|undertow-core|io.undertow|0|2.2.19.Final||Undertow vulnerable to Dos via Large AJP request
CVE-2022-2053|GHSA-95rf-557x-44g5|high|undertow-core|io.undertow|2.3.0.Alpha1|2.3.0.Alpha2||Undertow vulnerable to Dos via Large AJP request
CVE-2022-4492|GHSA-pfcc-3g6r-8rg8|critical|undertow-core|io.undertow|0|2.2.24.Final||Undertow client not checking server identity presented by server certificate in https connections
CVE-2022-4492|GHSA-pfcc-3g6r-8rg8|critical|undertow-core|io.undertow|2.3.0|2.3.5.Final||Undertow client not checking server identity presented by server certificate in https connections
CVE-2023-1108|GHSA-m4mm-pg93-fv78|high|undertow-core|io.undertow|0|2.2.24.Final||Undertow denial of service vulnerability
CVE-2023-1108|GHSA-m4mm-pg93-fv78|high|undertow-core|io.undertow|2.3.0|2.3.5.Final||Undertow denial of service vulnerability
CVE-2023-1973|GHSA-97cq-f4jm-mv8h|moderate|undertow-core|io.undertow|0|2.2.32.Final||Undertow Denial of Service vulnerability
CVE-2023-1973|GHSA-97cq-f4jm-mv8h|moderate|undertow-core|io.undertow|2.3.0.Alpha1|2.3.13.Final||Undertow Denial of Service vulnerability
CVE-2023-4639|GHSA-3jrv-jgp8-45v3|high|undertow-core|io.undertow|0|2.2.30.Final||Undertow incorrectly parses cookies
CVE-2023-4639|GHSA-3jrv-jgp8-45v3|high|undertow-core|io.undertow|2.3.0.Alpha1|2.3.11.Final||Undertow incorrectly parses cookies
CVE-2024-1459|GHSA-v76w-3ph8-vm66|moderate|undertow-core|io.undertow|0|2.2.31.Final||Undertow Path Traversal vulnerability
CVE-2024-1459|GHSA-v76w-3ph8-vm66|moderate|undertow-core|io.undertow|2.3.0.Alpha1|2.3.12.Final||Undertow Path Traversal vulnerability
CVE-2024-1635|GHSA-w6qf-42m7-vh68|high|undertow-core|io.undertow|0|2.2.31.Final||Undertow Uncontrolled Resource Consumption Vulnerability
CVE-2024-1635|GHSA-w6qf-42m7-vh68|high|undertow-core|io.undertow|2.3.0.Final|2.3.12.Final||Undertow Uncontrolled Resource Consumption Vulnerability
CVE-2024-3653|GHSA-ch7q-gpff-h9hp|moderate|undertow-core|io.undertow|0|2.2.34.Final||Undertow Missing Release of Memory after Effective Lifetime vulnerability
CVE-2024-3653|GHSA-ch7q-gpff-h9hp|moderate|undertow-core|io.undertow|2.3.0.Alpha1|2.3.15.Final||Undertow Missing Release of Memory after Effective Lifetime vulnerability
CVE-2024-3884|GHSA-6h4f-pj3g-q8fq|high|undertow-core|io.undertow|0|2.2.39.Final||Undertow OutOfMemory when parsing form data encoding with application/x-www-form-urlencoded
CVE-2024-3884|GHSA-6h4f-pj3g-q8fq|high|undertow-core|io.undertow|2.3.0.Alpha1|2.3.21.Final||Undertow OutOfMemory when parsing form data encoding with application/x-www-form-urlencoded
CVE-2024-3884|GHSA-6h4f-pj3g-q8fq|high|undertow-core|io.undertow|2.4.0.Alpha1|2.4.0.Beta1||Undertow OutOfMemory when parsing form data encoding with application/x-www-form-urlencoded
CVE-2024-4027|GHSA-33hj-rcmx-86mv|high|undertow-core|io.undertow|0|2.2.39.Final||Undertow Servlets Vulnerable to Remote DoS via OutOfMemoryError when Passed Large Parameter Names
CVE-2024-4027|GHSA-33hj-rcmx-86mv|high|undertow-core|io.undertow|2.3.0.Alpha1|2.3.21.Final||Undertow Servlets Vulnerable to Remote DoS via OutOfMemoryError when Passed Large Parameter Names
CVE-2024-4027|GHSA-33hj-rcmx-86mv|high|undertow-core|io.undertow|2.4.0.Alpha1|2.4.0.Beta1||Undertow Servlets Vulnerable to Remote DoS via OutOfMemoryError when Passed Large Parameter Names
CVE-2024-5971|GHSA-xpp6-8r3j-ww43|high|undertow-core|io.undertow|0|2.2.34.Final||Undertow Denial of Service vulnerability
CVE-2024-5971|GHSA-xpp6-8r3j-ww43|high|undertow-core|io.undertow|2.3.0.Alpha1|2.3.15.Final||Undertow Denial of Service vulnerability
CVE-2024-6162|GHSA-9442-gm4v-r222|high|undertow-core|io.undertow|0|2.2.33.Final||Undertow's url-encoded request path information can be broken on ajp-listener
CVE-2024-6162|GHSA-9442-gm4v-r222|high|undertow-core|io.undertow|2.3.0.Alpha1|2.3.14.Final||Undertow's url-encoded request path information can be broken on ajp-listener
CVE-2024-7885|GHSA-9623-mqmm-5rcf|high|undertow-core|io.undertow|0|2.2.36.Final||Undertow vulnerable to Race Condition
CVE-2024-7885|GHSA-9623-mqmm-5rcf|high|undertow-core|io.undertow|2.3.0.Alpha1|2.3.17.Final||Undertow vulnerable to Race Condition
CVE-2025-12543|GHSA-j382-5jj3-vw4j|critical|undertow-core|io.undertow|0|2.2.39.Final||Undertow HTTP server core doesn't properly validate the Host header in incoming HTTP requests
CVE-2025-12543|GHSA-j382-5jj3-vw4j|critical|undertow-core|io.undertow|2.3.0.Alpha1|2.3.21.Final||Undertow HTTP server core doesn't properly validate the Host header in incoming HTTP requests
CVE-2025-9784|GHSA-95h4-w6j8-2rp8|high|undertow-core|io.undertow|0|2.2.38.Final||Undertow MadeYouReset HTTP/2 DDoS Vulnerability
CVE-2025-9784|GHSA-95h4-w6j8-2rp8|high|undertow-core|io.undertow|2.3.0.Alpha1|2.3.20.Final||Undertow MadeYouReset HTTP/2 DDoS Vulnerability
CVE-2026-3260|GHSA-3x3v-w654-m28m|moderate|undertow-core|io.undertow|0|||Undertow: Denial of Service via Multipart/Form-Data Parsing on HTTP GET Requests
CVE-2019-10184|GHSA-w69w-jvc7-wjgv|high|undertow-servlet|io.undertow|0|2.0.23||Undertow Missing Authorization when requesting a protected directory without trailing slash
CVE-2023-4061|GHSA-26qx-4m49-6cfr|moderate|wildfly-controller|org.wildfly.core|0|22.0.0.Final||wildfly-core Exposure of Sensitive Information to an Unauthorized Actor vulnerability
CVE-2020-10714|GHSA-7fhr-2694-rg79|high|wildfly-elytron-base|org.wildfly.security|0|1.11.4||Session Fixation in WildFly Elytron
CVE-2020-1748|GHSA-qgrq-cx4c-2rmm|high|wildfly-elytron-base|org.wildfly.security|0|1.6.8||Incorrect Authorization in WildFly Elytron
CVE-2021-3642|GHSA-5499-qjvh-6j7w|moderate|wildfly-elytron-base|org.wildfly.security|0|1.10.14||Observable Discrepancy in Wildfly Elytron
CVE-2021-3642|GHSA-5499-qjvh-6j7w|moderate|wildfly-elytron-base|org.wildfly.security|1.11.0|1.15.5||Observable Discrepancy in Wildfly Elytron
CVE-2021-3642|GHSA-5499-qjvh-6j7w|moderate|wildfly-elytron-base|org.wildfly.security|1.16.0|1.16.1||Observable Discrepancy in Wildfly Elytron
CVE-2022-3143|GHSA-jmj6-p2j9-68cp|high|wildfly-elytron-base|org.wildfly.security|0|1.15.15.Final||Wildfly-elytron possibly vulnerable to timing attacks via use of unsafe comparator
CVE-2022-3143|GHSA-jmj6-p2j9-68cp|high|wildfly-elytron-base|org.wildfly.security|1.16.0.CR1|1.20.3.Final||Wildfly-elytron possibly vulnerable to timing attacks via use of unsafe comparator
CVE-2024-12369|GHSA-5565-3c98-g6jc|moderate|wildfly-elytron-base|org.wildfly.security|1.17.0.Final|2.2.9.Final||WildFly Elytron OpenID Connect Client ExtensionOIDC authorization code injection attack
CVE-2024-12369|GHSA-5565-3c98-g6jc|moderate|wildfly-elytron-base|org.wildfly.security|2.3.0.Final|2.6.2.Final||WildFly Elytron OpenID Connect Client ExtensionOIDC authorization code injection attack
CVE-2023-6236|GHSA-jpmx-996v-48fm|high|wildfly-elytron-http-oidc|org.wildfly.security|0|2.2.5.Final||WildFly Elytron: OIDC app attempting to access the second tenant, the user should be prompted to log
CVE-2024-12369|GHSA-5565-3c98-g6jc|moderate|wildfly-elytron-http-oidc|org.wildfly.security|1.17.0.Final|2.2.9.Final||WildFly Elytron OpenID Connect Client ExtensionOIDC authorization code injection attack
CVE-2024-12369|GHSA-5565-3c98-g6jc|moderate|wildfly-elytron-http-oidc|org.wildfly.security|2.3.0.Final|2.6.2.Final||WildFly Elytron OpenID Connect Client ExtensionOIDC authorization code injection attack
CVE-2025-23368|GHSA-qhp6-6p8p-2rqh|high|wildfly-elytron-integration|org.wildfly.core|0|31.0.3.Final||Wildfly Elytron integration susceptible to brute force attacks via CLI
CVE-2025-23368|GHSA-qhp6-6p8p-2rqh|high|wildfly-elytron-integration|org.wildfly.core|32.0.0.Beta1|32.0.0.Beta3||Wildfly Elytron integration susceptible to brute force attacks via CLI
CVE-2024-1233|GHSA-v4mm-q8fv-r2w5|high|wildfly-elytron-realm-token|org.wildfly.security|0||2.4.0.CR1|WildFly Elytron: SSRF security issue
CVE-2019-14838|GHSA-82v2-f875-73g9|moderate|wildfly-host-controller|org.wildfly.core|0|7.2.5.GA||Wildfly Authorization Misconfiguration
CVE-2021-3503|GHSA-c4r5-xvgw-2942|moderate|wildfly-metrics|org.wildfly|0|23.0.1.Final||Metrics exposure in Wildfly
CVE-2018-10862|GHSA-w8r2-5j8x-x8j6|moderate|wildfly-server|org.wildfly.core|0|6.0.0.Alpha3||Improper Limitation of a Pathname to a Restricted Directory in WildFly
CVE-2021-3644|GHSA-w88m-2936-rmxr|low|wildfly-server|org.wildfly.core|0|16.0.1.Final||wildfly-core allows user with access to management interface to access vault expression, retrieve item from vault
CVE-2021-3644|GHSA-w88m-2936-rmxr|low|wildfly-server|org.wildfly.core|17.0.0.Beta2|17.0.0.Beta3||wildfly-core allows user with access to management interface to access vault expression, retrieve item from vault
CVE-2021-3717|GHSA-p9xf-3rm3-qh2h|high|wildfly-server|org.wildfly.core|0|17.0||Wildfly-Core user account mismanagement
CVE-2025-23367|GHSA-qr6x-62gq-4ccp|moderate|wildfly-server|org.wildfly.core|0|27.0.1.Final||WildFly improper RBAC permission
CVE-2025-23367|GHSA-qr6x-62gq-4ccp|moderate|wildfly-server|org.wildfly.core|28.0.0.Beta1|28.0.0.Beta2||WildFly improper RBAC permission
CVE-2016-0793|GHSA-9q87-22gr-r8qf|high|wildfly-undertow|org.wildfly|0|10.0.0.Final||WildFly has incomplete blacklist vulnerability
CVE-2016-4993|GHSA-qcqr-hcjq-whfq|moderate|wildfly-undertow|org.wildfly|10.0.0.Final|11.0.0.Final||Improper Neutralization of CRLF Sequences in Wildfly Undertow
CVE-2016-9589|GHSA-p4xg-cpr9-vwvj|high|wildfly-undertow|org.wildfly|0|11.0.0.Beta1||Red Hat Wildfly DoS
CVE-2018-1047|GHSA-fmr4-w67p-vh8x|moderate|wildfly-undertow|org.wildfly|0|12.0.0||Improper Input Validation in org.wildfly:wildfly-undertow
CVE-2023-5685|GHSA-7f88-5hhx-67m2|high|xnio-api|org.jboss.xnio|0|3.8.14.Final||XNIO denial of service vulnerability
CVE-2020-14340|GHSA-c738-77x8-wmq5|moderate|xnio-nio|org.jboss.xnio|3.6.0|3.7.9.Final||Uncontrolled Resource Consumption in XNIO
CVE-2020-14340|GHSA-c738-77x8-wmq5|moderate|xnio-nio|org.jboss.xnio|3.8.0.Final|3.8.2.Final||Uncontrolled Resource Consumption in XNIO
# --- CVE_DB 끝 ---
EOF

N_APPLY=0; N_NA=0; N_FIXED=0
SEEN="$WORK/seen.txt"; : > "$SEEN"; NA="$WORK/na.txt"; : > "$NA"
GRP="$WORK/groups.txt"; : > "$GRP"
while IFS='|' read -r cve ghsa sev comp group intro fixed last desc; do
  case "$cve" in ''|\#*) continue ;; esac
  grep -qx "$cve" "$SEEN" && continue
  cur="$(comp_ver "$comp")"
  # 같은 jar 이름이라도 다른 프로젝트(groupId 다름)면 해당 없음
  if [ -n "$cur" ] && [ -n "$group" ]; then
    g="$(awk -F'|' -v n="$comp" '$1==n {print $2; f=1} END {if (!f) exit 1}' "$GRP")" || { g="$(comp_group "$comp")"; printf '%s|%s\n' "$comp" "$g" >> "$GRP"; }
    if [ -n "$g" ] && [ "$g" != "$group" ]; then
      grep -q "^$cve|" "$NA" || printf '%s|%s|%s:%s\n' "$cve" "$sev" "$group" "$comp" >> "$NA"
      continue
    fi
  fi
  if [ -z "$cur" ]; then
    grep -q "^$cve|" "$NA" || printf '%s|%s|%s\n' "$cve" "$sev" "$comp" >> "$NA"
    continue
  fi
  hit=0
  if [ "$intro" = "0" ] || vle "$intro" "$cur"; then
    if [ -n "$fixed" ]; then vlt "$cur" "$fixed" && hit=1
    elif [ -n "$last" ]; then vle "$cur" "$last" && hit=1
    else hit=1
    fi
  fi
  if [ "$hit" -eq 1 ]; then
    echo "$cve" >> "$SEEN"
    if [ -n "$fixed" ]; then range="$intro~$fixed 미만"
    elif [ -n "$last" ]; then range="$intro~$last 이하"
    else range="$intro~수정 버전 없음"
    fi
    [ "$comp" = "WILDFLY" ] && cname="WildFly" || cname="$comp"
    line="$cve [$sev] $desc (영향: $cname $range, 조건: $cname $cur 설치됨, 출처: $ghsa)"
    case "$sev" in critical|high) risk "$line" ;; *) warn "$line" ;; esac
    N_APPLY=$((N_APPLY+1))
  fi
done < "$CVE_DB"
# 구성요소가 아예 없어 미해당인 CVE (해당 CVE 로 이미 나온 것은 제외)
while IFS='|' read -r cve sev comp; do
  grep -qx "$cve" "$SEEN" && continue
  printf '[미해당] %s (%s) - 필요 모듈(%s) 미사용\n' "$cve" "$sev" "$comp" >> "$REPORT"
  N_NA=$((N_NA+1))
done < "$NA"
N_TOTAL="$(grep -vE '^(#|$)' "$CVE_DB" | cut -d'|' -f1 | sort -u | wc -l)"
N_FIXED=$((N_TOTAL - N_APPLY - N_NA))
log ""
log "  → 해당 CVE: ${N_APPLY}건 / 구성요소가 없거나 다른 프로젝트라 미해당: ${N_NA}건 / 수정된 버전이라 미해당: ${N_FIXED}건 (전체 ${N_TOTAL}건 중)"
if [ "$N_APPLY" -eq 0 ]; then
  ok "이 스크립트의 CVE 목록 기준으로 해당하는 CVE 가 없습니다."
fi

# =====================================================================
section "[3] 위험 설정 점검 (관리 인터페이스·계정·실행 옵션·파일 권한)"
# =====================================================================
if [ ! -r "$CONFIG" ]; then
  warn "메인 설정 파일을 읽지 못했습니다: $CONFIG  (설정 기반 점검 일부를 건너뜁니다)"
  : > "$WORK/config.xml"
else
  # 주석(<!-- -->) 제거본
  sed -e ':a' -e 's/<!--[^>]*-->//g' -e '/<!--/{N;ba' -e '}' "$CONFIG" > "$WORK/config.xml" 2>/dev/null || cp "$CONFIG" "$WORK/config.xml"
fi
CFG="$WORK/config.xml"
# ${prop:기본값} 표현식 풀기: 명령줄 -Dprop 값 → 기본값
resolve() {
  local e="$1" prop def val
  if [[ "$e" =~ ^\$\{([^:}]+)(:([^}]*))?\}$ ]]; then
    prop="${BASH_REMATCH[1]}"; def="${BASH_REMATCH[3]}"
    val="$(sysprop "$prop")"
    case "$prop" in
      jboss.bind.address) [ -z "$val" ] && val="$(cliarg -b)" ;;
      jboss.bind.address.management) [ -z "$val" ] && val="$(cliarg -bmanagement)" ;;
    esac
    printf '%s' "${val:-$def}"
  else
    printf '%s' "$e"
  fi
}
is_loopback() { [[ "$1" =~ ^(127\.|::1$|localhost$|\[::1\]$) ]]; }
# 인터페이스 이름 → 주소 (inet-address / any-address / loopback)
iface_addr() {
  local blk
  blk="$(awk -v n="$1" '$0 ~ "<interface name=\"" n "\"" {f=1} f {print} f && /<\/interface>|\/>[ \t]*$/ && !/<interface name/ {exit}' "$CFG")"
  if printf '%s' "$blk" | grep -q '<any-address'; then echo "0.0.0.0"; return; fi
  if printf '%s' "$blk" | grep -q '<loopback'; then echo "127.0.0.1"; return; fi
  resolve "$(printf '%s' "$blk" | sed -n 's/.*<inet-address value="\([^"]*\)".*/\1/p' | head -n1)"
}
OFFSET="$(resolve "$(sed -n 's/.*<socket-binding-group [^>]*port-offset="\([^"]*\)".*/\1/p' "$CFG" | head -n1)")"
OFFSET="${OFFSET:-0}"; [[ "$OFFSET" =~ ^[0-9]+$ ]] || OFFSET=0
port_of() { local p; p="$(resolve "$(sed -n "s/.*<socket-binding name=\"$1\"[^>]* port=\"\([^\"]*\)\".*/\1/p" "$CFG" | head -n1)")"; [[ "$p" =~ ^[0-9]+$ ]] && echo $((p + OFFSET)); }

# 3-1 관리 인터페이스(관리 콘솔·HTTP 관리 API) 노출
MGMT_ADDR="$(iface_addr management)"
MGMT_PORT="$(port_of management-http)"; MGMT_PORT="${MGMT_PORT:-$((9990 + OFFSET))}"
MGMT_SPORT="$(port_of management-https)"; MGMT_SPORT="${MGMT_SPORT:-$((9993 + OFFSET))}"
LISTEN=""
if [ -n "${PRECHECK_PID:-}" ] && command -v ss >/dev/null 2>&1; then
  LISTEN="$(ss -ltnpH 2>/dev/null | grep "pid=$PRECHECK_PID," | awk '{print $4}' | sort -u)"
fi
MGMT_OPEN="$(printf '%s\n' "$LISTEN" | grep -E ":($MGMT_PORT|$MGMT_SPORT)$" | grep -vE '^(127\.|\[::1\]|::1)')"
if [ -n "$MGMT_OPEN" ]; then
  risk "관리 인터페이스(관리 콘솔/관리 API, 포트 $MGMT_PORT/$MGMT_SPORT)가 외부 주소에서 접속 가능 → 비밀번호 추측·관리 API 공격 대상. 127.0.0.1 또는 관리망 전용 주소로 제한 권장"
  printf '%s\n' "$MGMT_OPEN" | show
elif [ -z "$LISTEN" ] && [ -n "$MGMT_ADDR" ] && ! is_loopback "$MGMT_ADDR"; then
  risk "관리 인터페이스 바인드 주소가 $MGMT_ADDR (설정 기준) → 외부에서 관리 콘솔 접속 가능. 127.0.0.1 또는 관리망 전용 주소로 제한 권장"
elif [ -n "$MGMT_ADDR" ]; then
  ok "관리 인터페이스는 루프백($MGMT_ADDR)에서만 열림"
else
  info "관리 인터페이스 바인드 주소를 확인하지 못함"
fi
if [ -n "$LISTEN" ]; then
  info "이 WildFly 프로세스가 열어 둔 포트"
  printf '%s\n' "$LISTEN" | show
fi

# 3-2 관리 인터페이스 인증
MI="$(awk '/<management-interfaces>/{f=1} f{print} /<\/management-interfaces>/{exit}' "$CFG")"
if printf '%s' "$MI" | grep -q '<http-interface'; then
  HI="$(printf '%s\n' "$MI" | awk '/<http-interface/{f=1} f{print} /<\/http-interface>|<http-interface[^>]*\/>/{if(f) exit}')"
  if printf '%s' "$HI" | grep -qE 'http-authentication-factory=|security-realm='; then
    ok "HTTP 관리 인터페이스에 인증 설정 있음"
  else
    risk "HTTP 관리 인터페이스에 인증 설정(http-authentication-factory / security-realm)이 없음 → 누구나 관리 API 사용 가능"
    printf '%s\n' "$HI" | head -n 3 | sed 's/^[ \t]*//' | show
  fi
  if printf '%s' "$HI" | grep -q 'console-enabled="false"'; then ok "관리 콘솔(웹 화면) 비활성화됨"; fi
fi

# 3-3 관리/애플리케이션 계정 비밀번호 (properties 파일의 해시 = MD5(아이디:영역:비밀번호))
WEAK_PW="admin password passw0rd p@ssw0rd P@ssw0rd 1234 12345 123456 12345678 1q2w3e4r qwer1234 admin123 admin1234 admin@123 wildfly jboss jboss123 changeit changeme manager test welcome1"
check_users() { # $1 파일, $2 기본 영역명, $3 설명, $4 쉬운 비밀번호 발견 시 수준(risk|warn)
  local f="$1" realm users weak="" u h p
  [ -f "$f" ] || return
  realm="$(sed -n 's/^#\$REALM_NAME=\([^$]*\)\$.*/\1/p' "$f" | head -n1)"; realm="${realm:-$2}"
  users="$(grep -E '^[^#!][^=]*=[0-9a-fA-F]{32}[ \t]*$' "$f" 2>/dev/null)"
  if [ -z "$users" ]; then
    [ "$4" = "risk" ] && ok "$3 계정 없음 (관리 콘솔 로그인 불가)"
    return
  fi
  info "$3 계정 $(printf '%s\n' "$users" | wc -l)개: $(printf '%s\n' "$users" | cut -d= -f1 | tr '\n' ' ')"
  while IFS='=' read -r u h; do
    h="$(printf '%s' "$h" | tr -d ' \t\r' | tr 'A-F' 'a-f')"
    for p in $WEAK_PW "$u"; do
      if [ "$(printf '%s:%s:%s' "$u" "$realm" "$p" | md5sum | cut -c1-32)" = "$h" ]; then weak="$weak $u"; break; fi
    done
  done <<< "$users"
  if [ -n "$weak" ]; then
    if [ "$4" = "risk" ]; then risk "$3 계정에 추측하기 쉬운 비밀번호 사용:$weak → 즉시 변경 (add-user.sh)"
    else warn "$3 계정에 추측하기 쉬운 비밀번호 사용:$weak → 변경 권장"; fi
  else
    ok "$3 계정에 흔한 비밀번호(사전 $(printf '%s\n' $WEAK_PW | wc -l)개·아이디와 같은 비밀번호) 사용 없음"
  fi
  if [ -n "$(find "$f" -perm -004 2>/dev/null)" ]; then
    warn "$(basename "$f") 를 모든 계정이 읽을 수 있음 → 비밀번호 해시 유출 위험. chmod 600 권장"
  fi
}
check_users "$CONF_DIR/mgmt-users.properties" ManagementRealm "관리" risk
check_users "$CONF_DIR/application-users.properties" ApplicationRealm "애플리케이션" warn

# 3-4 실행 계정
RUN_USER=""
[ -n "${PRECHECK_PID:-}" ] && RUN_USER="$(ps -o user= -p "$PRECHECK_PID" 2>/dev/null | tr -d ' ')"
if [ "$RUN_USER" = "root" ]; then risk "실행 계정이 root → 앱 취약점이 곧 서버 전체 장악으로 이어짐. 전용 계정(예: wildfly)으로 실행 권장"
elif [ -n "$RUN_USER" ]; then ok "실행 계정: $RUN_USER"
else info "실행 계정을 확인하지 못함 (WildFly 가 실행 중이 아님)"; fi

# 3-5 원격 디버그 / JMX 원격 접속 옵션
DBG="$(grep -E '^-(agentlib:jdwp|Xrunjdwp)' "$CMDLINE")"
if [ -n "$DBG" ]; then
  if printf '%s' "$DBG" | grep -qE 'address=(\*|0\.0\.0\.0|[^,]*[1-9][0-9]*\.[0-9])' && ! printf '%s' "$DBG" | grep -qE 'address=(127\.0\.0\.1|localhost):'; then
    risk "원격 디버그(JDWP)가 외부 주소에 열려 있음 → 인증 없이 원격 코드 실행 가능"
  else
    warn "원격 디버그(JDWP) 옵션이 켜져 있음 → 운영 서버에서는 제거 권장"
  fi
  printf '%s\n' "$DBG" | show
else
  [ -s "$CMDLINE" ] && ok "원격 디버그(JDWP) 옵션 없음"
fi
if grep -qE '^-Dcom\.sun\.management\.jmxremote\.port=' "$CMDLINE"; then
  if grep -qx -- '-Dcom.sun.management.jmxremote.authenticate=false' "$CMDLINE"; then
    risk "JMX 원격 접속이 인증 없이 열려 있음 (jmxremote.authenticate=false) → 원격 코드 실행 가능"
  else
    warn "JMX 원격 접속 포트가 설정되어 있음 → 접근 제어·인증 확인 필요"
  fi
  grep -E '^-Dcom\.sun\.management\.jmxremote' "$CMDLINE" | show
fi

# 3-6 웹(Undertow) 설정
if grep -q '<ajp-listener' "$CFG"; then
  warn "AJP 리스너 사용 중 → 프록시(Apache/Nginx) 외에는 접근하지 못하게 방화벽 제한 필요 (AJP 계열 CVE 대상)"
  grep '<ajp-listener' "$CFG" | sed 's/^[ \t]*//' | show
else
  ok "AJP 리스너 없음"
fi
if grep -qE '<location name="/" handler="welcome-content"' "$CFG"; then
  warn "기본 환영 페이지(welcome-content)가 / 에 연결됨 → WildFly 사용 사실·버전 노출. 운영 앱으로 교체하거나 제거 권장"
else
  ok "기본 환영 페이지 미사용"
fi
DL="$(grep -E 'directory-listing="true"' "$CFG")"
if [ -n "$DL" ]; then warn "디렉터리 목록 노출(directory-listing=\"true\")"; printf '%s\n' "$DL" | sed 's/^[ \t]*//' | show
else ok "디렉터리 목록 노출 설정 없음"; fi
if grep -qE '<jsp-config[^>]*development="true"' "$CFG"; then warn "JSP 개발 모드(development=\"true\") → 운영에서는 끄기 권장"; fi
if grep -qE '(<response-header[^>]*header-name="(Server|X-Powered-By)")' "$CFG"; then
  warn "응답 헤더로 서버 정보 노출 설정(Server / X-Powered-By) 있음"
  grep -E '<response-header[^>]*header-name="(Server|X-Powered-By)"' "$CFG" | sed 's/^[ \t]*//' | show
fi
HTTP_PORT="$(port_of http)"
if [ -n "$HTTP_PORT" ] && command -v curl >/dev/null 2>&1 && [ -n "${PRECHECK_PID:-}" ]; then
  HADDR="$(iface_addr public)"; { [ -z "$HADDR" ] || [ "$HADDR" = "0.0.0.0" ]; } && HADDR="127.0.0.1"
  HDR="$(curl -sS -m 5 -o /dev/null -D - "http://$HADDR:$HTTP_PORT/" 2>/dev/null | grep -iE '^(server|x-powered-by):' | tr -d '\r')"
  if printf '%s' "$HDR" | grep -qE '[0-9]+\.[0-9]'; then warn "HTTP 응답 헤더에 버전 번호 노출"; printf '%s\n' "$HDR" | show
  elif [ -n "$HDR" ]; then info "HTTP 응답 헤더: $(printf '%s' "$HDR" | tr '\n' ' ')"
  else ok "HTTP 응답 헤더에 서버 정보(Server/X-Powered-By) 없음"; fi
fi

# 3-7 로그 수준 (DEBUG/TRACE 는 인증 정보가 로그에 남는 CVE 계열 조건)
RL="$(awk '/<root-logger>/{f=1} f && /<level /{print; exit} /<\/root-logger>/{f=0}' "$CFG")"
if printf '%s' "$RL" | grep -qE 'name="(DEBUG|TRACE|ALL)"'; then
  warn "루트 로그 수준이 DEBUG/TRACE → 요청·인증 정보가 로그에 남을 수 있음"
  detail "$(printf '%s' "$RL" | sed 's/^[ \t]*//')"
fi

# 3-8 파일 권한 (모든 계정이 쓸 수 있으면 설정 변조·앱 바꿔치기 가능)
WW="$(find "$CONF_DIR" "$BASE_DIR/deployments" "$JBOSS_HOME/modules" "$JBOSS_HOME/bin" -maxdepth 3 -perm -002 ! -type l 2>/dev/null | head -n 10)"
if [ -n "$WW" ]; then risk "모든 계정이 쓸 수 있는 설정/배포/모듈/실행 파일·폴더 있음 → 설정 변조·악성 앱 배포 가능"; printf '%s\n' "$WW" | show
else ok "설정·배포·모듈·실행 폴더에 모든 계정 쓰기 권한 없음"; fi
if [ -n "$RUN_USER" ] && [ "$RUN_USER" != "root" ] && id "$RUN_USER" >/dev/null 2>&1; then
  OWN="$(find "$JBOSS_HOME/bin" "$JBOSS_HOME/modules" -maxdepth 2 -user "$RUN_USER" 2>/dev/null | head -n 5)"
  [ -n "$OWN" ] && { warn "실행 계정($RUN_USER)이 bin/modules 를 소유 → 앱 취약점으로 WildFly 자체 파일 변조 가능. root 소유 + 읽기 전용 권장"; printf '%s\n' "$OWN" | show; }
fi

# =====================================================================
section "[4] 침해 흔적 점검 (이미 해킹당했는지)"
# =====================================================================
# 4-1 접근 로그 (WildFly 는 기본값으로 접근 로그를 남기지 않음. Undertow <access-log> 설정 시 생성)
LOGS="$WORK/logs.txt"; : > "$LOGS"
if [ -n "$LOG_PATHS" ]; then
  for p in $LOG_PATHS; do
    # shellcheck disable=SC2086
    ls -d -- $p 2>/dev/null
  done >> "$LOGS"
  info "접근 로그 경로를 -l 옵션 값으로 사용: $LOG_PATHS"
else
  AL="$(grep -E '<access-log' "$CFG" | head -n1)"
  if [ -n "$AL" ]; then
    AP="$(printf '%s' "$AL" | sed -n 's/.*prefix="\([^"]*\)".*/\1/p')"; AP="${AP:-access_log.}"
    AD="$(printf '%s' "$AL" | sed -n 's/.*directory="\([^"]*\)".*/\1/p')"; AD="$(resolve "${AD:-$LOG_DIR}")"
    [ -z "$AD" ] && AD="$LOG_DIR"
    find "$AD" -maxdepth 1 -type f -name "${AP}*" 2>/dev/null >> "$LOGS"
  fi
  find "$LOG_DIR" -maxdepth 3 -type f -name 'access_log*' 2>/dev/null >> "$LOGS"
fi
sort -u "$LOGS" | while read -r f; do [ -f "$f" ] && [[ "$f" != "$REPORT" ]] && echo "$f"; done > "$WORK/logs2.txt"; mv "$WORK/logs2.txt" "$LOGS"

if [ ! -s "$LOGS" ]; then
  warn "접근 로그 파일을 찾지 못했습니다. 로그 기반 점검을 건너뜁니다. (WildFly 는 기본값으로 접근 로그를 남기지 않음)"
  detail "→ 앞단 프록시(Apache/Nginx) 로그가 있으면 -l 옵션으로 지정하세요. 예: sudo bash $0 -l '/var/log/httpd/access_log*'"
  detail "→ 접근 로그 켜기(CLI): /subsystem=undertow/server=default-server/host=default-host/setting=access-log:add"
else
  info "점검 대상 접근 로그: $(wc -l < "$LOGS")개"
  head -n 10 "$LOGS" | show
  zg() { while read -r f; do zgrep -hE "$1" "$f" 2>/dev/null; done < "$LOGS"; }

  zg '(\.%2e|%2e\.|%2e%2e|%252e|\.\./|\.\.%2f|%c0%ae)' > "$WORK/trav.txt"
  T_ALL=$(wc -l < "$WORK/trav.txt"); T_200=$(grep -cE '" 200 ' "$WORK/trav.txt")
  if [ "$T_200" -gt 0 ]; then
    risk "경로 탐색 시도 중 200(성공) 응답 ${T_200}건 → 침해 가능성. 즉시 상세 분석 필요"
    grep -E '" 200 ' "$WORK/trav.txt" | head -n 5 | show
  elif [ "$T_ALL" -gt 0 ]; then warn "경로 탐색 시도 ${T_ALL}건 (성공 응답 없음) → 스캔 대상이 되고 있음"
  else ok "경로 탐색 시도 흔적 없음"; fi

  zg '(cmd=|exec=|shell=|whoami|/etc/passwd|/bin/(ba)?sh|wget(%20|\+)|curl(%20|\+)|\$\{jndi:|%24%7Bjndi|Runtime\.getRuntime|java\.lang\.ProcessBuilder)' > "$WORK/shell.txt"
  S_200=$(grep -cE '" 200 ' "$WORK/shell.txt")
  if [ "$S_200" -gt 0 ]; then
    risk "명령실행/웹쉘/JNDI 주입 의심 요청 중 200 응답 ${S_200}건"
    grep -E '" 200 ' "$WORK/shell.txt" | head -n 5 | show
  elif [ -s "$WORK/shell.txt" ]; then warn "명령실행/웹쉘/JNDI 주입 의심 요청 $(wc -l < "$WORK/shell.txt")건 (성공 응답 없음)"
  else ok "명령실행/웹쉘/JNDI 주입 의심 요청 흔적 없음"; fi

  # JBoss/WildFly 를 노리는 잘 알려진 공격 경로 (JMX/EJB 인보커, 옛 관리 콘솔, 관리 API)
  zg '"(GET|POST|HEAD|PUT) /(invoker/(JMXInvokerServlet|EJBInvokerServlet|readonly)|jmx-console|web-console|admin-console|jbossmq-httpil|management|console)' > "$WORK/jboss.txt"
  J_200=$(grep -cE '" 200 ' "$WORK/jboss.txt")
  if [ "$J_200" -gt 0 ]; then
    risk "JBoss/WildFly 관리·인보커 경로 요청 중 200 응답 ${J_200}건 → 관리 기능이 웹으로 노출되었을 가능성"
    grep -E '" 200 ' "$WORK/jboss.txt" | head -n 5 | show
  elif [ -s "$WORK/jboss.txt" ]; then warn "JBoss/WildFly 관리·인보커 경로 요청 $(wc -l < "$WORK/jboss.txt")건 (성공 응답 없음) → 스캔 대상"
  else ok "JBoss/WildFly 관리·인보커 경로 공격 흔적 없음"; fi

  cat "$WORK/trav.txt" "$WORK/shell.txt" "$WORK/jboss.txt" | awk '{print $1}' | sort | uniq -c | sort -rn | head -n 5 > "$WORK/topip.txt"
  [ -s "$WORK/topip.txt" ] && { info "의심 요청 상위 IP (차단 검토용)"; show < "$WORK/topip.txt"; }
fi

# 4-2 배포된 애플리케이션 (deployments 폴더 + 관리 콘솔/CLI 로 배포된 data/content)
DEPDIRS="$WORK/depdirs.txt"; : > "$DEPDIRS"
for d in "$BASE_DIR/deployments" "$BASE_DIR/data/content"; do [ -d "$d" ] && echo "$d" >> "$DEPDIRS"; done
if [ ! -s "$DEPDIRS" ]; then
  warn "배포 폴더를 찾지 못했습니다. 파일 기반 점검을 건너뜁니다. ($BASE_DIR/deployments, $BASE_DIR/data/content)"
else
  DEPLOYED="$(sed -n 's/.*<deployment name="\([^"]*\)".*/\1/p' "$CFG"; find "$BASE_DIR/deployments" -maxdepth 1 \( -name '*.war' -o -name '*.ear' -o -name '*.jar' -o -name '*.rar' -o -name '*.sar' \) -printf '%f\n' 2>/dev/null)"
  DEPLOYED="$(printf '%s\n' "$DEPLOYED" | grep -v '^$' | sort -u)"
  if [ -n "$DEPLOYED" ]; then info "배포된 애플리케이션 $(printf '%s\n' "$DEPLOYED" | wc -l)개"; printf '%s\n' "$DEPLOYED" | head -n 20 | show
  else info "배포된 애플리케이션 없음"; fi

  WS_PAT='Runtime\.getRuntime\(\)\.exec|new[[:space:]]+ProcessBuilder|ScriptEngineManager|defineClass[[:space:]]*\(|ProcessImpl|getRuntime\(\)\.exec'
  : > "$WORK/ws.txt"; : > "$WORK/jspfiles.txt"
  # (a) 풀어서 배포된 폴더 안의 JSP
  while read -r d; do
    find "$d" -type f \( -iname '*.jsp' -o -iname '*.jspx' -o -iname '*.jspf' \) 2>/dev/null
  done < "$DEPDIRS" > "$WORK/jspfiles.txt"
  [ -s "$WORK/jspfiles.txt" ] && tr '\n' '\0' < "$WORK/jspfiles.txt" | xargs -0 -r grep -lE "$WS_PAT" 2>/dev/null >> "$WORK/ws.txt"
  # (b) 압축(war/ear/content) 안의 JSP
  ARCH="$WORK/arch.txt"
  while read -r d; do
    find "$d" -type f \( -name '*.war' -o -name '*.ear' -o -name 'content' \) 2>/dev/null
  done < "$DEPDIRS" > "$ARCH"
  ZIPTOOL=""; command -v unzip >/dev/null 2>&1 && ZIPTOOL=unzip
  [ -z "$ZIPTOOL" ] && command -v python3 >/dev/null 2>&1 && ZIPTOOL=python3
  if [ -s "$ARCH" ] && [ -z "$ZIPTOOL" ]; then
    warn "unzip/python3 이 없어 압축된 배포 파일(war/ear) 안의 JSP 를 점검하지 못했습니다."
  elif [ -s "$ARCH" ]; then
    while read -r a; do
      if [ "$ZIPTOOL" = unzip ]; then
        unzip -Z1 "$a" 2>/dev/null | grep -iE '\.jspx?$' | while read -r e; do
          unzip -p "$a" "$e" 2>/dev/null | grep -qE "$WS_PAT" && echo "$a!/$e"
        done
      else
        python3 -I -c '
import re, sys, zipfile
pat = re.compile(sys.argv[2].encode())
try:
    z = zipfile.ZipFile(sys.argv[1])
except Exception:
    sys.exit(0)
for n in z.namelist():
    if n.lower().endswith((".jsp", ".jspx")) and pat.search(z.read(n)):
        print(sys.argv[1] + "!/" + n)' "$a" "${WS_PAT//[[:space:]]/\\s}" 2>/dev/null
      fi
    done < "$ARCH" >> "$WORK/ws.txt"
  fi
  if [ -s "$WORK/ws.txt" ]; then
    risk "웹쉘 의심 코드 패턴(명령 실행·클래스 주입)을 포함한 JSP $(wc -l < "$WORK/ws.txt")개 (오탐 가능, 내용 확인 필수)"
    head -n 20 "$WORK/ws.txt" | show
  else
    ok "배포된 앱에 웹쉘 의심 코드 패턴 JSP 없음 (패턴 우회형·컴파일된 클래스형 웹쉘은 탐지 못함)"
  fi

  # 최근 변경된 배포 파일
  : > "$WORK/recent.txt"
  while read -r d; do
    find "$d" -type f -mtime "-$RECENT_DAYS" ! -name '*.deployed' ! -name '*.isdeploying' ! -name '*.pending' ! -name '*.undeployed' ! -name 'README.txt' 2>/dev/null
  done < "$DEPDIRS" >> "$WORK/recent.txt"
  if [ -s "$WORK/recent.txt" ]; then
    warn "최근 ${RECENT_DAYS}일 내 변경된 배포 파일 $(wc -l < "$WORK/recent.txt")개 → 배포 이력과 대조 필요"
    head -n 20 "$WORK/recent.txt" | while read -r f; do detail "$(ls -l --time-style=+%F_%T "$f" 2>/dev/null)"; done
  else
    ok "최근 ${RECENT_DAYS}일 내 변경된 배포 파일 없음"
  fi
fi

# 환영 페이지 폴더의 스크립트 파일 (정적 파일만 있어야 정상)
WC="$(find "$JBOSS_HOME/welcome-content" -type f \( -iname '*.jsp' -o -iname '*.jspx' -o -iname '*.sh' -o -iname '*.class' \) 2>/dev/null | head -n 10)"
[ -n "$WC" ] && { warn "환영 페이지 폴더(welcome-content)에 스크립트/클래스 파일 존재 → 원래 정적 파일만 있는 폴더"; printf '%s\n' "$WC" | show; }

# 4-3 WildFly 로그(server.log 등)의 공격·침해 흔적
#   대상: standalone.xml 로깅 설정의 파일 핸들러 경로(<file relative-to=... path=.../>, 회전된 파일 포함)
#         + 로그 폴더 아래 3단계까지의 server.log*  (예: logs/stdlog/server.log 같은 회사별 구조)
SLOGS_F="$WORK/slogs.txt"; : > "$SLOGS_F"
awk '/<subsystem xmlns="urn:jboss:domain:logging/{f=1} f && /<file /{print} f && /<\/subsystem>/{exit}' "$CFG" | while read -r line; do
  rel="$(printf '%s' "$line" | sed -n 's/.*relative-to="\([^"]*\)".*/\1/p')"
  pth="$(resolve "$(printf '%s' "$line" | sed -n 's/.*path="\([^"]*\)".*/\1/p')")"
  [ -z "$pth" ] && continue
  case "$rel" in
    "") base="" ;;
    jboss.server.log.dir|jboss.domain.log.dir) base="$LOG_DIR" ;;
    jboss.server.base.dir|jboss.domain.base.dir) base="$BASE_DIR" ;;
    jboss.home.dir) base="$JBOSS_HOME" ;;
    *) base="$(sysprop "$rel")" ;;
  esac
  case "$pth" in /*) f="$pth" ;; *) [ -n "$base" ] || continue; f="$base/$pth" ;; esac
  ls -d -- "$f" "$f".* 2>/dev/null
done >> "$SLOGS_F"
find "$LOG_DIR" -maxdepth 3 -type f -name 'server.log*' 2>/dev/null >> "$SLOGS_F"
SLOGS="$(sort -u "$SLOGS_F" | while read -r f; do [ -f "$f" ] && echo "$f"; done)"
if [ -z "$SLOGS" ]; then
  warn "server.log 를 찾지 못했습니다. WildFly 로그 기반 공격 흔적 점검을 건너뜁니다. (찾아본 곳: $LOG_DIR 아래 3단계, 로깅 설정의 파일 경로)"
  detail "→ 로그 위치는 WildFly 시작 옵션 -Djboss.server.log.dir 과 standalone.xml 의 logging 설정(<file path=...>)을 확인하세요."
else
  info "점검 대상 WildFly 로그: $(printf '%s\n' "$SLOGS" | wc -l)개"
  printf '%s\n' "$SLOGS" | head -n 10 | show
  GAD="$(printf '%s\n' "$SLOGS" | xargs -r zgrep -hE 'InvokerTransformer|TemplatesImpl|ysoserial|ChainedTransformer|JdbcRowSetImpl|\$\{jndi:(ldap|rmi|dns)' 2>/dev/null | grep -vE 'serialFilter|VM Arguments|-Djdk\.serial' | head -n 5)"
  if [ -n "$GAD" ]; then
    risk "server.log 에 역직렬화 공격 도구·JNDI 주입 흔적 → 침해 시도/성공 여부 상세 분석 필요"
    printf '%s\n' "$GAD" | cut -c1-200 | show
  else
    ok "server.log 에 역직렬화 공격·JNDI 주입 흔적 없음"
  fi
  DEP="$(printf '%s\n' "$SLOGS" | xargs -r zgrep -hE 'WFLYSRV0010: (Deployed|배포)|WFLYSRV0016: Replaced deployment' 2>/dev/null | tail -n 10)"
  [ -n "$DEP" ] && { info "최근 배포 기록 (server.log, 최근 10건) → 배포 이력과 대조"; printf '%s\n' "$DEP" | cut -c1-200 | show; }
fi

# 4-4 실행 계정의 의심 프로세스 / 크론 / 임시파일 / 외부 연결
if [ -n "$RUN_USER" ] && [ "$RUN_USER" != "root" ] && id "$RUN_USER" >/dev/null 2>&1; then
  PS="$(ps -u "$RUN_USER" -o pid=,ppid=,etime=,args= 2>/dev/null | grep -vE 'jboss-modules\.jar|standalone\.sh|domain\.sh|grep|ps -u' | grep -vE "^ *$$ ")"
  if [ -n "$PS" ]; then risk "WildFly 실행계정($RUN_USER)으로 실행 중인 다른 프로세스 (리버스쉘/채굴기 의심)"; printf '%s\n' "$PS" | cut -c1-200 | show
  else ok "실행계정의 비정상 프로세스 없음"; fi

  CR="$(crontab -l -u "$RUN_USER" 2>/dev/null | grep -vE '^\s*(#|$)')"
  if [ -n "$CR" ]; then risk "실행계정($RUN_USER)에 크론 작업 등록됨 (지속성 확보 의심)"; printf '%s\n' "$CR" | show
  else ok "실행계정 크론 작업 없음"; fi

  TMPF="$(find /tmp /var/tmp /dev/shm -xdev -user "$RUN_USER" -type f ! -path '*/hsperfdata_*' ! -path '*/vfs/*' 2>/dev/null | head -n 20)"
  if [ -n "$TMPF" ]; then warn "임시 디렉터리에 실행계정 소유 파일 존재 → 실행파일/스크립트 여부 확인"; printf '%s\n' "$TMPF" | show
  else ok "임시 디렉터리에 실행계정 소유 파일 없음"; fi
elif [ "$RUN_USER" = "root" ]; then
  info "실행 계정이 root 라 계정 기준 의심 프로세스/크론 점검은 생략합니다. (전용 계정으로 바꾸면 점검 가능)"
fi
if [ -n "${PRECHECK_PID:-}" ] && command -v ss >/dev/null 2>&1; then
  CONN="$(ss -tnpH state established 2>/dev/null | grep "pid=$PRECHECK_PID," | awk '{print $3" -> "$4}' | sort | uniq -c | sort -rn | head -n 15)"
  if [ -n "$CONN" ]; then
    info "WildFly 프로세스의 연결 목록 (DB·프록시 외의 외부 IP로 나가는 연결이 있으면 의심)"
    printf '%s\n' "$CONN" | show
  fi
fi

# =====================================================================
section "점검 요약"
# =====================================================================
log "  [위험] ${CNT_RISK}건   [주의] ${CNT_WARN}건   [양호] ${CNT_OK}건   [정보] ${CNT_INFO}건"
log ""
log "  ※ 이 결과는 '알려진 패턴' 기준이며 안전을 보증하지 않습니다."
log "    - [위험] 중 침해 흔적(로그 200 응답, 웹쉘, 비정상 프로세스)이 있으면 설정 보완보다 침해사고 대응이 우선입니다."
log "    - CVE 판정은 설치 폴더의 구성요소(jar) 버전과 OSV 영향 구간 기준이며, 실제 악용 가능 여부는 사용 기능에 따라 다릅니다."
log "    - 근본 대책은 최신 Final($LATEST_FINAL) 이상으로의 업그레이드입니다."
log ""
log "  리포트 파일: $REPORT"
