#!/usr/bin/env bash
# =====================================================================
#  apache_precheck.sh
#  Apache httpd 2.4.69 이전 버전 서버 - 패치 전 보안 사전 점검 스크립트
#
#  - 읽기 전용: 설정 변경/파일 삭제/서비스 재시작을 하지 않습니다.
#  - 점검 항목
#      [1] 버전 / 설치 방식(RPM·DEB·소스) 확인
#      [2] 버전 구간별 해당 CVE 판정 (켜진 모듈 기준으로 해당/미해당 구분)
#      [3] 위험 설정 점검 (httpd 가 실제로 읽는 = Include 된 설정 파일만,
#          꺼진 <IfModule>/<IfDefine> 블록 안의 설정은 제외)
#      [4] 침해 흔적 점검 (접근 로그, 웹쉘 의심 파일, 의심 프로세스/연결/크론)
#  - 결과: 화면 출력 + 리포트 파일(/tmp/apache_precheck_<호스트>_<시각>[_pid<PID>].txt)
#
#  수정 이력 (원본 대비)
#    1) 인스턴스 자동 탐지 버그 수정: httpd 를 옵션(-f/-d) 없이 띄운 경우 PID 가 실행 인자로 잘못
#       들어가 "로드된 모듈 수: 0" → 모듈 조건 CVE 전부 미해당 오판정, 설정 파일 목록 실패 문제
#    2) [3] 설정 점검 대상: DUMP_INCLUDES 실패 시 설정 폴더의 *.conf 를 전부 보던 방식 →
#       httpd.conf 의 (주석 아닌) Include/IncludeOptional 만 따라가도록 변경.
#       소스 설치의 #Include 로 막혀 있는 conf/extra/httpd-autoindex.conf, httpd-manual.conf,
#       httpd-userdir.conf 등이 점검되던 오탐 해결. 점검한 파일 목록과 확인 방법을 리포트에 기록
#    3) 서버 IP(루프백 제외)와 메인 설정 파일 경로를 리포트에 기록 (대시보드 표시용)
#
#  CVE 데이터 출처: https://httpd.apache.org/security/vulnerabilities_24.html
#                   (2026-10-15 기준, 2.4.69 릴리스 반영)
#
#  사용법:  ./apache_precheck.sh            ← 옵션 없이 실행 (권장)
#    - 실행 중인 httpd 프로세스를 자동으로 찾아 실행파일·설정파일(-f/-d)을 따라갑니다.
#    - 인스턴스가 여러 개면 각각 점검하고 리포트를 따로 만듭니다.
#    - root 가 아니면 sudo 로 자동 재실행합니다(비밀번호를 물을 수 있음).
#  선택 옵션: [-b httpd경로] [-d 일수] [-l '로그경로']
#    -b : httpd 실행파일 경로 강제 지정 (Apache 가 꺼져 있어 자동 탐지가 안 될 때)
#    -d : "최근 변경 파일" 점검 기간(일). 기본 30
#    -l : 접근 로그 경로 직접 지정 (와일드카드 가능, 반드시 작은따옴표로 감쌀 것)
#         예: -l '/logs/apache/access_log*'   여러 개: -l '/logs/a/*access* /data/logs/*_log*'
# =====================================================================

HTTPD_BIN=""
RECENT_DAYS=30
LOG_PATHS=""
HTTPD_ARGS_STR=""
ORIG_ARGS=("$@")
while getopts "b:d:l:A:h" opt; do
  case "$opt" in
    b) HTTPD_BIN="$OPTARG" ;;
    A) HTTPD_ARGS_STR="$OPTARG" ;;   # 내부용: 인스턴스의 -f/-d/-D 인자
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

# --- 실행 중인 Apache 인스턴스 자동 탐지 ---------------------------------
# 출력 형식: 실행파일경로<US>인자(-f/-d/-D)<US>PID   (US=\x1f)
# ※ 구분자로 TAB 을 쓰면 인자가 비었을 때 read 가 연속 TAB 을 하나로 합쳐
#   PID 가 인자 자리로 밀려 들어감 → httpd 호출 실패(모듈 0개). 공백이 아닌 \x1f 사용.
detect_instances() {
  local pid ppid comm pcomm exe args
  ps -eo pid=,ppid=,comm= 2>/dev/null | awk '$3 ~ /^(httpd|apache2|httpd\.worker|httpd\.event|apache)$/' |
  while read -r pid ppid comm; do
    # 부모도 httpd 이면 워커 프로세스 → 건너뜀 (마스터만 사용)
    pcomm="$(ps -o comm= -p "$ppid" 2>/dev/null)"
    [[ "$pcomm" =~ ^(httpd|apache2|apache) ]] && continue
    exe="$(readlink /proc/"$pid"/exe 2>/dev/null)"; exe="${exe% (deleted)}"
    if [ -z "$exe" ] || [ ! -x "$exe" ]; then
      exe="$(tr '\0' '\n' < /proc/"$pid"/cmdline 2>/dev/null | head -n1)"
      [[ "$exe" != /* ]] && exe="$(command -v "$exe" 2>/dev/null)"
    fi
    [ -z "$exe" ] && continue
    # -f 설정파일 / -d ServerRoot / -D 정의 인자만 추출
    args="$(tr '\0' '\n' < /proc/"$pid"/cmdline 2>/dev/null | awk '
      NR==1 {next}
      want {printf "%s %s ", opt, $0; want=0; next}
      $0=="-f"||$0=="-d"||$0=="-D" {opt=$0; want=1; next}
      $0 ~ /^-[fdD]./ {printf "%s %s ", substr($0,1,2), substr($0,3)}')"
    printf '%s\x1f%s\x1f%s\n' "$exe" "${args% }" "$pid"
  done | sort -u -t$'\x1f' -k1,2
}

if [ -z "$HTTPD_BIN" ]; then
  INSTANCES="$(detect_instances)"
  N_INST=0; [ -n "$INSTANCES" ] && N_INST="$(printf '%s\n' "$INSTANCES" | wc -l)"
  if [ "$N_INST" -gt 1 ]; then
    echo "[안내] 실행 중인 Apache 인스턴스 ${N_INST}개를 찾았습니다. 각각 점검합니다."
    printf '%s\n' "$INSTANCES" | awk -F$'\x1f' '{printf "       - PID %s : %s %s\n", $3, $1, $2}'
    i=0
    while IFS=$'\x1f' read -r exe args pid; do
      i=$((i+1))
      echo ""; echo "################ 인스턴스 ${i}/${N_INST} (PID ${pid}) ################"
      PASS=(-b "$exe" -d "$RECENT_DAYS")
      [ -n "$args" ] && PASS+=(-A "$args")
      [ -n "$LOG_PATHS" ] && PASS+=(-l "$LOG_PATHS")
      PRECHECK_NO_SUDO=1 PRECHECK_PID="$pid" bash "$SELF" "${PASS[@]}" </dev/null
    done <<< "$INSTANCES"
    echo ""; echo "[안내] 전체 인스턴스 점검 완료. 리포트 파일 목록:"
    ls -1t /tmp/apache_precheck_*_pid*.txt 2>/dev/null | head -n "$N_INST" | sed 's/^/       /'
    exit 0
  elif [ "$N_INST" -eq 1 ]; then
    IFS=$'\x1f' read -r HTTPD_BIN HTTPD_ARGS_STR PRECHECK_PID <<< "$INSTANCES"
  fi
fi
# 인스턴스 실행 인자 → 배열 (모든 httpd 호출에 함께 전달)
read -ra HTTPD_ARGS <<< "$HTTPD_ARGS_STR"
# httpd 호출 래퍼: 실제 인스턴스와 같은 설정파일로 -M/-t 를 실행
hb() { "$HTTPD_BIN" "${HTTPD_ARGS[@]}" "$@"; }

TS="$(date +%Y%m%d_%H%M%S)"
REPORT="/tmp/apache_precheck_$(hostname -s 2>/dev/null || echo host)_${TS}${PRECHECK_PID:+_pid$PRECHECK_PID}.txt"
WORK="$(mktemp -d /tmp/apache_precheck.XXXXXX)"
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

: > "$REPORT"
log "Apache 패치 전 보안 사전 점검  |  호스트: $(hostname)  |  일시: $(date '+%F %T')"

if [ "$(id -u)" -ne 0 ]; then
  warn "root 권한이 아닙니다(sudo 없음). 로그/설정/프로세스 정보를 못 읽어 결과가 불완전할 수 있습니다."
fi

# =====================================================================
section "[1] 버전 및 설치 방식 확인"
# =====================================================================
[ -n "${PRECHECK_PID:-}" ] && info "실행 중인 Apache 프로세스 자동 탐지: 마스터 PID $PRECHECK_PID"
[ -n "$HTTPD_ARGS_STR" ] && info "인스턴스 실행 인자: $HTTPD_ARGS_STR"
if [ -z "$HTTPD_BIN" ]; then
  warn "실행 중인 httpd 프로세스를 찾지 못해 설치 경로에서 찾습니다. (Apache 가 꺼져 있거나 프로세스명이 다를 수 있음)"
  for c in httpd apache2 /usr/sbin/httpd /usr/sbin/apache2 /usr/local/apache2/bin/httpd /opt/apache2/bin/httpd /usr/local/httpd/bin/httpd; do
    if command -v "$c" >/dev/null 2>&1; then HTTPD_BIN="$(command -v "$c")"; break; fi
  done
fi
if [ -z "$HTTPD_BIN" ] || [ ! -x "$HTTPD_BIN" ]; then
  risk "httpd 실행파일을 찾지 못했습니다. Apache 를 기동한 상태에서 다시 실행하거나 -b 로 경로를 지정하세요. (예: -b /usr/local/apache2/bin/httpd)"
  exit 1
fi

# Debian/Ubuntu 의 apache2 는 환경변수 파일이 필요함
if [ "$(basename "$HTTPD_BIN")" = "apache2" ] && [ -f /etc/apache2/envvars ]; then
  # shellcheck disable=SC1091
  . /etc/apache2/envvars
fi

VER_LINE="$("$HTTPD_BIN" -v 2>/dev/null | head -n1)"
VER="$(printf '%s' "$VER_LINE" | grep -oE 'Apache/[0-9]+\.[0-9]+\.[0-9]+' | cut -d/ -f2)"
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
SERVER_IPS="$(server_ips)"
info "서버 IP: ${SERVER_IPS:-확인 불가}"
info "실행파일: $HTTPD_BIN"
info "버전 정보: ${VER_LINE:-확인 불가}"

if [ -z "$VER" ]; then
  risk "버전을 해석하지 못했습니다. 수동 확인이 필요합니다."
  exit 1
fi
case "$VER" in
  2.2.*|2.0.*|1.*) risk "Apache $VER 은(는) 공식 EOL 버전입니다. 보안 패치가 더 이상 나오지 않으므로 교체 외의 근본 대책이 없습니다." ;;
esac
if ver_le "2.4.69" "$VER"; then
  ok "Apache $VER : 2.4.69 이상입니다. (이 스크립트의 CVE 목록 기준 수정 완료)"
else
  risk "Apache $VER : 2.4.69 미만입니다. 아래 [2]에서 해당 CVE를 확인하세요."
fi

# 설치 방식 (패키지라면 버전 숫자와 실제 보안수정 반영 여부가 다를 수 있음)
PKG_TYPE="source"; CHANGELOG="$WORK/changelog.txt"; : > "$CHANGELOG"
if command -v rpm >/dev/null 2>&1 && rpm -qf "$HTTPD_BIN" >/dev/null 2>&1; then
  PKG_TYPE="rpm"
  PKG_NAME="$(rpm -qf "$HTTPD_BIN")"
  rpm -q --changelog "$(rpm -qf --qf '%{NAME}' "$HTTPD_BIN")" > "$CHANGELOG" 2>/dev/null
  info "설치 방식: RPM 패키지 ($PKG_NAME)"
  warn "패키지 설치본은 버전 숫자가 낮아도 배포판이 보안수정을 백포트했을 수 있습니다. [2]에서 changelog 반영 여부를 함께 표시합니다."
elif command -v dpkg >/dev/null 2>&1 && dpkg -S "$HTTPD_BIN" >/dev/null 2>&1; then
  PKG_TYPE="deb"
  PKG_NAME="$(dpkg -S "$HTTPD_BIN" 2>/dev/null | cut -d: -f1 | head -n1)"
  for f in /usr/share/doc/apache2/changelog.Debian.gz /usr/share/doc/apache2-bin/changelog.Debian.gz; do
    [ -f "$f" ] && zcat "$f" >> "$CHANGELOG" 2>/dev/null
  done
  info "설치 방식: DEB 패키지 ($PKG_NAME)"
  warn "패키지 설치본은 배포판 백포트 여부를 함께 확인해야 합니다. [2]에서 changelog 반영 여부를 표시합니다."
else
  info "설치 방식: 소스 설치(또는 패키지 정보 없음) → 버전 숫자 기준으로 판정합니다."
fi

# 모듈 목록
MODS="$WORK/modules.txt"
hb -M 2>/dev/null | awk '/_module/ {print $1}' | sort -u > "$MODS"
info "로드된 모듈 수: $(wc -l < "$MODS")"
detail "$(tr '\n' ' ' < "$MODS")"

has_mod() { grep -qx "$1" "$MODS"; }

# 조건식: "a,b" = a 또는 b,  "a&b" = a 그리고 b,  "core" = 항상 해당
cond_match() {
  local cond="$1" term t all
  [ "$cond" = "core" ] && return 0
  IFS=',' read -ra OR_TERMS <<< "$cond"
  for term in "${OR_TERMS[@]}"; do
    all=1
    IFS='&' read -ra AND_TERMS <<< "$term"
    for t in "${AND_TERMS[@]}"; do has_mod "$t" || all=0; done
    [ "$all" -eq 1 ] && return 0
  done
  return 1
}

# =====================================================================
section "[2] 버전 구간별 해당 CVE 판정 (2.4.x)"
# =====================================================================
# 형식: CVE|최소영향버전|최대영향버전|등급|조건모듈|설명
CVE_DB="$WORK/cve.txt"
cat > "$CVE_DB" <<'EOF'
CVE-2019-0211|2.4.17|2.4.38|important|core|MPM 스코어보드 조작으로 자식 프로세스 코드가 부모(root) 권한으로 실행 가능
CVE-2021-40438|2.4.0|2.4.48|important|proxy_module|mod_proxy SSRF - 공격자가 고른 서버로 요청 전달
CVE-2021-41773|2.4.49|2.4.49|critical|core|경로 탐색/파일 노출, CGI 켜져 있으면 원격코드실행 (실제 공격 확인)
CVE-2021-42013|2.4.49|2.4.50|critical|core|CVE-2021-41773 불완전 수정 - 경로 탐색/원격코드실행
CVE-2021-44224|2.4.7|2.4.51|moderate|proxy_module|포워드 프록시(ProxyRequests On) 크래시/SSRF
CVE-2021-44790|2.4.0|2.4.51|important|lua_module|mod_lua multipart 파서 버퍼 오버플로
CVE-2022-22720|2.4.0|2.4.52|important|core|요청 본문 폐기 오류 시 연결 미종료 → HTTP 요청 스머글링
CVE-2022-23943|2.4.0|2.4.52|important|sed_module|mod_sed 힙 메모리 덮어쓰기
CVE-2023-25690|2.4.0|2.4.55|important|proxy_module&rewrite_module|mod_proxy+RewriteRule/ProxyPassMatch 조합 요청 스머글링
CVE-2024-38474|2.4.0|2.4.59|important|rewrite_module|mod_rewrite 인코딩된 ? 처리로 스크립트 실행/소스 노출
CVE-2024-38475|2.4.0|2.4.59|important|rewrite_module|mod_rewrite 치환 시 의도치 않은 파일 매핑 → 코드실행/소스 노출
CVE-2024-38476|2.4.0|2.4.59|important|core|악성 백엔드 응답 헤더로 정보노출/SSRF/로컬 스크립트 실행
CVE-2024-38477|2.4.0|2.4.59|important|proxy_module|악성 요청으로 mod_proxy 크래시(DoS)
CVE-2024-39884|2.4.60|2.4.60|important|core|AddType 핸들러 설정 시 소스코드 노출(PHP 등)
CVE-2024-40725|2.4.60|2.4.61|important|core|AddType 핸들러 설정 시 소스코드 노출(불완전 수정)
CVE-2025-23048|2.4.35|2.4.63|moderate|ssl_module|TLS1.3 세션 재개로 가상호스트 간 클라이언트인증 우회
CVE-2025-49812|2.4.0|2.4.63|moderate|ssl_module|SSLEngine optional 사용 시 TLS 업그레이드 세션 탈취
CVE-2025-58098|2.4.0|2.4.65|moderate|cgid_module&include_module|SSI + mod_cgid 시 쿼리스트링이 #exec cmd 로 전달
CVE-2026-23918|2.4.66|2.4.66|important|http2_module|HTTP/2 double free, 원격코드실행 가능
CVE-2026-24072|2.4.0|2.4.66|moderate|core|.htaccess 작성자가 httpd 권한으로 파일 읽기(권한상승)
CVE-2026-28780|2.4.0|2.4.66|low|proxy_ajp_module|악성 AJP 백엔드에 의한 힙 오버플로
CVE-2026-29169|2.4.0|2.4.66|low|dav_lock_module|mod_dav_lock NULL 역참조 크래시 (모듈 제거로 완화 가능)
CVE-2026-33006|2.4.0|2.4.66|moderate|auth_digest_module|Digest 인증 타이밍 공격으로 인증 우회
CVE-2026-34355|2.4.0|2.4.67|moderate|proxy_html_module|악성 백엔드에 의한 mod_proxy_html 버퍼 오버플로
CVE-2026-42535|2.4.0|2.4.67|moderate|dav_fs_module|mod_dav_fs 경로 처리 - DAV 속성DB 조작/크래시
CVE-2026-43951|2.4.0|2.4.67|moderate|headers_module&mime_module|응답 헤더 병합 OOB Read 크래시
CVE-2026-44119|2.4.0|2.4.67|moderate|core|.htaccess 표현식으로 httpd 권한 파일 읽기(권한상승)
CVE-2026-44186|2.4.0|2.4.67|moderate|proxy_ftp_module|악성 FTP 백엔드에 의한 무한루프 DoS
CVE-2026-49975|2.4.17|2.4.67|moderate|http2_module|HTTP/2 과도한 메모리 할당 DoS
CVE-2026-42356|2.4.60|2.4.68|low|cgi_module,cgid_module|CGI 내부 리다이렉트 대상이 CGI로 실행되는 제한적 RCE
CVE-2026-42528|2.4.0|2.4.68|moderate|dav_module|WebDAV 공유 잠금 오버플로 - 자식 프로세스 크래시
CVE-2026-57941|2.4.17|2.4.68|moderate|http2_module|mod_http2 use-after-free / wild write
CVE-2026-63045|2.4.0|2.4.68|low|proxy_ftp_module|포워드 프록시에서 FTP PASV 응답으로 제3 호스트 연결
CVE-2026-63292|2.4.0|2.4.68|moderate|vhost_alias_module|Host 헤더 8192바이트 초과 시 스택 오버플로(LimitRequestFieldSize 상향 시)
CVE-2026-63718|2.4.30|2.4.68|low|proxy_uwsgi_module|mod_proxy_uwsgi 응답 스머글링
CVE-2026-73637|2.4.0|2.4.68|low|auth_digest_module|Digest 인증 동시요청 시 인증상태 손상
CVE-2026-79768|2.4.0|2.4.68|low|userdir_module|mod_userdir 정보 노출
CVE-2026-93546|2.4.0|2.4.68|moderate|dav_fs_module|PROPPATCH 네임스페이스 정수 오버플로 - 크래시/속성DB 손상
EOF

if [[ "$VER" != 2.4.* ]]; then
  info "2.4.x 가 아니므로 CVE 표 판정을 건너뜁니다."
else
  N_APPLY=0; N_SKIP=0
  while IFS='|' read -r cve vmin vmax sev cond desc; do
    [ -z "$cve" ] && continue
    ver_le "$vmin" "$VER" && ver_le "$VER" "$vmax" || continue
    if ! cond_match "$cond"; then
      N_SKIP=$((N_SKIP+1))
      printf '[미해당] %s (%s) - 필요 모듈(%s) 미사용\n' "$cve" "$sev" "$cond" >> "$REPORT"
      continue
    fi
    N_APPLY=$((N_APPLY+1))
    bp=""
    if [ "$PKG_TYPE" != "source" ] && grep -q "$cve" "$CHANGELOG"; then
      bp=" → 패키지 changelog에 수정 기록 있음(백포트 반영 추정)"
    fi
    msg="$cve [$sev] $desc (영향: $vmin~$vmax, 조건: $cond)$bp"
    if [ -n "$bp" ]; then info "$msg"
    else
      case "$sev" in
        critical|important) risk "$msg" ;;
        moderate)           warn "$msg" ;;
        *)                  info "$msg" ;;
      esac
    fi
  done < "$CVE_DB"
  log ""
  log "  → 해당 CVE: ${N_APPLY}건 / 모듈 미사용으로 미해당: ${N_SKIP}건 (미해당 목록은 리포트 파일에 기록)"
fi

# =====================================================================
section "[3] 위험 설정 점검 (실제로 Include 된 설정 파일만)"
# =====================================================================
CONF_LIST="$WORK/conf_files.txt"; : > "$CONF_LIST"

# 설정 파일 1개에서 "실제로 적용되는" 줄만 골라냄 (주석·빈 줄 제외, 꺼진 <IfModule>/<IfDefine> 블록 제외)
# 출력: L<TAB>파일:줄:내용 / I<TAB>Include 경로 / S<TAB>제외된 줄 수(마지막 1줄)
conf_active() {
  awk -v F="$1" -v MODS="$(tr '\n' ' ' < "$MODS")" -v DEFS="$DEFINES" '
    function modok(x,   neg, name, r) {
      neg = 0; if (substr(x, 1, 1) == "!") { neg = 1; x = substr(x, 2) }
      if (nm == 0) return 1                              # 모듈 목록을 모르면 켜진 것으로 간주
      name = x
      if (name ~ /^mod_.*\.c$/) { sub(/^mod_/, "", name); sub(/\.c$/, "", name); name = name "_module" }
      else if (name ~ /\.c$/) return 1                   # core.c, prefork.c 등 판별 불가 → 켜짐
      r = (name in mod) ? 1 : 0
      return neg ? !r : r
    }
    function defok(x,   neg, r) {
      neg = 0; if (substr(x, 1, 1) == "!") { neg = 1; x = substr(x, 2) }
      r = (x in def) ? 1 : 0
      return neg ? !r : r
    }
    BEGIN {
      nm = split(MODS, m, " "); for (i = 1; i <= nm; i++) mod[m[i]] = 1
      nd = split(DEFS, d, " "); for (i = 1; i <= nd; i++) def[d[i]] = 1
      depth = 0; act[0] = 1; skipped = 0
    }
    {
      l = $0; sub(/^[ \t]+/, "", l); sub(/[ \t\r]+$/, "", l)
      if (l == "" || l ~ /^#/) next
      low = tolower(l)
      if (low ~ /^<if(module|define|version|file|directive|section)[ \t>]/) {
        arg = l; sub(/^<[^ \t>]+[ \t]*/, "", arg); sub(/>$/, "", arg); gsub(/"/, "", arg)
        ok = 1
        if (low ~ /^<ifmodule/) ok = modok(arg)
        else if (low ~ /^<ifdefine/) ok = defok(arg)
        depth++; act[depth] = (act[depth - 1] && ok) ? 1 : 0
        next
      }
      if (low ~ /^<\/if(module|define|version|file|directive|section)[ \t]*>/) { if (depth > 0) depth--; next }
      if (!act[depth]) { skipped++; next }
      if (low ~ /^include(optional)?[ \t]/) { a = l; sub(/^[^ \t]+[ \t]+/, "", a); gsub(/"/, "", a); print "I\t" a }
      print "L\t" F ":" NR ":" l
    }
    END { print "S\t" skipped }' "$1" 2>/dev/null
}

# ${APACHE_LOG_DIR} 같은 환경변수 치환
expand_vars() {
  local p="$1" v pat
  while [[ "$p" =~ \$\{([A-Za-z_][A-Za-z0-9_]*)\} ]]; do
    v="${BASH_REMATCH[1]}"; pat="\${$v}"; p="${p//"$pat"/${!v:-}}"
  done
  printf '%s' "$p"
}

# 메인 설정 파일에서 시작해 (주석이 아니고 켜진 블록 안의) Include/IncludeOptional 을 따라가며 파일 목록 작성
resolve_includes() {
  local queue=("$1") f pat p x seen="$WORK/seen.txt"
  : > "$seen"
  while [ ${#queue[@]} -gt 0 ]; do
    f="${queue[0]}"; queue=("${queue[@]:1}")
    [ -r "$f" ] || continue
    grep -qxF -- "$f" "$seen" && continue
    printf '%s\n' "$f" >> "$seen"
    while IFS= read -r pat; do
      pat="$(expand_vars "$pat")"
      [[ "$pat" != /* ]] && pat="$SROOT/$pat"
      while IFS= read -r p; do
        if [ -d "$p" ]; then
          while IFS= read -r x; do queue+=("$x"); done < <(find "$p" -type f 2>/dev/null | sort)
        elif [ -f "$p" ]; then
          queue+=("$p")
        fi
      done < <(compgen -G "$pat" | sort)
    done < <(conf_active "$f" | awk -F'\t' '$1 == "I" { print $2 }')
  done
  cat "$seen"
}

# 메인 설정 파일과 ServerRoot: 실행 인자(-f/-d) > 컴파일 기본값, ServerRoot 지시자가 있으면 그것이 우선
ROOT0="$("$HTTPD_BIN" -V 2>/dev/null | sed -n 's/.*HTTPD_ROOT="\(.*\)"/\1/p')"
CFG="$("$HTTPD_BIN" -V 2>/dev/null | sed -n 's/.*SERVER_CONFIG_FILE="\(.*\)"/\1/p')"
DEFINES=""
for ((k=0; k<${#HTTPD_ARGS[@]}; k++)); do
  [ "${HTTPD_ARGS[$k]}" = "-d" ] && ROOT0="${HTTPD_ARGS[$((k+1))]}"
  [ "${HTTPD_ARGS[$k]}" = "-f" ] && CFG="${HTTPD_ARGS[$((k+1))]}"
  [ "${HTTPD_ARGS[$k]}" = "-D" ] && DEFINES="$DEFINES ${HTTPD_ARGS[$((k+1))]}"
done
[[ -n "$CFG" && "$CFG" != /* ]] && CFG="$ROOT0/$CFG"
SROOT="$ROOT0"
if [ -r "$CFG" ]; then
  SR="$(conf_active "$CFG" | awk -F'\t' '$1 == "L"' | sed -n 's/^L\t[^:]*:[0-9]*:[Ss][Ee][Rr][Vv][Ee][Rr][Rr][Oo][Oo][Tt][ \t]\+//p' | head -n1 | tr -d '"')"
  [ -n "$SR" ] && SROOT="$(expand_vars "$SR")"
fi

# 1순위: httpd 가 직접 알려 주는 "실제로 읽는 설정 파일" 목록
DUMP_ERR="$WORK/dump.err"
if [ -z "${PRECHECK_TEST_NO_DUMP:-}" ]; then
  hb -t -D DUMP_INCLUDES 2>"$DUMP_ERR" | sed -n 's/^[ \t]*([0-9*]*)[ \t]*\(\/.*\)$/\1/p' | awk '!seen[$0]++' > "$CONF_LIST"
else
  echo "테스트용으로 DUMP_INCLUDES 사용 안 함" > "$DUMP_ERR"
fi
if [ -s "$CONF_LIST" ]; then
  info "설정 파일 목록 확인 방법: httpd -t -D DUMP_INCLUDES (httpd 가 실제로 읽는 파일)"
else
  # 2순위: httpd.conf 의 Include/IncludeOptional 을 직접 따라감 (예전처럼 폴더의 *.conf 를 전부 점검하지 않음)
  REASON="$(grep -v '^Syntax OK' "$DUMP_ERR" 2>/dev/null | head -n1 | cut -c1-200)"
  if [ -r "$CFG" ]; then
    resolve_includes "$CFG" > "$CONF_LIST"
    info "설정 파일 목록 확인 방법: 메인 설정($CFG)의 Include/IncludeOptional 직접 추적 (DUMP_INCLUDES 실패: ${REASON:-출력 없음})"
  else
    warn "메인 설정 파일을 찾지 못해 설정 점검을 할 수 없습니다: ${CFG:-(알 수 없음)} (DUMP_INCLUDES 실패: ${REASON:-출력 없음})"
  fi
fi
info "메인 설정 파일: ${CFG:-확인 불가}"
[ -s "$MODS" ] || warn "모듈 목록을 확인하지 못해 <IfModule> 조건을 모두 '켜짐'으로 간주했습니다. (설정 점검 결과가 실제보다 많을 수 있음)"
info "점검 대상 설정 파일 수: $(wc -l < "$CONF_LIST")"
head -n 100 "$CONF_LIST" | while IFS= read -r f; do detail "$f"; done
[ "$(wc -l < "$CONF_LIST")" -gt 100 ] && detail "... (100개까지만 표시)"

# 적용되는 설정 줄 통합본 (파일명:줄번호:내용) — 주석·빈 줄, 꺼진 <IfModule>/<IfDefine> 블록 제외
ALLCONF="$WORK/all.conf"; : > "$ALLCONF"
SKIPPED=0
while IFS= read -r f; do
  [ -r "$f" ] || continue
  conf_active "$f" > "$WORK/active.txt"
  awk -F'\t' '$1 == "L" { sub(/^L\t/, ""); print }' "$WORK/active.txt" >> "$ALLCONF"
  n="$(awk -F'\t' '$1 == "S" { print $2 }' "$WORK/active.txt")"
  SKIPPED=$((SKIPPED + ${n:-0}))
done < "$CONF_LIST"
[ "$SKIPPED" -gt 0 ] && info "꺼진 <IfModule>/<IfDefine> 블록 안의 설정 ${SKIPPED}줄은 실제로 적용되지 않으므로 점검에서 제외했습니다."
cfg_grep() { grep -iE "$1" "$ALLCONF"; }
show() { while IFS= read -r line; do detail "$line"; done; }

# 3-1 Directory / 에 Require all granted
ROOTDIR="$(awk -F: 'BEGIN{IGNORECASE=1} { c=$0; sub(/^[^:]*:[^:]*:/,"",c) }
  tolower(c) ~ /^<directory[ \t]+"?\/"?[ \t]*>/ {inb=1; next}
  inb && tolower(c) ~ /^<\/directory>/ {inb=0}
  inb && tolower(c) ~ /require[ \t]+all[ \t]+granted/ {print $0}' "$ALLCONF")"
if [ -n "$ROOTDIR" ]; then
  risk "<Directory /> 에 Require all granted 설정 → 경로 탐색 시 파일시스템 전체 노출 위험"
  printf '%s\n' "$ROOTDIR" | show
else
  ok "<Directory /> 에 Require all granted 없음"
fi

# 3-2 Protocols h2
H2="$(cfg_grep '^[^:]*:[0-9]+:Protocols .*h2')"
if [ -n "$H2" ] && has_mod http2_module; then
  warn "HTTP/2 활성화됨 → HTTP/2 계열 CVE 해당. 불필요하면 'Protocols http/1.1' 로 변경 검토"
  printf '%s\n' "$H2" | show
elif has_mod http2_module; then
  info "http2_module 은 로드되었으나 Protocols 에 h2 설정은 없음 (모듈 언로드 시 더 안전)"
else
  ok "HTTP/2 미사용"
fi

# 3-3 ProxyRequests On (포워드 프록시)
PR="$(cfg_grep ':ProxyRequests[ \t]+On')"
if [ -n "$PR" ]; then
  risk "ProxyRequests On (포워드 프록시) → SSRF/오픈 프록시 위험"
  printf '%s\n' "$PR" | show
else
  ok "ProxyRequests On 없음"
fi

# 3-4 AllowOverride
AO="$(cfg_grep ':AllowOverride' | grep -viE 'AllowOverride[ \t]+None')"
if [ -n "$AO" ]; then
  warn ".htaccess 허용(AllowOverride None 아님) → .htaccess 권한상승 계열 CVE 해당. 미사용 시 None 권장"
  printf '%s\n' "$AO" | show
else
  ok "AllowOverride 는 모두 None (또는 미설정)"
fi

# 3-5 ServerTokens / ServerSignature
ST="$(cfg_grep ':ServerTokens' | tail -n1)"
if printf '%s' "$ST" | grep -qiE 'ServerTokens[ \t]+(Prod|ProductOnly)'; then
  ok "ServerTokens Prod (버전 정보 비노출)"
else
  warn "ServerTokens 가 Prod 가 아님(미설정 시 기본값 Full) → 응답 헤더로 버전 노출. 'ServerTokens Prod' 권장"
  [ -n "$ST" ] && detail "$ST"
fi
SS="$(cfg_grep ':ServerSignature[ \t]+(On|EMail)')"
if [ -n "$SS" ]; then warn "ServerSignature On → 에러 페이지에 버전 노출"; printf '%s\n' "$SS" | show
else ok "ServerSignature On 없음"; fi

# 3-6 디렉터리 리스팅
IDX="$(cfg_grep ':Options[ \t]' | grep -iE '[ \t]\+?Indexes' | grep -viE '\-Indexes')"
if [ -n "$IDX" ]; then warn "Options Indexes → 디렉터리 목록 노출"; printf '%s\n' "$IDX" | show
else ok "Options Indexes 없음"; fi

# 3-7 TraceEnable
if cfg_grep ':TraceEnable[ \t]+Off' >/dev/null; then ok "TraceEnable Off"
else warn "TraceEnable Off 설정 없음 → TRACE 메서드 허용 가능"; fi

# 3-8 SSLEngine optional
SO="$(cfg_grep ':SSLEngine[ \t]+optional')"
if [ -n "$SO" ]; then risk "SSLEngine optional → CVE-2025-49812(TLS 업그레이드 세션 탈취) 조건 충족"; printf '%s\n' "$SO" | show
else ok "SSLEngine optional 없음"; fi

# 3-9 LimitRequestFieldSize 상향 (+ vhost_alias)
LRF="$(cfg_grep ':LimitRequestFieldSize[ \t]+[0-9]+' | awk '{v=$NF+0; if (v>8190) print}')"
if [ -n "$LRF" ]; then
  if has_mod vhost_alias_module; then risk "LimitRequestFieldSize 상향 + vhost_alias_module → CVE-2026-63292 조건 충족"
  else warn "LimitRequestFieldSize 가 기본값(8190)보다 큼"; fi
  printf '%s\n' "$LRF" | show
else ok "LimitRequestFieldSize 기본값 유지"; fi

# 3-10 실행 계정
RUN_USER="$(cfg_grep ':User[ \t]+' | tail -n1 | awk '{print $NF}' | tr -d '"')"
if printf '%s' "$RUN_USER" | grep -q '^\$'; then   # ${APACHE_RUN_USER} 같은 변수
  v="${RUN_USER#\$}"; v="${v#\{}"; v="${v%\}}"; RUN_USER="${!v:-}"
fi
[ -z "$RUN_USER" ] && RUN_USER="$(ps -eo user=,comm= | awk '$2 ~ /httpd|apache2/ && $1!="root"{print $1; exit}')"
if [ "$RUN_USER" = "root" ]; then risk "워커 실행 계정이 root"
elif [ -n "$RUN_USER" ]; then ok "워커 실행 계정: $RUN_USER"
else warn "워커 실행 계정을 확인하지 못함"; fi

# 3-11 클라이언트 인증서 + SSLStrictSNIVHostCheck
if cfg_grep ':SSLVerifyClient[ \t]+require' >/dev/null && ! cfg_grep ':SSLStrictSNIVHostCheck[ \t]+On' >/dev/null; then
  warn "클라이언트 인증서 사용 중이나 SSLStrictSNIVHostCheck On 없음 → CVE-2025-23048 조건 검토 필요"
fi

# 3-12 Digest 인증 위험 설정
if cfg_grep ':AuthDigestNonceLifetime[ \t]+0' >/dev/null; then
  warn "AuthDigestNonceLifetime 0 → mod_auth_digest 재전송/DoS 계열 조건 충족"
fi

# 3-13 불필요 가능성이 높은 모듈
for m in dav_module dav_fs_module dav_lock_module userdir_module proxy_ftp_module lua_module sed_module proxy_uwsgi_module status_module info_module autoindex_module; do
  has_mod "$m" && info "로드됨: $m → 실제 사용 여부 확인 후 미사용이면 비활성화 검토"
done
if has_mod status_module || has_mod info_module; then
  SI="$(cfg_grep 'SetHandler[ \t]+(server-status|server-info)')"
  [ -n "$SI" ] && { warn "server-status/server-info 핸들러 설정됨 → 접근제어(Require ip) 확인 필요"; printf '%s\n' "$SI" | show; }
fi

# =====================================================================
section "[4] 침해 흔적 점검 (이미 해킹당했는지)"
# =====================================================================
# 4-1 접근 로그 수집
LOGS="$WORK/logs.txt"; : > "$LOGS"
HROOT="$("$HTTPD_BIN" -V 2>/dev/null | sed -n 's/.*HTTPD_ROOT="\(.*\)"/\1/p')"
for ((k=0; k<${#HTTPD_ARGS[@]}; k++)); do [ "${HTTPD_ARGS[$k]}" = "-d" ] && HROOT="${HTTPD_ARGS[$((k+1))]}"; done

# 경로 문자열 → 실제 파일 목록 (회전된 파일 포함)
add_log_path() {
  local p="$1" v pat
  # ${APACHE_LOG_DIR} 같은 환경변수 치환
  while [[ "$p" =~ \$\{([A-Za-z_][A-Za-z0-9_]*)\} ]]; do
    v="${BASH_REMATCH[1]}"; pat="\${$v}"; p="${p//"$pat"/${!v:-}}"
  done
  # rotatelogs/cronolog 날짜 형식(%Y%m%d 등) → 와일드카드
  p="$(printf '%s' "$p" | sed 's/%[A-Za-z]/*/g')"
  [[ "$p" != /* ]] && p="$HROOT/$p"
  # shellcheck disable=SC2086
  ls -d -- $p* 2>/dev/null
}

if [ -n "$LOG_PATHS" ]; then
  # -l 옵션으로 직접 지정한 경우
  for p in $LOG_PATHS; do
    # shellcheck disable=SC2086
    ls -d -- $p 2>/dev/null
  done >> "$LOGS"
  info "접근 로그 경로를 -l 옵션 값으로 사용: $LOG_PATHS"
else
  # (a) 설정 파일의 CustomLog / TransferLog (파이프 로그 rotatelogs·cronolog 포함)
  cfg_grep ':(CustomLog|TransferLog)[ \t]' | sed -E 's/^[^:]*:[0-9]+:[A-Za-z]+[ \t]+//' > "$WORK/logdirs.txt"
  while IFS= read -r rest; do
    if [[ "$rest" =~ ^\"?\| ]]; then
      # 예: "|/usr/sbin/rotatelogs -l /logs/access_%Y%m%d.log 86400"  → 프로그램 뒤 첫 번째 경로
      arg="$(printf '%s' "$rest" | tr -d '"|' | awk '{for(i=2;i<=NF;i++) if ($i ~ /\//) {print $i; exit}}')"
    else
      arg="$(printf '%s' "$rest" | awk '{print $1}' | tr -d '"')"
    fi
    [[ -z "$arg" || "$arg" == syslog* ]] && continue
    add_log_path "$arg"
  done < "$WORK/logdirs.txt" >> "$LOGS"

  # (b) 실행 중인 httpd/rotatelogs 가 실제로 열고 있는 로그 파일 (/proc 기준, root 권한 필요)
  for name in httpd apache2 rotatelogs cronolog; do pgrep -x "$name" 2>/dev/null; done | sort -u | while read -r pid; do
    for fd in /proc/"$pid"/fd/*; do readlink "$fd" 2>/dev/null; done
  done | grep -E '^/' | grep -iE 'log' | grep -vE '^/(dev|proc)/|\(deleted\)$' | sort -u | while read -r f; do
    [ -f "$f" ] || continue
    echo "$f"
    find "$(dirname "$f")" -maxdepth 1 -type f -name '*access*' 2>/dev/null
  done >> "$LOGS"

  # (c) 배포판 기본 경로
  for d in /var/log/httpd /var/log/apache2 /usr/local/apache2/logs /opt/apache2/logs; do
    [ -d "$d" ] && find "$d" -type f \( -name '*access*' -o -name '*ssl_request*' \) 2>/dev/null
  done >> "$LOGS"
fi
# 정규 파일만, 에러 로그·작업 디렉터리 제외
sort -u "$LOGS" | while read -r f; do
  [ -f "$f" ] || continue
  [[ "$f" == "$WORK"* || "$f" == "$REPORT" ]] && continue
  case "$(basename "$f")" in *error*|*.pid) continue ;; esac
  echo "$f"
done > "$WORK/logs2.txt"
mv "$WORK/logs2.txt" "$LOGS"

if [ ! -s "$LOGS" ]; then
  warn "접근 로그 파일을 찾지 못했습니다. 로그 기반 점검을 건너뜁니다."
  detail "→ 로그 위치 확인 후 -l 옵션으로 지정하세요. 예: sudo bash $0 -l '/logs/apache/access_log*'"
  detail "→ 위치 확인 명령: sudo ls -l /proc/\$(pgrep -o -x httpd)/fd | grep -i log"
else
  info "점검 대상 접근 로그: $(wc -l < "$LOGS")개 (회전된 .gz 포함)"
  head -n 10 "$LOGS" | show
  [ "$(wc -l < "$LOGS")" -gt 10 ] && detail "... (전체 목록은 리포트 파일 참고)"
  sed 's/^/        /' "$LOGS" | tail -n +11 >> "$REPORT"
  zg() { while read -r f; do zgrep -hE "$1" "$f" 2>/dev/null; done < "$LOGS"; }

  # 경로 탐색 (CVE-2021-41773/42013 등)
  zg '(\.%2e|%2e\.|%2e%2e|%252e|\.\./|\.\.%2f)' > "$WORK/trav.txt"
  T_ALL=$(wc -l < "$WORK/trav.txt")
  T_200=$(grep -cE '" 200 ' "$WORK/trav.txt")
  if [ "$T_200" -gt 0 ]; then
    risk "경로 탐색 시도 중 200(성공) 응답 ${T_200}건 → 침해 가능성. 즉시 상세 분석 필요"
    grep -E '" 200 ' "$WORK/trav.txt" | head -n 5 | show
  elif [ "$T_ALL" -gt 0 ]; then
    warn "경로 탐색 시도 ${T_ALL}건 (성공 응답 없음) → 스캔 대상이 되고 있음"
  else
    ok "경로 탐색 시도 흔적 없음"
  fi

  # 웹쉘/명령실행 의심 요청
  zg '(cmd=|exec=|shell=|passthru|system\(|base64_decode|/bin/(ba)?sh|wget(%20|\+)|curl(%20|\+)|whoami|/etc/passwd|uname(%20|\+)-a)' > "$WORK/shell.txt"
  S_200=$(grep -cE '" 200 ' "$WORK/shell.txt")
  if [ "$S_200" -gt 0 ]; then
    risk "명령실행/웹쉘 의심 요청 중 200 응답 ${S_200}건"
    grep -E '" 200 ' "$WORK/shell.txt" | head -n 5 | show
  elif [ -s "$WORK/shell.txt" ]; then
    warn "명령실행/웹쉘 의심 요청 $(wc -l < "$WORK/shell.txt")건 (성공 응답 없음)"
  else
    ok "명령실행/웹쉘 의심 요청 흔적 없음"
  fi

  # 의심 요청을 많이 보낸 IP 상위 5
  cat "$WORK/trav.txt" "$WORK/shell.txt" | awk '{print $1}' | sort | uniq -c | sort -rn | head -n 5 > "$WORK/topip.txt"
  [ -s "$WORK/topip.txt" ] && { info "의심 요청 상위 IP (차단 검토용)"; show < "$WORK/topip.txt"; }
fi

# 4-2 DocumentRoot 수집
DOCROOTS="$WORK/docroots.txt"
cfg_grep ':DocumentRoot[ \t]' | awk '{print $2}' | tr -d '"' | sort -u | while read -r d; do [ -d "$d" ] && echo "$d"; done > "$DOCROOTS"
if [ ! -s "$DOCROOTS" ]; then
  warn "DocumentRoot 를 찾지 못했습니다. 파일 기반 점검을 건너뜁니다."
else
  info "점검 대상 DocumentRoot: $(tr '\n' ' ' < "$DOCROOTS")"
  EXT='\( -name "*.php" -o -name "*.php[0-9]" -o -name "*.phtml" -o -name "*.jsp" -o -name "*.jspx" -o -name "*.asp" -o -name "*.aspx" -o -name "*.cgi" -o -name "*.pl" -o -name "*.py" -o -name "*.sh" \)'

  # 웹쉘 의심 코드 패턴
  : > "$WORK/ws.txt"
  while read -r d; do
    eval find "\"$d\"" -type f "$EXT" -print0 2>/dev/null | \
      xargs -0 -r grep -lE 'eval\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)|assert\s*\(\s*\$_(POST|GET|REQUEST)|(shell_exec|passthru|proc_open|popen)\s*\(|system\s*\(\s*\$_|Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder|WScript\.Shell' 2>/dev/null >> "$WORK/ws.txt"
  done < "$DOCROOTS"
  if [ -s "$WORK/ws.txt" ]; then
    risk "웹쉘 의심 코드 패턴 포함 파일 $(wc -l < "$WORK/ws.txt")개 (오탐 가능, 내용 확인 필수)"
    head -n 20 "$WORK/ws.txt" | show
  else
    ok "웹쉘 의심 코드 패턴 파일 없음 (패턴 우회형 웹쉘은 탐지 못함 → KISA 휘슬 병행 권장)"
  fi

  # 최근 변경된 스크립트 파일
  : > "$WORK/recent.txt"
  while read -r d; do
    eval find "\"$d\"" -type f "$EXT" -mtime "-$RECENT_DAYS" 2>/dev/null >> "$WORK/recent.txt"
  done < "$DOCROOTS"
  if [ -s "$WORK/recent.txt" ]; then
    warn "최근 ${RECENT_DAYS}일 내 변경된 스크립트 파일 $(wc -l < "$WORK/recent.txt")개 → 배포 이력과 대조 필요"
    head -n 20 "$WORK/recent.txt" | while read -r f; do detail "$(ls -l --time-style=+%F_%T "$f" 2>/dev/null)"; done
  else
    ok "최근 ${RECENT_DAYS}일 내 변경된 스크립트 파일 없음"
  fi

  # 웹 실행 계정이 쓸 수 있는 파일 (웹쉘 업로드/변조 통로)
  if [ -n "$RUN_USER" ] && id "$RUN_USER" >/dev/null 2>&1; then
    W=$(while read -r d; do find "$d" -user "$RUN_USER" 2>/dev/null; done < "$DOCROOTS" | wc -l)
    if [ "$W" -gt 0 ]; then warn "DocumentRoot 내 웹 실행계정($RUN_USER) 소유 파일/디렉터리 ${W}개 → 업로드 경로 외에는 소유권 회수 검토"
    else ok "DocumentRoot 내 웹 실행계정 소유 파일 없음"; fi
  fi
fi

# 4-3 웹 실행계정의 의심 프로세스 / 크론 / 임시파일 / 외부 연결
if [ -n "$RUN_USER" ] && id "$RUN_USER" >/dev/null 2>&1; then
  PS="$(ps -u "$RUN_USER" -o pid=,ppid=,etime=,args= 2>/dev/null | grep -vE 'httpd|apache2|php-fpm|rotatelogs|grep' )"
  if [ -n "$PS" ]; then risk "웹 실행계정($RUN_USER)으로 실행 중인 비정상 프로세스 (리버스쉘/채굴기 의심)"; printf '%s\n' "$PS" | show
  else ok "웹 실행계정의 비정상 프로세스 없음"; fi

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
fi

# =====================================================================
section "점검 요약"
# =====================================================================
log "  [위험] ${CNT_RISK}건   [주의] ${CNT_WARN}건   [양호] ${CNT_OK}건   [정보] ${CNT_INFO}건"
log ""
log "  ※ 이 결과는 '알려진 패턴' 기준이며 안전을 보증하지 않습니다."
log "    - [위험] 중 침해 흔적(로그 200 응답, 웹쉘, 비정상 프로세스)이 있으면 설정 보완보다 침해사고 대응이 우선입니다."
log "    - CVE 판정은 업스트림 버전 기준이며, 패키지 설치본은 배포판 보안 공지로 최종 확인하세요."
log "    - 근본 대책은 2.4.69 이상(또는 보안수정이 반영된 배포판 패키지)으로의 업그레이드입니다."
log ""
log "  리포트 파일: $REPORT"
