#!/usr/bin/env bash
# =====================================================================
#  tomcat_precheck.sh
#  Apache Tomcat 서버 - 패치 전 보안 사전 점검 스크립트
#  (기준: 지원 중인 브랜치별 최신 버전 11.0.27 / 10.1.61 / 9.0.123)
#
#  - 읽기 전용: 설정 변경/파일 삭제/서비스 재시작을 하지 않습니다.
#  - 점검 항목
#      [1] 버전 / 설치 방식 / 지원 종료(EOL) 브랜치 여부 확인
#      [2] 버전별 해당 CVE 판정 (Tomcat 버전을 OSV 취약점 DB 의 영향 구간과 비교,
#          선택 구성요소(jasper·websocket·tribes 등)는 lib 폴더에 jar 가 있을 때만 해당)
#      [3] 위험 설정 점검 (셧다운 포트, AJP 커넥터, 관리자 앱·쉬운 비밀번호, 예제 앱,
#          DefaultServlet 쓰기/목록, 버전 노출, 원격 디버그, 실행 계정, 파일 권한 등)
#      [4] 침해 흔적 점검 (접근 로그, 배포된 앱 안의 웹쉘 의심 JSP, catalina 로그, 의심 프로세스/연결/크론)
#  - 결과: 화면 출력 + 리포트 파일(/tmp/tomcat_precheck_<호스트>_<시각>[_pid<PID>].txt)
#
#  CVE 데이터 출처: OSV (https://osv.dev) Maven 데이터 (org.apache.tomcat 패키지)
#                   https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip
#                   (2026-11-02 내려받음, GitHub Advisory Database 등급 사용)
#                   대시보드에 연결된 에이전트로 실행하면 대시보드가 12시간마다 갱신한 최신 CVE 목록을
#                   자동으로 받아 씁니다(PRECHECK_CVE_DB). 직접 실행할 때는 -C 로 목록 파일을 지정할 수 있습니다.
#  최신 버전 기준: https://downloads.apache.org/tomcat/ 의 브랜치별 최신 버전
#
#  사용법:  ./tomcat_precheck.sh            ← 옵션 없이 실행 (권장)
#    - 실행 중인 Tomcat(java ... org.apache.catalina.startup.Bootstrap) 프로세스를 자동으로 찾아
#      설치 폴더(catalina.home)·인스턴스 폴더(catalina.base)를 따라갑니다.
#    - 인스턴스가 여러 개면 각각 점검하고 리포트를 따로 만듭니다.
#    - root 가 아니면 sudo 로 자동 재실행합니다(비밀번호를 물을 수 있음).
#  선택 옵션: [-H 설치폴더] [-B 인스턴스폴더] [-d 일수] [-l '로그경로'] [-s '서버로그경로'] [-C CVE목록파일]
#    -H : Tomcat 설치 폴더(CATALINA_HOME) 직접 지정 (Tomcat 이 꺼져 있어 자동 탐지가 안 될 때)
#    -B : 인스턴스 폴더(CATALINA_BASE) 직접 지정 (기본값: 설치 폴더와 같음)
#    -d : "최근 변경 파일" 점검 기간(일). 기본 30
#    -l : 접근 로그 경로 직접 지정 (와일드카드 가능, 반드시 작은따옴표로 감쌀 것)
#         예: -l '/logs/tomcat/localhost_access_log*'
#    -s : 서버 로그(catalina.out 등) 경로 추가 지정 (자동으로 찾는 logs 폴더에 더해서 읽음. 작은따옴표로 감쌀 것)
#         예: -s '/applog/tomcat/catalina.out*'
#    -d 기간은 OS 로그인 기록(/var/log/secure 등) 점검 기간으로도 씁니다.
#    -C : CVE 목록 파일 (대시보드의 [CVE 목록 받기] 또는 /agent-api/cve/tomcat 에서 받은 파일)
# =====================================================================

LATEST_BRANCHES="11.0.27 10.1.61 9.0.123"
CATALINA_HOME_ARG=""
CATALINA_BASE_ARG=""
RECENT_DAYS=30
LOG_PATHS=""
SERVER_LOG_PATHS=""
ORIG_ARGS=("$@")
while getopts "H:B:d:l:s:C:h" opt; do
  case "$opt" in
    H) CATALINA_HOME_ARG="$OPTARG" ;;
    B) CATALINA_BASE_ARG="$OPTARG" ;;
    d) RECENT_DAYS="$OPTARG" ;;
    l) LOG_PATHS="$OPTARG" ;;
    s) SERVER_LOG_PATHS="$OPTARG" ;;
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

# --- 실행 중인 Tomcat 인스턴스 자동 탐지 ---------------------------------
# java 명령줄에 org.apache.catalina.startup.Bootstrap 이 있고 마지막 인자가 start 인 프로세스
# (Spring Boot 등 내장 Tomcat 은 Bootstrap 을 쓰지 않으므로 대상 아님)
# 출력: PID (한 줄에 하나)
detect_instances() {
  local pid cl ppid all="" parents=""
  for pid in $(ps -e -o pid= -o args= 2>/dev/null | awk '/org\.apache\.catalina\.startup\.Bootstrap/ && !/awk/ {print $1}'); do
    cl="$(tr '\0' ' ' < /proc/"$pid"/cmdline 2>/dev/null)"
    case "$cl" in
      *org.apache.catalina.startup.Bootstrap*\ stop*) ;;   # 종료 명령 프로세스 제외
      *org.apache.catalina.startup.Bootstrap*) all="$all $pid" ;;
    esac
  done
  # jsvc: root 관리 프로세스(부모)와 실제 JVM 을 돌리는 자식(tomcat 계정)이 같은 명령줄 → 부모는 빼고 자식만 점검
  for pid in $all; do
    ppid="$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')"
    case " $all " in *" $ppid "*) parents="$parents $ppid" ;; esac
  done
  for pid in $all; do
    case " $parents " in *" $pid "*) ;; *) echo "$pid" ;; esac
  done
}

if [ -z "$CATALINA_HOME_ARG" ] && [ -z "${PRECHECK_PID:-}" ]; then
  INSTANCES="$(detect_instances)"
  N_INST=0; [ -n "$INSTANCES" ] && N_INST="$(printf '%s\n' "$INSTANCES" | wc -l)"
  if [ "$N_INST" -gt 1 ]; then
    echo "[안내] 실행 중인 Tomcat 인스턴스 ${N_INST}개를 찾았습니다. 각각 점검합니다."
    i=0
    while read -r pid; do
      i=$((i+1))
      echo ""; echo "################ 인스턴스 ${i}/${N_INST} (PID ${pid}) ################"
      PASS=(-d "$RECENT_DAYS")
      [ -n "$LOG_PATHS" ] && PASS+=(-l "$LOG_PATHS")
      [ -n "$SERVER_LOG_PATHS" ] && PASS+=(-s "$SERVER_LOG_PATHS")
      PRECHECK_NO_SUDO=1 PRECHECK_PID="$pid" bash "$SELF" "${PASS[@]}" </dev/null
    done <<< "$INSTANCES"
    echo ""; echo "[안내] 전체 인스턴스 점검 완료. 리포트 파일 목록:"
    ls -1t /tmp/tomcat_precheck_*_pid*.txt 2>/dev/null | head -n "$N_INST" | sed 's/^/       /'
    exit 0
  elif [ "$N_INST" -eq 1 ]; then
    PRECHECK_PID="$INSTANCES"
  fi
fi

TS="$(date +%Y%m%d_%H%M%S)"
REPORT="/tmp/tomcat_precheck_$(hostname -s 2>/dev/null || echo host)_${TS}${PRECHECK_PID:+_pid$PRECHECK_PID}.txt"
WORK="$(mktemp -d /tmp/tomcat_precheck.XXXXXX)"
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

# 실행 계정의 다른 프로세스를 "누가 띄웠는지"로 나눔 (부모 프로세스를 거슬러 올라가며 확인)
#   srv   : 서버 프로세스(PRECHECK_PID 또는 서버 프로그램)가 띄운 것 → 웹쉘·리버스쉘의 전형적인 모습
#   login : sshd/su/sudo/login 에서 시작해 터미널이 붙어 있는 것 → 사람이 그 계정으로 로그인한 세션
#   known : 같은 계정으로 도는 알려진 웹·WAS 서버(Tomcat·WildFly·Apache·Nginx) → 정보 (그 제품 리포트에서 따로 점검)
#           이름만 흉내 낸 프로세스를 거르려고 실제 실행 파일(java·httpd·nginx)까지 확인
#   other : 그 밖 (부모가 이미 끝나 init 에 붙은 백그라운드 프로세스 등) → 출처 확인 필요
# 사용: split_user_procs 계정 '제외할 명령줄 정규식' '서버 프로그램 이름 정규식(ps comm)'
# 결과: $WORK/ps_srv, $WORK/ps_known, $WORK/ps_login, $WORK/ps_other (한 줄: PID PPID 터미널 실행시간 명령줄 ← 시작한 곳)
split_user_procs() {
  : > "$WORK/ps_srv"; : > "$WORK/ps_known"; : > "$WORK/ps_login"; : > "$WORK/ps_other"
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
    # 점검 중인 서버가 띄운 게 아니고, 같은 계정의 알려진 다른 웹·WAS 서버면 따로 분류
    if [ "$kind" != srv ]; then
      exe="$(readlink /proc/"$pid"/exe 2>/dev/null)"; exe="${exe% (deleted)}"; eb="${exe##*/}"
      other_srv=""
      case "$eb:$args" in
        java:*org.apache.catalina.startup.Bootstrap*) other_srv="Tomcat $(printf '%s' "$args" | grep -oE -- '-Dcatalina\.(base|home)=[^ ]+' | head -n1 | cut -d= -f2-)" ;;
        java:*jboss-modules.jar*) other_srv="WildFly $(printf '%s' "$args" | grep -oE -- '-Djboss\.home\.dir=[^ ]+' | head -n1 | cut -d= -f2-)" ;;
        httpd:*|apache2:*) other_srv="Apache $exe" ;;
        nginx:"nginx: master process"*|nginx:"nginx: worker process"*|nginx:"nginx: cache"*) other_srv="Nginx $exe" ;;
      esac
      if [ -n "$other_srv" ]; then kind=known; via="다른 서버: ${other_srv% }"; fi
    fi
    if [ "$kind" = known ]; then   # 명령줄이 길어 잘려도 어떤 서버인지 보이도록 앞에 표시
      printf '[%s] %s %s %s %s %s\n' "${via#다른 서버: }" "$pid" "$ppid" "$tty" "$etime" "$args" >> "$WORK/ps_known"
    else
      printf '%s %s %s %s %s  <- %s\n' "$pid" "$ppid" "$tty" "$etime" "$args" "${via:-시작한 곳 확인 불가(부모 종료)}" >> "$WORK/ps_$kind"
    fi
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
  if [ -s "$WORK/ps_known" ]; then
    info "$1 으로 실행 중인 다른 웹·WAS 서버 (같은 계정 — 해당 제품의 리포트에서 따로 점검됩니다)"
    cut -c1-220 "$WORK/ps_known" | show
    detail "→ 같은 계정이면 한 서버가 뚫렸을 때 다른 서버의 파일·프로세스도 건드릴 수 있습니다. 가능하면 서버마다 실행 계정을 나누는 것이 안전합니다."
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

# Maven 식 버전 비교: vcmp a b → -1 / 0 / 1
#   숫자 부분(최대 5자리) → 수식어 순위(Alpha<Beta<M(마일스톤)<RC<SNAPSHOT<정식<SP) → 수식어 번호
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

# zip(jar/war) 안의 파일 1개 내용 출력 (unzip → python3 순서)
zip_cat() {
  if command -v unzip >/dev/null 2>&1; then
    unzip -p "$1" "$2" 2>/dev/null
  elif command -v python3 >/dev/null 2>&1; then
    python3 -I -c 'import sys,zipfile
try: sys.stdout.write(zipfile.ZipFile(sys.argv[1]).read(sys.argv[2]).decode("utf-8","replace"))
except Exception: pass' "$1" "$2"
  fi
}

# 대시보드에서 받은 CVE 목록의 최신 버전 기준 (# LATEST=11.0.28,10.1.62,9.0.124) 이 있으면 그 값을 사용
if [ -n "${PRECHECK_CVE_DB:-}" ] && [ -r "$PRECHECK_CVE_DB" ]; then
  L="$(sed -n 's/^# LATEST=//p' "$PRECHECK_CVE_DB" | head -n1 | tr ',' ' ')"
  if [ -n "$L" ] && printf '%s' "$L" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+( [0-9]+\.[0-9]+\.[0-9]+)*$'; then
    LATEST_BRANCHES="$L"
  fi
fi

: > "$REPORT"
log "Tomcat 패치 전 보안 사전 점검  |  호스트: $(hostname)  |  일시: $(date '+%F %T')"

if [ "$(id -u)" -ne 0 ]; then
  warn "root 권한이 아닙니다(sudo 없음). 로그/설정/프로세스 정보를 못 읽어 결과가 불완전할 수 있습니다."
fi

# =====================================================================
section "[1] 버전 및 설치 방식 확인"
# =====================================================================
CMDLINE="$WORK/cmdline.txt"; : > "$CMDLINE"
if [ -n "${PRECHECK_PID:-}" ] && [ -r /proc/"$PRECHECK_PID"/cmdline ]; then
  tr '\0' '\n' < /proc/"$PRECHECK_PID"/cmdline > "$CMDLINE"
  info "실행 중인 Tomcat 프로세스 자동 탐지: PID $PRECHECK_PID"
fi
# -Dprop=value 값 읽기 (명령줄에 없으면 빈 값)
sysprop() { grep -E "^-D$1=" "$CMDLINE" | tail -n1 | cut -d= -f2-; }

CATALINA_HOME="${CATALINA_HOME_ARG:-$(sysprop catalina.home)}"
if [ -z "$CATALINA_HOME" ]; then
  warn "실행 중인 Tomcat 프로세스를 찾지 못해 흔한 설치 경로에서 찾습니다. (Tomcat 이 꺼져 있을 수 있음)"
  for c in /opt/tomcat /opt/tomcat/latest /usr/local/tomcat /usr/share/tomcat /usr/share/tomcat11 /usr/share/tomcat10 /usr/share/tomcat9 /srv/tomcat; do
    if [ -f "$c/lib/catalina.jar" ]; then CATALINA_HOME="$c"; break; fi
  done
  [ -z "$CATALINA_HOME" ] && CATALINA_HOME="$(ls -d /opt/apache-tomcat-* /usr/local/apache-tomcat-* /opt/tomcat* 2>/dev/null | while read -r d; do [ -f "$d/lib/catalina.jar" ] && echo "$d"; done | sort -V | tail -n1)"
fi
CATALINA_HOME="${CATALINA_HOME%/}"
if [ -z "$CATALINA_HOME" ] || [ ! -f "$CATALINA_HOME/lib/catalina.jar" ]; then
  risk "Tomcat 설치 폴더를 찾지 못했습니다. Tomcat 을 기동한 상태에서 다시 실행하거나 -H 로 경로를 지정하세요. (예: -H /opt/tomcat)"
  exit 1
fi
CATALINA_BASE="${CATALINA_BASE_ARG:-$(sysprop catalina.base)}"
CATALINA_BASE="${CATALINA_BASE:-$CATALINA_HOME}"; CATALINA_BASE="${CATALINA_BASE%/}"
# Debian/Ubuntu 패키지는 설치(/usr/share/tomcatN)와 인스턴스(/var/lib/tomcatN)가 나뉨
if [ -z "$CATALINA_BASE_ARG" ] && [ "$CATALINA_BASE" = "$CATALINA_HOME" ] && [ ! -f "$CATALINA_BASE/conf/server.xml" ]; then
  for c in /var/lib/"$(basename "$CATALINA_HOME")" /etc/"$(basename "$CATALINA_HOME")"/..; do
    [ -f "$c/conf/server.xml" ] && { CATALINA_BASE="$(readlink -f "$c")"; break; }
  done
fi
CONF_DIR="$CATALINA_BASE/conf"
CONFIG="$CONF_DIR/server.xml"
LOG_DIR="$CATALINA_BASE/logs"

[ "$CATALINA_BASE" != "$CATALINA_HOME" ] && info "인스턴스 구분: base=$CATALINA_BASE"

SERVER_IPS="$(server_ips)"
info "서버 IP: ${SERVER_IPS:-확인 불가}"
info "설치 폴더: $CATALINA_HOME"
info "메인 설정 파일: $CONFIG"

# --- 버전: catalina.jar 의 ServerInfo.properties(server.number) → RELEASE-NOTES → version.sh 순서 -----
# (server.info 는 보안 설정으로 바꿔 둔 곳이 많아 server.number 를 먼저 봄)
TC_VER=""; VER_LINE=""
SI="$(zip_cat "$CATALINA_HOME/lib/catalina.jar" org/apache/catalina/util/ServerInfo.properties | tr -d '\r')"
if [ -n "$SI" ]; then
  NUM="$(printf '%s\n' "$SI" | sed -n 's/^server\.number=//p' | head -n1)"
  INFO_LINE="$(printf '%s\n' "$SI" | sed -n 's/^server\.info=//p' | head -n1)"
  TC_VER="$(printf '%s' "$INFO_LINE" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+(-M[0-9]+)?' | head -n1)"
  if [ -n "$NUM" ] && ! printf '%s' "$INFO_LINE" | grep -qE '[0-9]+\.[0-9]+\.[0-9]+'; then
    TC_VER="$(printf '%s' "$NUM" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+')"   # server.info 를 숨긴 경우
  fi
fi
if [ -z "$TC_VER" ] && [ -f "$CATALINA_HOME/RELEASE-NOTES" ]; then
  TC_VER="$(grep -oE 'Apache Tomcat Version [0-9]+\.[0-9]+\.[0-9]+(-M[0-9]+)?' "$CATALINA_HOME/RELEASE-NOTES" | head -n1 | awk '{print $4}')"
fi
if [ -z "$TC_VER" ] && [ -x "$CATALINA_HOME/bin/version.sh" ]; then
  TC_VER="$(CATALINA_BASE="$CATALINA_BASE" "$CATALINA_HOME/bin/version.sh" 2>/dev/null | sed -n 's/^Server number: *//p' | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+')"
fi
[ -n "$TC_VER" ] && VER_LINE="Apache Tomcat/$TC_VER"
[ -n "$INFO_LINE" ] && [ "$INFO_LINE" != "$VER_LINE" ] && VER_LINE="$VER_LINE (server.info: $INFO_LINE)"
info "버전 정보: ${VER_LINE:-확인 불가}"

if [ -z "$TC_VER" ]; then
  risk "버전을 해석하지 못했습니다. 수동 확인이 필요합니다. (unzip 또는 python3 가 있으면 catalina.jar 에서 읽을 수 있음)"
  exit 1
fi
BRANCH="$(printf '%s' "$TC_VER" | cut -d. -f1-2)"
case "$TC_VER" in *-M*) warn "Tomcat $TC_VER 은(는) 마일스톤(시험판) 릴리스입니다. 운영 사용 비권장" ;; esac
LATEST_SAME=""
for v in $LATEST_BRANCHES; do [ "$(printf '%s' "$v" | cut -d. -f1-2)" = "$BRANCH" ] && LATEST_SAME="$v"; done
if [ -z "$LATEST_SAME" ]; then
  risk "지원 종료(EOL) 브랜치 Tomcat $BRANCH.x 입니다. 보안 패치가 더 이상 나오지 않으므로 지원 브랜치($(printf '%s' "$LATEST_BRANCHES" | sed 's/ / \/ /g'))로 교체해야 합니다."
elif vle "$LATEST_SAME" "$TC_VER"; then
  ok "Tomcat $TC_VER : $BRANCH 브랜치 최신($LATEST_SAME) 이상입니다."
else
  warn "Tomcat $TC_VER : $BRANCH 브랜치 최신($LATEST_SAME) 미만입니다. 아래 [2]에서 해당 CVE를 확인하세요."
fi
case "$BRANCH" in
  [1-9].*) info "Java EE(javax) 계열 Tomcat($BRANCH)입니다. 10.1 이상(jakarta 계열)으로 올릴 때 애플리케이션의 javax → jakarta 변경이 필요합니다." ;;
esac

# 설치 방식
if command -v rpm >/dev/null 2>&1 && rpm -qf "$CATALINA_HOME/lib/catalina.jar" >/dev/null 2>&1; then
  info "설치 방식: RPM 패키지 ($(rpm -qf "$CATALINA_HOME/lib/catalina.jar"))"
  warn "패키지 설치본은 배포판이 보안수정을 백포트했을 수 있습니다. CVE 판정은 업스트림 버전 기준이므로 배포판 보안 공지로 최종 확인하세요."
elif command -v dpkg >/dev/null 2>&1 && dpkg -S "$CATALINA_HOME/lib/catalina.jar" >/dev/null 2>&1; then
  info "설치 방식: DEB 패키지 ($(dpkg -S "$CATALINA_HOME/lib/catalina.jar" 2>/dev/null | cut -d: -f1 | head -n1))"
  warn "패키지 설치본은 배포판이 보안수정을 백포트했을 수 있습니다. CVE 판정은 업스트림 버전 기준이므로 배포판 보안 공지로 최종 확인하세요."
else
  info "설치 방식: ZIP 배포본 (공식 압축 파일을 푼 설치)"
fi

# Java
JAVA_BIN=""
[ -n "${PRECHECK_PID:-}" ] && JAVA_BIN="$(readlink /proc/"$PRECHECK_PID"/exe 2>/dev/null)"
[ -z "$JAVA_BIN" ] && JAVA_BIN="$(command -v java 2>/dev/null)"
if [ -n "$JAVA_BIN" ]; then
  info "Java: $("$JAVA_BIN" -version 2>&1 | grep -v JAVA_TOOL_OPTIONS | head -n1) ($JAVA_BIN)"
fi

# 구성요소(jar): 단독 설치 Tomcat 은 모든 jar 가 Tomcat 버전과 같음 → 선택 구성요소는 "있는지"만 확인
info "구성요소(jar) 수: $(find "$CATALINA_HOME/lib" "$CATALINA_BASE/lib" -maxdepth 1 -name '*.jar' 2>/dev/null | sort -u | wc -l)"
comp_jar() {
  case "$1" in
    tomcat) echo "$CATALINA_HOME/lib/catalina.jar" ;;
    tomcat-jasper) echo "$CATALINA_HOME/lib/jasper.jar" ;;
    tomcat-websocket) echo "$CATALINA_HOME/lib/tomcat-websocket.jar" ;;
    tomcat-tribes) echo "$CATALINA_HOME/lib/catalina-tribes.jar" ;;
    tomcat-catalina-jmx-remote) echo "$CATALINA_HOME/lib/catalina-jmx-remote.jar" ;;
    tomcat-coyote-ffm) echo "$CATALINA_HOME/lib/tomcat-coyote-ffm.jar" ;;
    *) echo "" ;;
  esac
}
for c in tomcat-jasper tomcat-websocket tomcat-tribes tomcat-catalina-jmx-remote tomcat-coyote-ffm; do
  j="$(comp_jar "$c")"; [ -f "$j" ] && detail "$c ($(basename "$j"))"
done

# =====================================================================
section "[2] 버전별 해당 CVE 판정 (OSV 기준)"
# =====================================================================
# 형식: CVE|권고ID|등급|구성요소|groupId|시작버전|수정버전|마지막영향버전|설명
#   수정버전이 있으면  시작 <= 버전 < 수정  이면 해당
#   마지막영향버전이 있으면  시작 <= 버전 <= 마지막  이면 해당
#   둘 다 비어 있으면  시작 <= 버전  이면 해당 (OSV 에 수정 버전이 아직 없음)
CVE_DB="$WORK/cve.txt"
cat > "$CVE_DB" <<'EOF'
# --- CVE_DB 시작 (대시보드 CveFeed 와 같은 규칙으로 생성) ---
CVE-2000-0759|GHSA-qg4g-6jcq-rw93|moderate|tomcat||0||3.1|Jakarta Apache Tomcat Reveals Physical Paths
CVE-2000-1210|GHSA-4gr9-99j3-vqxv|moderate|tomcat||0||3.1|Apache Tomcat Directory Traversal
CVE-2001-0590|GHSA-x445-mmpw-7r4f|moderate|tomcat||0|3.2.2||Apache Tomcat Allows Source Disclosure
CVE-2001-0829|GHSA-58hj-575g-5j25|moderate|tomcat||0||3.2.1|Apache Tomcat allows webmasters to insert xss into error messages
CVE-2001-0917|GHSA-2w2w-cv3h-rr38|moderate|tomcat||0|4.0.2||Apache Tomcat Reveals Path through Long URL
CVE-2002-0493|GHSA-p543-jg43-9pm5|high|tomcat||0|4.0b7||Apache Tomcat may be started without proper security settings
CVE-2002-0935|GHSA-xmf4-j3j7-xj7q|moderate|tomcat||0|4.1.3-beta||Apache Tomcat DoS Via Requests Including Null Characters
CVE-2002-1148|GHSA-jxcv-v856-j5vg|moderate|tomcat||4.0.0|4.0.5||Apache Tomcat Source Code Disclosure
CVE-2002-1148|GHSA-jxcv-v856-j5vg|moderate|tomcat||4.1.0|4.1.12||Apache Tomcat Source Code Disclosure
CVE-2002-1394|GHSA-8v5p-2cpv-c2x6|high|tomcat||0|4.0.6||Apache Tomcat Source Code Disclosure
CVE-2002-1567|GHSA-86fp-jgwm-wgj5|moderate|tomcat||4.1.0|4.1.29||Apache Tomcat XSS Vulnerability
CVE-2002-2006|GHSA-8g4f-fh7f-4fwh|low|tomcat||3.0|3.3a||Apache Tomcat Default Installation Reveals Sensitive Information
CVE-2002-2006|GHSA-8g4f-fh7f-4fwh|low|tomcat||4.0.0|4.1.0||Apache Tomcat Default Installation Reveals Sensitive Information
CVE-2002-2008|GHSA-m8w6-7rh6-4xj6|moderate|tomcat||0|4.1.3||Apache Tomcat Leaks Information via Error Message
CVE-2002-2009|GHSA-r6cf-cr44-m8rr|moderate|tomcat||4.0.0||4.0.1|Apache Tomcat Leaks Pathname Information via Error Message
CVE-2002-2272|GHSA-pqr5-9v2j-44xg|high|tomcat||4.0.0||4.1.12|Apache Tomcat DoS via Malicious Get Request
CVE-2003-0042|GHSA-qfw2-wvrw-mvw4|moderate|tomcat||0|3.3.1a||Jakarta Tomcat Directory Listing vulnerability
CVE-2003-0043|GHSA-cvx5-7vc7-rg77|moderate|tomcat||0|3.3.1a||Tomcat uses trusted privileges when processing web.xml file
CVE-2003-0044|GHSA-5hgm-qm5m-5vmw|moderate|tomcat||3.0|3.3.2||Jakarta Tomcat cross-site scripting (XSS) vulnerability
CVE-2003-0045|GHSA-w97x-xfxf-f9xj|moderate|tomcat||0|3.3.1a||Jakarta Tomcat Denial of Service vulnerability
CVE-2003-0866|GHSA-7wj2-48c4-2684|moderate|tomcat||4.0|4.1.0||Apache Tomcat Denial of Service vulnerability in the Catalina package
CVE-2005-2090|GHSA-f2gq-p6qv-ccw4|moderate|tomcat||4.0.0||4.1.24|Tomcat Vulnerable to Web Cache Poisoning
CVE-2005-2090|GHSA-f2gq-p6qv-ccw4|moderate|tomcat||5.0.0||5.0.19|Tomcat Vulnerable to Web Cache Poisoning
CVE-2005-3164|GHSA-qhqv-q4xg-f6g7|low|tomcat||4.0.1||4.0.6|Apache Tomcat AJP Connector Information Leak
CVE-2005-3164|GHSA-qhqv-q4xg-f6g7|low|tomcat||4.1.0||4.1.36|Apache Tomcat AJP Connector Information Leak
CVE-2005-3510|GHSA-8f4w-jwqv-5cxc|high|tomcat||5.5.0|5.5.12||Apache Tomcat Vulnerable to Denial of Service (DoS) via Simultaneous Requests
CVE-2005-4703|GHSA-x89r-2wjq-mj7x|moderate|tomcat||0||4.0.3|Apache Tomcat Discloses MS-DOS Pathname
CVE-2005-4836|GHSA-qrcx-p4rr-g48h|high|tomcat||4.1.15||4.1.40|Apache Tomcat allows remote attackers to read JSP source files
CVE-2006-3835|GHSA-wfj7-mhr5-pcwq|moderate|tomcat||5.0.0|5.5.17||Apache Tomcat Reveals Directories
CVE-2006-7195|GHSA-p57v-p3fx-qgwm|moderate|tomcat||5.0.0||5.0.30|Apache Tomcat XSS Vulnerability
CVE-2006-7195|GHSA-p57v-p3fx-qgwm|moderate|tomcat||5.5.0|5.5.18||Apache Tomcat XSS Vulnerability
CVE-2006-7196|GHSA-pm78-wxxf-fw98|moderate|tomcat||4.0.0|4.0.7||Cross-site scripting in Apache Tomcat
CVE-2006-7196|GHSA-pm78-wxxf-fw98|moderate|tomcat||4.1.0|4.1.32||Cross-site scripting in Apache Tomcat
CVE-2006-7196|GHSA-pm78-wxxf-fw98|moderate|tomcat||5.0.0|5.0.31||Cross-site scripting in Apache Tomcat
CVE-2006-7196|GHSA-pm78-wxxf-fw98|moderate|tomcat||5.5.0|5.5.16||Cross-site scripting in Apache Tomcat
CVE-2006-7197|GHSA-jpqr-vh55-xqxf|high|tomcat||0||5.5.15|Apache Tomcat Buffer Over-Read
CVE-2007-0450|GHSA-4prh-gqw8-rgh5|moderate|tomcat||5.0|5.5.22||Apache Tomcat Directory Traversal
CVE-2007-0450|GHSA-4prh-gqw8-rgh5|moderate|tomcat||6.0|6.0.10||Apache Tomcat Directory Traversal
CVE-2007-1358|GHSA-xmc9-6p56-3c4v|low|tomcat||4.0.0||4.0.6|Apache Tomcat XSS In Accept-Language Headers
CVE-2007-1358|GHSA-xmc9-6p56-3c4v|low|tomcat||4.1.0||4.1.34|Apache Tomcat XSS In Accept-Language Headers
CVE-2007-2449|GHSA-hc39-rjwp-qffq|moderate|tomcat||4.0.0||4.0.6|Apache Tomcat XSS Vulnerabilities in Examples Web Application
CVE-2007-2449|GHSA-hc39-rjwp-qffq|moderate|tomcat||5.0.0||5.0.30|Apache Tomcat XSS Vulnerabilities in Examples Web Application
CVE-2007-2449|GHSA-hc39-rjwp-qffq|moderate|tomcat||5.5.0||5.5.24|Apache Tomcat XSS Vulnerabilities in Examples Web Application
CVE-2007-2449|GHSA-hc39-rjwp-qffq|moderate|tomcat||6.0.0||6.0.13|Apache Tomcat XSS Vulnerabilities in Examples Web Application
CVE-2007-2450|GHSA-5c5p-jxvx-x7j2|low|tomcat||4.0.0||4.0.6|Apache Tomcat vulnerable to Cross-site Scripting
CVE-2007-2450|GHSA-5c5p-jxvx-x7j2|low|tomcat||4.1.0|4.1.37||Apache Tomcat vulnerable to Cross-site Scripting
CVE-2007-2450|GHSA-5c5p-jxvx-x7j2|low|tomcat||5.0.0||5.0.30|Apache Tomcat vulnerable to Cross-site Scripting
CVE-2007-2450|GHSA-5c5p-jxvx-x7j2|low|tomcat||5.5.0|5.5.25||Apache Tomcat vulnerable to Cross-site Scripting
CVE-2007-2450|GHSA-5c5p-jxvx-x7j2|low|tomcat||6.0.0|6.0.14||Apache Tomcat vulnerable to Cross-site Scripting
CVE-2007-3382|GHSA-qff8-g48j-pwpw|moderate|tomcat||3.3.0||3.3.2|Apache Tomcat treats single quotes as delimiters in cookies
CVE-2007-3382|GHSA-qff8-g48j-pwpw|moderate|tomcat||4.1.0||4.1.36|Apache Tomcat treats single quotes as delimiters in cookies
CVE-2007-3382|GHSA-qff8-g48j-pwpw|moderate|tomcat||5.0.0||5.0.30|Apache Tomcat treats single quotes as delimiters in cookies
CVE-2007-3382|GHSA-qff8-g48j-pwpw|moderate|tomcat||5.5.0||5.5.24|Apache Tomcat treats single quotes as delimiters in cookies
CVE-2007-3382|GHSA-qff8-g48j-pwpw|moderate|tomcat||6.0.0||6.0.13|Apache Tomcat treats single quotes as delimiters in cookies
CVE-2007-3383|GHSA-wjwr-3jch-479j|moderate|tomcat||4.0.0||4.0.6|Apache Tomcat SendMailServlet XSS
CVE-2007-3383|GHSA-wjwr-3jch-479j|moderate|tomcat||4.1.0||4.1.36|Apache Tomcat SendMailServlet XSS
CVE-2007-3384|GHSA-36hp-4x3g-phrg|moderate|tomcat||3.3.0||3.3.2|Apache Tomcat's CookieExample Vulnerable to XSS
CVE-2007-3385|GHSA-6j8f-66vh-39mj|moderate|tomcat||3.3.0||3.3.2|Apache Tomcat Mishandles Character Sequence in Cookies
CVE-2007-3385|GHSA-6j8f-66vh-39mj|moderate|tomcat||4.1.0||4.1.36|Apache Tomcat Mishandles Character Sequence in Cookies
CVE-2007-3385|GHSA-6j8f-66vh-39mj|moderate|tomcat||5.0.0||5.0.30|Apache Tomcat Mishandles Character Sequence in Cookies
CVE-2007-3385|GHSA-6j8f-66vh-39mj|moderate|tomcat||5.5.0||5.5.24|Apache Tomcat Mishandles Character Sequence in Cookies
CVE-2007-3385|GHSA-6j8f-66vh-39mj|moderate|tomcat||6.0.0||6.0.13|Apache Tomcat Mishandles Character Sequence in Cookies
CVE-2007-4724|GHSA-g77g-vjjm-x83j|moderate|tomcat||0||4.1.31|Apache Tomcat Example Application CSRF and XSS Vulnerabilities
CVE-2007-5333|GHSA-cww4-vj5r-rx57|moderate|tomcat||4.1.0|4.1.37||Exposure of Sensitive Information in Apache Tomcat
CVE-2007-5333|GHSA-cww4-vj5r-rx57|moderate|tomcat||5.5.0|5.5.26||Exposure of Sensitive Information in Apache Tomcat
CVE-2007-5333|GHSA-cww4-vj5r-rx57|moderate|tomcat||6.0.0|6.0.15||Exposure of Sensitive Information in Apache Tomcat
CVE-2007-5342|GHSA-w65j-cmqc-37p2|moderate|tomcat||5.5.9||5.5.25|JULI logging component in Apache Tomcat does not restrict certain permissions for web applications
CVE-2007-5342|GHSA-w65j-cmqc-37p2|moderate|tomcat||6.0.0||6.0.15|JULI logging component in Apache Tomcat does not restrict certain permissions for web applications
CVE-2007-5461|GHSA-v5p2-vg3c-pmrr|low|tomcat||4.0.0||4.0.6|Apache Tomcat Path Traversal Vulnerability
CVE-2007-5461|GHSA-v5p2-vg3c-pmrr|low|tomcat||5.5.0||5.5.25|Apache Tomcat Path Traversal Vulnerability
CVE-2007-5461|GHSA-v5p2-vg3c-pmrr|low|tomcat||6.0.0||6.0.14|Apache Tomcat Path Traversal Vulnerability
CVE-2007-6286|GHSA-qrj4-rmqg-4hcp|moderate|tomcat||5.5.11||5.5.25|Apache Tomcat Does Not Properly Handle Empty Requests
CVE-2007-6286|GHSA-qrj4-rmqg-4hcp|moderate|tomcat||6.0.0||6.0.15|Apache Tomcat Does Not Properly Handle Empty Requests
CVE-2008-0002|GHSA-5x5f-9r6q-q7mh|moderate|tomcat||6.0.0|6.0.16||Apache Tomcat Sensitive Information Disclosure
CVE-2008-1232|GHSA-q74x-qqhr-f8rx|moderate|tomcat||4.1.0|4.1.38||Apache Tomcat Cross-site scripting (XSS) vulnerability
CVE-2008-1232|GHSA-q74x-qqhr-f8rx|moderate|tomcat||5.5.0|5.5.27||Apache Tomcat Cross-site scripting (XSS) vulnerability
CVE-2008-1232|GHSA-q74x-qqhr-f8rx|moderate|tomcat||6.0.0|6.0.17||Apache Tomcat Cross-site scripting (XSS) vulnerability
CVE-2008-1947|GHSA-f98p-9pp6-7q6c|moderate|tomcat||5.5.9|5.5.27||Apache Tomcat Cross-site scripting (XSS) vulnerability
CVE-2008-1947|GHSA-f98p-9pp6-7q6c|moderate|tomcat||6.0.0|6.0.18||Apache Tomcat Cross-site scripting (XSS) vulnerability
CVE-2008-2370|GHSA-m8h8-6rvg-f4mg|moderate|tomcat||4.1.0|4.1.38||Apache Tomcat Path Traversal Vulnerability
CVE-2008-2370|GHSA-m8h8-6rvg-f4mg|moderate|tomcat||5.5.0|5.5.27||Apache Tomcat Path Traversal Vulnerability
CVE-2008-2370|GHSA-m8h8-6rvg-f4mg|moderate|tomcat||6.0.0|6.0.18||Apache Tomcat Path Traversal Vulnerability
CVE-2008-2938|GHSA-m7xj-ccqc-p4g2|moderate|tomcat||4.1.0|4.1.39||Apache Tomcat Directory Traversal vulnerability
CVE-2008-2938|GHSA-m7xj-ccqc-p4g2|moderate|tomcat||5.5.0|5.5.27||Apache Tomcat Directory Traversal vulnerability
CVE-2008-2938|GHSA-m7xj-ccqc-p4g2|moderate|tomcat||6.0.0|6.0.18||Apache Tomcat Directory Traversal vulnerability
CVE-2008-4308|GHSA-7g59-hm8v-cwmc|low|tomcat||4.1.32|4.1.35||Apache Tomcat information disclosure vulnerability
CVE-2008-4308|GHSA-7g59-hm8v-cwmc|low|tomcat||5.5.10|5.5.21||Apache Tomcat information disclosure vulnerability
CVE-2008-5515|GHSA-9737-qmgc-hfr9|moderate|tomcat||4.1.0|4.1.40||Directory Traversal in Apache Tomcat
CVE-2008-5515|GHSA-9737-qmgc-hfr9|moderate|tomcat||5.5.0|5.5.28||Directory Traversal in Apache Tomcat
CVE-2008-5515|GHSA-9737-qmgc-hfr9|moderate|tomcat||6.0.0|6.0.20||Directory Traversal in Apache Tomcat
CVE-2009-0033|GHSA-5cw4-ggx9-36vg|moderate|tomcat||4.1.0||4.1.39|Apache Tomcat Denial of Service via Malformed Request Headers
CVE-2009-0033|GHSA-5cw4-ggx9-36vg|moderate|tomcat||5.5.0||5.5.27|Apache Tomcat Denial of Service via Malformed Request Headers
CVE-2009-0033|GHSA-5cw4-ggx9-36vg|moderate|tomcat||6.0.0||6.0.18|Apache Tomcat Denial of Service via Malformed Request Headers
CVE-2009-0580|GHSA-w227-xcfx-3pj8|moderate|tomcat||4.1.0|4.1.40||Exposure of Sensitive Information in Apache Tomcat
CVE-2009-0580|GHSA-w227-xcfx-3pj8|moderate|tomcat||5.0.0|5.5.28||Exposure of Sensitive Information in Apache Tomcat
CVE-2009-0580|GHSA-w227-xcfx-3pj8|moderate|tomcat||6.0.0|6.0.19||Exposure of Sensitive Information in Apache Tomcat
CVE-2009-0781|GHSA-j788-fx57-99wp|moderate|tomcat||4.1.0||4.1.39|Cross-site scripting in Apache Tomcat
CVE-2009-0781|GHSA-j788-fx57-99wp|moderate|tomcat||5.5.0||5.5.27|Cross-site scripting in Apache Tomcat
CVE-2009-0781|GHSA-j788-fx57-99wp|moderate|tomcat||6.0.0|6.0.20||Cross-site scripting in Apache Tomcat
CVE-2009-0783|GHSA-hhjg-g8xq-hhr3|moderate|tomcat||4.1.0||4.1.39|Exposure of Sensitive Information to an Unauthorized Actor in Apache Tomcat
CVE-2009-0783|GHSA-hhjg-g8xq-hhr3|moderate|tomcat||5.5.0||5.5.27|Exposure of Sensitive Information to an Unauthorized Actor in Apache Tomcat
CVE-2009-0783|GHSA-hhjg-g8xq-hhr3|moderate|tomcat||6.0.0|6.0.20||Exposure of Sensitive Information to an Unauthorized Actor in Apache Tomcat
CVE-2009-2693|GHSA-ggx9-4728-588r|moderate|tomcat||5.5.0|5.5.29||Apache Tomcat Directory Traversal vulnerability
CVE-2009-2693|GHSA-ggx9-4728-588r|moderate|tomcat||6.0.0|6.0.24||Apache Tomcat Directory Traversal vulnerability
CVE-2009-2901|GHSA-hjfh-7c4v-7q8h|moderate|tomcat||5.5.0|5.5.29||Improper Authentication in Apache Tomcat
CVE-2009-2901|GHSA-hjfh-7c4v-7q8h|moderate|tomcat||6.0.0|6.0.24||Improper Authentication in Apache Tomcat
CVE-2009-2902|GHSA-8wch-9gcg-v2pr|moderate|tomcat||5.5.0|5.5.29||Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in Apache Tomcat
CVE-2009-2902|GHSA-8wch-9gcg-v2pr|moderate|tomcat||6.0.0|6.0.24||Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in Apache Tomcat
CVE-2009-3555|GHSA-f7w7-6pjc-wwm6|critical|tomcat||5.0.0|5.5.33||Apache Tomcat affected by vulnerability in TLS and SSL protocol
CVE-2009-3555|GHSA-f7w7-6pjc-wwm6|critical|tomcat||6.0.0|6.0.32||Apache Tomcat affected by vulnerability in TLS and SSL protocol
CVE-2009-3555|GHSA-f7w7-6pjc-wwm6|critical|tomcat||7.0.0|7.0.10||Apache Tomcat affected by vulnerability in TLS and SSL protocol
CVE-2010-1157|GHSA-w6q7-ww2x-7gm3|moderate|tomcat||5.5.0|5.5.30||Exposure of Sensitive Information to an Unauthorized Actor in Apache Tomcat
CVE-2010-1157|GHSA-w6q7-ww2x-7gm3|moderate|tomcat||6.0.0|6.0.28||Exposure of Sensitive Information to an Unauthorized Actor in Apache Tomcat
CVE-2010-2227|GHSA-cxg2-49rq-8gcr|moderate|tomcat||5.5.0|5.5.30||Apache Tomcat does not properly handle an invalid Transfer-Encoding header
CVE-2010-2227|GHSA-cxg2-49rq-8gcr|moderate|tomcat||6.0.0|6.0.28||Apache Tomcat does not properly handle an invalid Transfer-Encoding header
CVE-2010-2227|GHSA-cxg2-49rq-8gcr|moderate|tomcat||7.0.0|7.0.2||Apache Tomcat does not properly handle an invalid Transfer-Encoding header
CVE-2010-3718|GHSA-fj6c-prgj-gr3r|low|tomcat||5.5.0|5.5.30||Improper Limitation of a Pathname to a Restricted Directory in Apache Tomcat
CVE-2010-3718|GHSA-fj6c-prgj-gr3r|low|tomcat||6.0.0|6.0.30||Improper Limitation of a Pathname to a Restricted Directory in Apache Tomcat
CVE-2010-3718|GHSA-fj6c-prgj-gr3r|low|tomcat||7.0.0|7.0.4||Improper Limitation of a Pathname to a Restricted Directory in Apache Tomcat
CVE-2010-4172|GHSA-c78g-qwpw-2jgv|moderate|tomcat||6.0.12||6.0.29|Improper Neutralization of Input During Web Page Generation in Apache Tomcat
CVE-2010-4172|GHSA-c78g-qwpw-2jgv|moderate|tomcat||7.0.0|7.0.5||Improper Neutralization of Input During Web Page Generation in Apache Tomcat
CVE-2010-4312|GHSA-pvjh-7h8q-q56r|moderate|tomcat||6.0.0|6.0.35||Apache Tomcat has cookies without HTTPOnly flag in Set-Cookie header
CVE-2010-4476|GHSA-gvgc-rxmh-5hvw|moderate|tomcat||5.5.0|5.5.33||Apache Tomcat affected by infinite loop in Double.parseDouble method in Java Runtime Environment
CVE-2010-4476|GHSA-gvgc-rxmh-5hvw|moderate|tomcat||6.0.0|6.0.32||Apache Tomcat affected by infinite loop in Double.parseDouble method in Java Runtime Environment
CVE-2010-4476|GHSA-gvgc-rxmh-5hvw|moderate|tomcat||7.0.0|7.0.7||Apache Tomcat affected by infinite loop in Double.parseDouble method in Java Runtime Environment
CVE-2011-0013|GHSA-3p86-xgrq-m6p6|moderate|tomcat||5.5.0|5.5.32||Improper Neutralization of Input During Web Page Generation in Apache Tomcat
CVE-2011-0013|GHSA-3p86-xgrq-m6p6|moderate|tomcat||6.0.0|6.0.30||Improper Neutralization of Input During Web Page Generation in Apache Tomcat
CVE-2011-0013|GHSA-3p86-xgrq-m6p6|moderate|tomcat||7.0.0|7.0.6||Improper Neutralization of Input During Web Page Generation in Apache Tomcat
CVE-2011-0534|GHSA-43v2-6grp-9pp9|high|tomcat||6.0.0|6.0.32||Apache Tomcat does not enforce the maxHttpHeaderSize limit
CVE-2011-0534|GHSA-43v2-6grp-9pp9|high|tomcat||7.0.0|7.0.8||Apache Tomcat does not enforce the maxHttpHeaderSize limit
CVE-2011-1088|GHSA-mg4v-rf8p-ghqq|moderate|tomcat||7.0.0|7.0.10||Apache Tomcat allows remote attackers to bypass intended access restrictions
CVE-2011-1183|GHSA-p26v-97vp-jcx6|moderate|tomcat||7.0.11|7.0.12||Access controll bypass in Apache Tomcat
CVE-2011-1184|GHSA-q9xf-jwr4-v445|moderate|tomcat||5.5.0|5.5.34||Authentication Bypass in Apache Tomcat
CVE-2011-1184|GHSA-q9xf-jwr4-v445|moderate|tomcat||6.0.0|6.0.33||Authentication Bypass in Apache Tomcat
CVE-2011-1184|GHSA-q9xf-jwr4-v445|moderate|tomcat||7.0.0|7.0.12||Authentication Bypass in Apache Tomcat
CVE-2011-1419|GHSA-vch7-92vf-jm44|moderate|tomcat||7.0|7.0.11||Apache Tomcat does not follow ServletSecurity annotations
CVE-2011-1475|GHSA-h6c8-rg87-f3pc|moderate|tomcat||7.0.0|7.0.12||Apache Tomcat HTTP BIO Connector Error Discloses Information From Different Requests to Remote Users
CVE-2011-1582|GHSA-3xpj-jgv5-q4vv|moderate|tomcat||7.0.12|7.0.14||Access restriction bypass in Apache Tomcat
CVE-2011-2204|GHSA-c57p-3v2g-w9rg|moderate|tomcat||5.5.0|5.5.34||Insertion of Sensitive Information into Log File in Apache Tomcat
CVE-2011-2204|GHSA-c57p-3v2g-w9rg|moderate|tomcat||6.0.0|6.0.33||Insertion of Sensitive Information into Log File in Apache Tomcat
CVE-2011-2204|GHSA-c57p-3v2g-w9rg|moderate|tomcat||7.0.0|7.0.19||Insertion of Sensitive Information into Log File in Apache Tomcat
CVE-2011-2481|GHSA-r7c8-hghc-2mp8|moderate|tomcat||7.0.0|7.0.17||Apache Tomcat Allows Replacing of XML Parser
CVE-2011-2526|GHSA-9ggm-7897-x4mg|moderate|tomcat||0|5.5.34||Improper Input Validation in Apache Tomcat
CVE-2011-2526|GHSA-9ggm-7897-x4mg|moderate|tomcat||6.0.0|6.0.33||Improper Input Validation in Apache Tomcat
CVE-2011-2526|GHSA-9ggm-7897-x4mg|moderate|tomcat||7.0.0|7.0.19||Improper Input Validation in Apache Tomcat
CVE-2011-3190|GHSA-c38m-v4m2-524v|high|tomcat||5.0.0|5.5.34||Apache Tomcat Allows Remote Attackers to Spoof AJP Requests
CVE-2011-3190|GHSA-c38m-v4m2-524v|high|tomcat||6.0.0|6.0.34||Apache Tomcat Allows Remote Attackers to Spoof AJP Requests
CVE-2011-3190|GHSA-c38m-v4m2-524v|high|tomcat||7.0.0|7.0.21||Apache Tomcat Allows Remote Attackers to Spoof AJP Requests
CVE-2011-3375|GHSA-rp8h-vr48-4j8p|moderate|tomcat||6.0.30|6.0.35||Apache Tomcat Exposes IP Addresses and HTTP Headers of Requests
CVE-2011-3375|GHSA-rp8h-vr48-4j8p|moderate|tomcat||7.0|7.0.22||Apache Tomcat Exposes IP Addresses and HTTP Headers of Requests
CVE-2011-4858|GHSA-wr3m-gw98-mc3j|moderate|tomcat||5.5.0|5.5.35||Improper Input Validation in Apache Tomcat
CVE-2011-4858|GHSA-wr3m-gw98-mc3j|moderate|tomcat||6.0.0|6.0.35||Improper Input Validation in Apache Tomcat
CVE-2011-4858|GHSA-wr3m-gw98-mc3j|moderate|tomcat||7.0.0|7.0.23||Improper Input Validation in Apache Tomcat
CVE-2011-5062|GHSA-4f7h-9j2x-cmr4|moderate|tomcat||5.5.0|5.5.34||Improper Authentication in Apache Tomcat
CVE-2011-5062|GHSA-4f7h-9j2x-cmr4|moderate|tomcat||6.0.0|6.0.33||Improper Authentication in Apache Tomcat
CVE-2011-5062|GHSA-4f7h-9j2x-cmr4|moderate|tomcat||7.0.0|7.0.12||Improper Authentication in Apache Tomcat
CVE-2011-5063|GHSA-hffm-fqv4-w27r|moderate|tomcat||5.5.0|5.5.34||Improper Authentication in Apache Tomcat
CVE-2011-5063|GHSA-hffm-fqv4-w27r|moderate|tomcat||6.0.0|6.0.33||Improper Authentication in Apache Tomcat
CVE-2011-5063|GHSA-hffm-fqv4-w27r|moderate|tomcat||7.0.0|7.0.12||Improper Authentication in Apache Tomcat
CVE-2011-5064|GHSA-6cr4-7c7p-p3xv|moderate|tomcat||5.5.0|5.5.34||Use of Hard-coded Cryptographic Key in Apache Tomcat
CVE-2011-5064|GHSA-6cr4-7c7p-p3xv|moderate|tomcat||6.0.0|6.0.33||Use of Hard-coded Cryptographic Key in Apache Tomcat
CVE-2011-5064|GHSA-6cr4-7c7p-p3xv|moderate|tomcat||7.0.0|7.0.12||Use of Hard-coded Cryptographic Key in Apache Tomcat
CVE-2012-0022|GHSA-8h2q-qm9x-55jc|moderate|tomcat||5.5.0|5.5.35||Denial of Service in Apache Tomcat
CVE-2012-0022|GHSA-8h2q-qm9x-55jc|moderate|tomcat||6.0.0|6.0.34||Denial of Service in Apache Tomcat
CVE-2012-0022|GHSA-8h2q-qm9x-55jc|moderate|tomcat||7.0.0|7.0.23||Denial of Service in Apache Tomcat
CVE-2012-3544|GHSA-qfxv-3ppc-7qg5|moderate|tomcat||6.0.0|6.0.37||Apache Tomcat Vulnerable to Denial of Service (DoS) via Improper Handling of chunk extensions
CVE-2012-3544|GHSA-qfxv-3ppc-7qg5|moderate|tomcat||7.0.0|7.0.30||Apache Tomcat Vulnerable to Denial of Service (DoS) via Improper Handling of chunk extensions
CVE-2012-3546|GHSA-jgm2-m5cg-f66g|moderate|tomcat||6.0.0|6.0.36||Authentication Bypass in Apache Tomcat
CVE-2012-3546|GHSA-jgm2-m5cg-f66g|moderate|tomcat||7.0.0|7.0.30||Authentication Bypass in Apache Tomcat
CVE-2012-4431|GHSA-76vr-72mv-mf3q|moderate|tomcat||6.0.0|6.0.36||Cross-Site Request Forgery in Apache Tomcat
CVE-2012-4431|GHSA-76vr-72mv-mf3q|moderate|tomcat||7.0.0|7.0.32||Cross-Site Request Forgery in Apache Tomcat
CVE-2012-5885|GHSA-99rf-92v6-cwx4|moderate|tomcat||5.5.0|5.5.36||Improper Access Control in Apache Tomcat
CVE-2012-5885|GHSA-99rf-92v6-cwx4|moderate|tomcat||6.0.0|6.0.36||Improper Access Control in Apache Tomcat
CVE-2012-5885|GHSA-99rf-92v6-cwx4|moderate|tomcat||7.0.0|7.0.30||Improper Access Control in Apache Tomcat
CVE-2012-5886|GHSA-9xrj-439h-62hg|moderate|tomcat||5.5.0|5.5.36||Improper Authentication in Apache Tomcat
CVE-2012-5886|GHSA-9xrj-439h-62hg|moderate|tomcat||6.0.0|6.0.36||Improper Authentication in Apache Tomcat
CVE-2012-5886|GHSA-9xrj-439h-62hg|moderate|tomcat||7.0.0|7.0.30||Improper Authentication in Apache Tomcat
CVE-2012-5887|GHSA-28cq-6rmx-pjq4|moderate|tomcat||5.5.0|5.5.36||Improper Authentication in Apache Tomcat
CVE-2012-5887|GHSA-28cq-6rmx-pjq4|moderate|tomcat||6.0.0|6.0.36||Improper Authentication in Apache Tomcat
CVE-2012-5887|GHSA-28cq-6rmx-pjq4|moderate|tomcat||7.0.0|7.0.30||Improper Authentication in Apache Tomcat
CVE-2013-2067|GHSA-6m48-jxwx-76q7|moderate|tomcat||6.0.21|6.0.37||Improper Authentication in Apache Tomcat
CVE-2013-2067|GHSA-6m48-jxwx-76q7|moderate|tomcat||7.0.0|7.0.33||Improper Authentication in Apache Tomcat
CVE-2013-2071|GHSA-3p5r-7cw3-2m67|low|tomcat||7.0.0|7.0.40||Exposure of Sensitive Information to an Unauthorized Actor in Apache Tomcat
CVE-2013-2185|GHSA-v6c7-8qx5-8gmp|high|tomcat||0|7.0.39||Deserialization of Untrusted Data in Apache Tomcat
CVE-2013-4286|GHSA-j448-j653-r3vj|moderate|tomcat||0|6.0.39||Apache Tomcat is vulnerable to HTTP request-smuggling
CVE-2013-4286|GHSA-j448-j653-r3vj|moderate|tomcat||7.0.0|7.0.47||Apache Tomcat is vulnerable to HTTP request-smuggling
CVE-2013-4286|GHSA-j448-j653-r3vj|moderate|tomcat||8.0.0-RC1|8.0.0-RC3||Apache Tomcat is vulnerable to HTTP request-smuggling
CVE-2013-4322|GHSA-wq2p-q66w-q8gp|moderate|tomcat||0|6.0.39||Apache Tomcat Denial of Service vulnerability
CVE-2013-4322|GHSA-wq2p-q66w-q8gp|moderate|tomcat||7.0.0|7.0.50||Apache Tomcat Denial of Service vulnerability
CVE-2013-4322|GHSA-wq2p-q66w-q8gp|moderate|tomcat||8.0.0-RC1|8.0.0-RC10||Apache Tomcat Denial of Service vulnerability
CVE-2013-4444|GHSA-h6c8-x5r3-pm88|moderate|tomcat||7.0|7.0.40||Apache Tomcat Unrestricted file upload vulnerability
CVE-2013-4590|GHSA-87w9-x2c3-hrjj|moderate|tomcat||0|6.0.39||Exposure of Sensitive Information to an Unauthorized Actor in Apache Tomcat
CVE-2013-4590|GHSA-87w9-x2c3-hrjj|moderate|tomcat||7.0.0|7.0.50||Exposure of Sensitive Information to an Unauthorized Actor in Apache Tomcat
CVE-2013-4590|GHSA-87w9-x2c3-hrjj|moderate|tomcat||8.0.0-RC1|8.0.0-RC10||Exposure of Sensitive Information to an Unauthorized Actor in Apache Tomcat
CVE-2014-0033|GHSA-6gjj-c5mj-4cvp|moderate|tomcat||6.0.33|6.0.38||Improper Input Validation in Apache Tomcat
CVE-2014-0050|GHSA-xx68-jfcg-xmmf|high|tomcat||7.0.0|7.0.52||Commons FileUpload Denial of service vulnerability
CVE-2014-0050|GHSA-xx68-jfcg-xmmf|high|tomcat||8.0.0-RC1|8.0.3||Commons FileUpload Denial of service vulnerability
CVE-2014-0075|GHSA-475f-74wp-pqv5|moderate|tomcat||0|6.0.40||Integer Overflow or Wraparound in Apache Tomcat
CVE-2014-0075|GHSA-475f-74wp-pqv5|moderate|tomcat||7.0.0|7.0.53||Integer Overflow or Wraparound in Apache Tomcat
CVE-2014-0075|GHSA-475f-74wp-pqv5|moderate|tomcat||8.0.0|8.0.4||Integer Overflow or Wraparound in Apache Tomcat
CVE-2014-0095|GHSA-wf5v-jhxj-q632|moderate|tomcat||8.0.0-RC1|8.0.4||Denial of service in Apache Tomcat
CVE-2014-0096|GHSA-qprx-q2r7-3rx6|moderate|tomcat||0|6.0.40||Improper Input Validation in Apache Tomcat
CVE-2014-0096|GHSA-qprx-q2r7-3rx6|moderate|tomcat||7.0.0|7.0.54||Improper Input Validation in Apache Tomcat
CVE-2014-0096|GHSA-qprx-q2r7-3rx6|moderate|tomcat||8.0.0|8.0.6||Improper Input Validation in Apache Tomcat
CVE-2014-0099|GHSA-xh5x-j8jf-pcpx|moderate|tomcat||0|6.0.40||Improper Neutralization of CRLF Sequences in HTTP Headers in Apache Tomcat
CVE-2014-0099|GHSA-xh5x-j8jf-pcpx|moderate|tomcat||7.0.0|7.0.54||Improper Neutralization of CRLF Sequences in HTTP Headers in Apache Tomcat
CVE-2014-0099|GHSA-xh5x-j8jf-pcpx|moderate|tomcat||8.0.0|8.0.6||Improper Neutralization of CRLF Sequences in HTTP Headers in Apache Tomcat
CVE-2014-0119|GHSA-prc3-7f44-w48j|moderate|tomcat||0|6.0.40||Missing XML Validation in Apache Tomcat
CVE-2014-0119|GHSA-prc3-7f44-w48j|moderate|tomcat||7.0.0|7.0.54||Missing XML Validation in Apache Tomcat
CVE-2014-0119|GHSA-prc3-7f44-w48j|moderate|tomcat||8.0.0|8.0.6||Missing XML Validation in Apache Tomcat
CVE-2014-0227|GHSA-42j3-498q-m6vp|moderate|tomcat||6.0.0|6.0.42||Improper Input Validation in Apache Tomcat
CVE-2014-0227|GHSA-42j3-498q-m6vp|moderate|tomcat||7.0.0|7.0.55||Improper Input Validation in Apache Tomcat
CVE-2014-0227|GHSA-42j3-498q-m6vp|moderate|tomcat||8.0.0|8.0.9||Improper Input Validation in Apache Tomcat
CVE-2014-0230|GHSA-pxcx-cxq8-4mmw|high|tomcat||6.0.0|6.0.44||Uncontrolled Resource Consumption in Apache Tomcat
CVE-2014-0230|GHSA-pxcx-cxq8-4mmw|high|tomcat||7.0.0|7.0.55||Uncontrolled Resource Consumption in Apache Tomcat
CVE-2014-0230|GHSA-pxcx-cxq8-4mmw|high|tomcat||8.0.0|8.0.9||Uncontrolled Resource Consumption in Apache Tomcat
CVE-2014-7810|GHSA-4c43-cwvx-9crh|moderate|tomcat||6.0.0|6.0.44||Improper Access Control in Apache Tomcat
CVE-2014-7810|GHSA-4c43-cwvx-9crh|moderate|tomcat||7.0.0|7.0.58||Improper Access Control in Apache Tomcat
CVE-2014-7810|GHSA-4c43-cwvx-9crh|moderate|tomcat||8.0.0|8.0.16||Improper Access Control in Apache Tomcat
CVE-2015-5174|GHSA-6qr6-x7jm-x2q6|moderate|tomcat||6.0.0|6.0.45||Improper Limitation of a Pathname to a Restricted Directory in Apache Tomcat
CVE-2015-5174|GHSA-6qr6-x7jm-x2q6|moderate|tomcat||7.0.0|7.0.65||Improper Limitation of a Pathname to a Restricted Directory in Apache Tomcat
CVE-2015-5174|GHSA-6qr6-x7jm-x2q6|moderate|tomcat||8.0.0-RC1|8.0.27||Improper Limitation of a Pathname to a Restricted Directory in Apache Tomcat
CVE-2015-5345|GHSA-rh8q-vjgf-gf74|moderate|tomcat||6.0.0|6.0.45||Improper Limitation of a Pathname to a Restricted Directory in Apache Tomcat
CVE-2015-5345|GHSA-rh8q-vjgf-gf74|moderate|tomcat||7.0.0|7.0.68||Improper Limitation of a Pathname to a Restricted Directory in Apache Tomcat
CVE-2015-5345|GHSA-rh8q-vjgf-gf74|moderate|tomcat||8.0.0-RC1|8.0.30||Improper Limitation of a Pathname to a Restricted Directory in Apache Tomcat
CVE-2015-5345|GHSA-rh8q-vjgf-gf74|moderate|tomcat||9.0.0.M1|9.0.0.M2||Improper Limitation of a Pathname to a Restricted Directory in Apache Tomcat
CVE-2015-5346|GHSA-jrcp-c39h-r29x|high|tomcat||7.0.0|7.0.66||Improper Neutralization of Input During Web Page Generation in Apache Tomcat
CVE-2015-5346|GHSA-jrcp-c39h-r29x|high|tomcat||8.0.0.RC1|8.0.31||Improper Neutralization of Input During Web Page Generation in Apache Tomcat
CVE-2015-5346|GHSA-jrcp-c39h-r29x|high|tomcat||9.0.0.M1|9.0.0.M2||Improper Neutralization of Input During Web Page Generation in Apache Tomcat
CVE-2015-5351|GHSA-w7cg-5969-678w|high|tomcat||0|7.0.68||Apache Tomcat allows remote attackers to bypass a CSRF protection mechanism by using a token
CVE-2015-5351|GHSA-w7cg-5969-678w|high|tomcat||8.0.0|8.0.31||Apache Tomcat allows remote attackers to bypass a CSRF protection mechanism by using a token
CVE-2015-5351|GHSA-w7cg-5969-678w|high|tomcat||9.0.0.M0|9.0.0.M2||Apache Tomcat allows remote attackers to bypass a CSRF protection mechanism by using a token
CVE-2016-0706|GHSA-6vx3-hr43-cfrh|moderate|tomcat||6.0.0|6.0.45||Exposure of Sensitive Information to an Unauthorized Actor in Apache Tomcat
CVE-2016-0706|GHSA-6vx3-hr43-cfrh|moderate|tomcat||8.0.0.RC1|8.0.31||Exposure of Sensitive Information to an Unauthorized Actor in Apache Tomcat
CVE-2016-0706|GHSA-6vx3-hr43-cfrh|moderate|tomcat||9.0.0.M1|9.0.0.M2||Exposure of Sensitive Information to an Unauthorized Actor in Apache Tomcat
CVE-2016-0714|GHSA-mv42-px54-87jw|high|tomcat||6.0.0|6.0.46||Improper Access Control in Apache Tomcat
CVE-2016-0714|GHSA-mv42-px54-87jw|high|tomcat||7.0.0|7.0.70||Improper Access Control in Apache Tomcat
CVE-2016-0714|GHSA-mv42-px54-87jw|high|tomcat||8.0.0.RC1|8.0.32||Improper Access Control in Apache Tomcat
CVE-2016-0714|GHSA-mv42-px54-87jw|high|tomcat||9.0.0.M1|9.0.0.M2||Improper Access Control in Apache Tomcat
CVE-2016-0762|GHSA-wxcp-f2c8-x6xv|moderate|tomcat||6.0.0|6.0.46||Observable Discrepancy in Apache Tomcat
CVE-2016-0762|GHSA-wxcp-f2c8-x6xv|moderate|tomcat||7.0.0|7.0.72||Observable Discrepancy in Apache Tomcat
CVE-2016-0762|GHSA-wxcp-f2c8-x6xv|moderate|tomcat||8.0.0.RC1|8.0.37||Observable Discrepancy in Apache Tomcat
CVE-2016-0762|GHSA-wxcp-f2c8-x6xv|moderate|tomcat||8.5.0|8.5.5||Observable Discrepancy in Apache Tomcat
CVE-2016-0762|GHSA-wxcp-f2c8-x6xv|moderate|tomcat||9.0.0M1|9.0.0.M10||Observable Discrepancy in Apache Tomcat
CVE-2016-0763|GHSA-9hjv-9h75-xmpp|moderate|tomcat||7.0.0|7.0.68||Improper Verification of Source of a Communication Channel in Apache Tomcat
CVE-2016-0763|GHSA-9hjv-9h75-xmpp|moderate|tomcat||8.0.0|8.0.32||Improper Verification of Source of a Communication Channel in Apache Tomcat
CVE-2016-0763|GHSA-9hjv-9h75-xmpp|moderate|tomcat||9.0.0M1|9.0.0.M3||Improper Verification of Source of a Communication Channel in Apache Tomcat
CVE-2016-5388|GHSA-v646-rx6w-r3qq|high|tomcat||7.0.0|7.0.72||Improper Access Control in Apache Tomcat
CVE-2016-5388|GHSA-v646-rx6w-r3qq|high|tomcat||8.0.0|8.5.5||Improper Access Control in Apache Tomcat
CVE-2016-6794|GHSA-2rvf-329f-p99g|moderate|tomcat||6.0.0|6.0.47||System Property Disclosure in Apache Tomcat
CVE-2016-6794|GHSA-2rvf-329f-p99g|moderate|tomcat||7.0.0|7.0.72||System Property Disclosure in Apache Tomcat
CVE-2016-6794|GHSA-2rvf-329f-p99g|moderate|tomcat||8.0.0|8.0.37||System Property Disclosure in Apache Tomcat
CVE-2016-6794|GHSA-2rvf-329f-p99g|moderate|tomcat||8.1.0|8.5.5||System Property Disclosure in Apache Tomcat
CVE-2016-6794|GHSA-2rvf-329f-p99g|moderate|tomcat||9.0.0.M1|9.0.0.M10||System Property Disclosure in Apache Tomcat
CVE-2016-6796|GHSA-3mjp-p938-4329|high|tomcat||6.0.0|6.0.46||Apache Tomcat vulnerable to SecurityManager bypass
CVE-2016-6796|GHSA-3mjp-p938-4329|high|tomcat||7.0.0|7.0.71||Apache Tomcat vulnerable to SecurityManager bypass
CVE-2016-6796|GHSA-3mjp-p938-4329|high|tomcat||8.0.0.RC1|8.0.37||Apache Tomcat vulnerable to SecurityManager bypass
CVE-2016-6796|GHSA-3mjp-p938-4329|high|tomcat||8.5.0|8.5.5||Apache Tomcat vulnerable to SecurityManager bypass
CVE-2016-6796|GHSA-3mjp-p938-4329|high|tomcat||9.0.0.M1|9.0.0.M10||Apache Tomcat vulnerable to SecurityManager bypass
CVE-2016-6797|GHSA-q6x7-f33r-3wxx|high|tomcat||7.0.0|7.0.72||Incorrect Authorization in Apache Tomcat
CVE-2016-6797|GHSA-q6x7-f33r-3wxx|high|tomcat||8.0.0|8.0.37||Incorrect Authorization in Apache Tomcat
CVE-2016-6797|GHSA-q6x7-f33r-3wxx|high|tomcat||8.5.0|8.5.5||Incorrect Authorization in Apache Tomcat
CVE-2016-6797|GHSA-q6x7-f33r-3wxx|high|tomcat||9.0.0.M1|9.0.0.M10||Incorrect Authorization in Apache Tomcat
CVE-2016-6816|GHSA-jc7p-5r39-9477|high|tomcat||6.0.0|6.0.48||Improper Input Validation in Apache Tomcat
CVE-2016-6816|GHSA-jc7p-5r39-9477|high|tomcat||7.0.0|7.0.73||Improper Input Validation in Apache Tomcat
CVE-2016-6816|GHSA-jc7p-5r39-9477|high|tomcat||8.0.0RC1|8.0.39||Improper Input Validation in Apache Tomcat
CVE-2016-6816|GHSA-jc7p-5r39-9477|high|tomcat||8.5.0|8.5.8||Improper Input Validation in Apache Tomcat
CVE-2016-6816|GHSA-jc7p-5r39-9477|high|tomcat||9.0.0.M1|9.0.0.M12||Improper Input Validation in Apache Tomcat
CVE-2016-6817|GHSA-698c-2x4j-g9gq|high|tomcat||8.5.0|8.5.8||Improper Restriction of Operations within the Bounds of a Memory Buffer in Apache Tomcat
CVE-2016-6817|GHSA-698c-2x4j-g9gq|high|tomcat||9.0.0.M1|9.0.0.M12||Improper Restriction of Operations within the Bounds of a Memory Buffer in Apache Tomcat
CVE-2016-8735|GHSA-cw54-59pw-4g8c|critical|tomcat||0|6.0.48||Apache Tomcat Improper Access Control vulnerability
CVE-2016-8735|GHSA-cw54-59pw-4g8c|critical|tomcat||7.0.0|7.0.73||Apache Tomcat Improper Access Control vulnerability
CVE-2016-8735|GHSA-cw54-59pw-4g8c|critical|tomcat||8.0.0|8.0.39||Apache Tomcat Improper Access Control vulnerability
CVE-2016-8735|GHSA-cw54-59pw-4g8c|critical|tomcat||8.5.0|8.5.7||Apache Tomcat Improper Access Control vulnerability
CVE-2016-8735|GHSA-cw54-59pw-4g8c|critical|tomcat||9.0.0.M1|9.0.0.M12||Apache Tomcat Improper Access Control vulnerability
CVE-2016-8745|GHSA-w3j5-q8f2-3cqq|high|tomcat||6.0.16|6.0.50||Concurrent Execution using Shared Resource with Improper Synchronization in Apache Tomcat
CVE-2016-8745|GHSA-w3j5-q8f2-3cqq|high|tomcat||7.0.0|7.0.75||Concurrent Execution using Shared Resource with Improper Synchronization in Apache Tomcat
CVE-2016-8745|GHSA-w3j5-q8f2-3cqq|high|tomcat||8.0.0-RC1|8.0.41||Concurrent Execution using Shared Resource with Improper Synchronization in Apache Tomcat
CVE-2016-8745|GHSA-w3j5-q8f2-3cqq|high|tomcat||8.5.0|8.5.9||Concurrent Execution using Shared Resource with Improper Synchronization in Apache Tomcat
CVE-2016-8745|GHSA-w3j5-q8f2-3cqq|high|tomcat||9.0.0.M1|9.0.0.M14||Concurrent Execution using Shared Resource with Improper Synchronization in Apache Tomcat
CVE-2016-8747|GHSA-fjwp-r6fm-q6qw|high|tomcat||8.5.7|8.5.10||Apache Tomcat allows remote attackers to read data that was intended to be associated with a different request
CVE-2016-8747|GHSA-fjwp-r6fm-q6qw|high|tomcat||9.0.0.M11|9.0.0.M16||Apache Tomcat allows remote attackers to read data that was intended to be associated with a different request
CVE-2017-12615|GHSA-pjfr-qf3p-3q25|high|tomcat||7.0.0|7.0.79||When running Apache Tomcat on Windows with HTTP PUTs enabled it was possible to upload a JSP file to the server
CVE-2017-12616|GHSA-8qq4-8jvq-mfw4|high|tomcat||7.0.0|7.0.81||Exposure of Sensitive Information to an Unauthorized Actor in Apache Tomcat
CVE-2017-12617|GHSA-xjgh-84hx-56c5|high|tomcat||7.0.0|7.0.82||Unrestricted Upload of File with Dangerous Type Apache Tomcat
CVE-2017-12617|GHSA-xjgh-84hx-56c5|high|tomcat||8.0.0-RC1|8.0.47||Unrestricted Upload of File with Dangerous Type Apache Tomcat
CVE-2017-12617|GHSA-xjgh-84hx-56c5|high|tomcat||8.5.0|8.5.23||Unrestricted Upload of File with Dangerous Type Apache Tomcat
CVE-2017-12617|GHSA-xjgh-84hx-56c5|high|tomcat||9.0.0.M1|9.0.1||Unrestricted Upload of File with Dangerous Type Apache Tomcat
CVE-2017-15706|GHSA-372q-33vh-8mpc|moderate|tomcat||7.0.79|7.0.84||Inconsistent documentation in Apache Tomcat
CVE-2017-15706|GHSA-372q-33vh-8mpc|moderate|tomcat||8.0.45|8.0.48||Inconsistent documentation in Apache Tomcat
CVE-2017-15706|GHSA-372q-33vh-8mpc|moderate|tomcat||8.5.16|8.5.24||Inconsistent documentation in Apache Tomcat
CVE-2017-15706|GHSA-372q-33vh-8mpc|moderate|tomcat||9.0.0.M22|9.0.2||Inconsistent documentation in Apache Tomcat
CVE-2017-5647|GHSA-3gv7-3h64-78cm|high|tomcat||6.0.0|6.0.53||Exposure of Sensitive Information to an Unauthorized Actor in Apache Tomcat
CVE-2017-5647|GHSA-3gv7-3h64-78cm|high|tomcat||7.0.0|7.0.77||Exposure of Sensitive Information to an Unauthorized Actor in Apache Tomcat
CVE-2017-5647|GHSA-3gv7-3h64-78cm|high|tomcat||8.0.0|8.0.43||Exposure of Sensitive Information to an Unauthorized Actor in Apache Tomcat
CVE-2017-5647|GHSA-3gv7-3h64-78cm|high|tomcat||8.5.0|8.5.13||Exposure of Sensitive Information to an Unauthorized Actor in Apache Tomcat
CVE-2017-5647|GHSA-3gv7-3h64-78cm|high|tomcat||9.0.0.M1|9.0.0.M19||Exposure of Sensitive Information to an Unauthorized Actor in Apache Tomcat
CVE-2017-5648|GHSA-3vx3-xf6q-r5xp|critical|tomcat||7.0.0|7.0.76||Exposure of Resource to Wrong Sphere in Apache Tomcat
CVE-2017-5648|GHSA-3vx3-xf6q-r5xp|critical|tomcat||8.0.0|8.0.42||Exposure of Resource to Wrong Sphere in Apache Tomcat
CVE-2017-5648|GHSA-3vx3-xf6q-r5xp|critical|tomcat||8.5.0|8.5.13||Exposure of Resource to Wrong Sphere in Apache Tomcat
CVE-2017-5648|GHSA-3vx3-xf6q-r5xp|critical|tomcat||9.0.0.M1|9.0.0.M18||Exposure of Resource to Wrong Sphere in Apache Tomcat
CVE-2017-5650|GHSA-9785-w233-x6hv|high|tomcat||8.5.0|8.5.13||Improper Resource Shutdown or Release in Apache Tomcat
CVE-2017-5650|GHSA-9785-w233-x6hv|high|tomcat||9.0.0.M1|9.0.0.M19||Improper Resource Shutdown or Release in Apache Tomcat
CVE-2017-5651|GHSA-9hg2-395j-83rm|critical|tomcat||8.5.0|8.5.13||Expected Behavior Violation in Apache Tomcat
CVE-2017-5651|GHSA-9hg2-395j-83rm|critical|tomcat||9.0.0.M1|9.0.0.M19||Expected Behavior Violation in Apache Tomcat
CVE-2017-5664|GHSA-jmvv-524f-hj5j|high|tomcat||7.0.0|7.0.78||Improper Handling of Exceptional Conditions in Apache Tomcat
CVE-2017-5664|GHSA-jmvv-524f-hj5j|high|tomcat||8.0.0|8.0.44||Improper Handling of Exceptional Conditions in Apache Tomcat
CVE-2017-5664|GHSA-jmvv-524f-hj5j|high|tomcat||8.5.0|8.5.15||Improper Handling of Exceptional Conditions in Apache Tomcat
CVE-2017-5664|GHSA-jmvv-524f-hj5j|high|tomcat||9.0.0.M1|9.0.0.M21||Improper Handling of Exceptional Conditions in Apache Tomcat
CVE-2017-7674|GHSA-73rx-3f9r-x949|moderate|tomcat||7.0.41|7.0.79||Insufficient Verification of Data Authenticity in Apache Tomcat
CVE-2017-7674|GHSA-73rx-3f9r-x949|moderate|tomcat||8.0.0.RC1|8.0.45||Insufficient Verification of Data Authenticity in Apache Tomcat
CVE-2017-7674|GHSA-73rx-3f9r-x949|moderate|tomcat||8.5.0|8.5.16||Insufficient Verification of Data Authenticity in Apache Tomcat
CVE-2017-7674|GHSA-73rx-3f9r-x949|moderate|tomcat||9.0.0.M1|9.0.0.M22||Insufficient Verification of Data Authenticity in Apache Tomcat
CVE-2017-7675|GHSA-68g5-8q7f-m384|high|tomcat||8.5.0|8.5.16||Improper Limitation of a Pathname to a Restricted Directory in Apache Tomcat
CVE-2017-7675|GHSA-68g5-8q7f-m384|high|tomcat||9.0.0.M1|9.0.0.M22||Improper Limitation of a Pathname to a Restricted Directory in Apache Tomcat
CVE-2018-11784|GHSA-5q99-f34m-67gc|moderate|tomcat||7.0.23|7.0.91||Apache Tomcat Open Redirect vulnerability
CVE-2018-11784|GHSA-5q99-f34m-67gc|moderate|tomcat||8.5.0|8.5.34||Apache Tomcat Open Redirect vulnerability
CVE-2018-11784|GHSA-5q99-f34m-67gc|moderate|tomcat||9.0.0|9.0.12||Apache Tomcat Open Redirect vulnerability
CVE-2018-1304|GHSA-6rxj-58jh-436r|moderate|tomcat||7.0.0|7.0.86||Apache Tomcat unauthorized access vulnerability
CVE-2018-1304|GHSA-6rxj-58jh-436r|moderate|tomcat||8.0.0|8.0.51||Apache Tomcat unauthorized access vulnerability
CVE-2018-1304|GHSA-6rxj-58jh-436r|moderate|tomcat||8.5.0|8.5.28||Apache Tomcat unauthorized access vulnerability
CVE-2018-1304|GHSA-6rxj-58jh-436r|moderate|tomcat||9.0.0|9.0.5||Apache Tomcat unauthorized access vulnerability
CVE-2018-1305|GHSA-jx6h-3fjx-cgv5|moderate|tomcat||7.0.0|7.0.85||Apache Tomcat information exposure vulnerability
CVE-2018-1305|GHSA-jx6h-3fjx-cgv5|moderate|tomcat||8.5.0|8.5.28||Apache Tomcat information exposure vulnerability
CVE-2018-1305|GHSA-jx6h-3fjx-cgv5|moderate|tomcat||9.0.0M1|9.0.5||Apache Tomcat information exposure vulnerability
CVE-2018-1336|GHSA-m59c-jpc8-m2x4|high|tomcat||7.0.28|7.0.87||In Apache Tomcat there is an improper handing of overflow in the UTF-8 decoder
CVE-2018-1336|GHSA-m59c-jpc8-m2x4|high|tomcat||8.0.0RC1|8.0.51||In Apache Tomcat there is an improper handing of overflow in the UTF-8 decoder
CVE-2018-1336|GHSA-m59c-jpc8-m2x4|high|tomcat||8.5.0|8.5.31||In Apache Tomcat there is an improper handing of overflow in the UTF-8 decoder
CVE-2018-1336|GHSA-m59c-jpc8-m2x4|high|tomcat||9.0.0.M9|9.0.8||In Apache Tomcat there is an improper handing of overflow in the UTF-8 decoder
CVE-2018-8014|GHSA-r4x2-3cq5-hqvp|critical|tomcat||7.0.41|7.0.88||The defaults settings for the CORS filter provided in Apache Tomcat are insecure and enable 'supportsCredentials' for all origins
CVE-2018-8014|GHSA-r4x2-3cq5-hqvp|critical|tomcat||8.0.0RC1|8.0.53||The defaults settings for the CORS filter provided in Apache Tomcat are insecure and enable 'supportsCredentials' for all origins
CVE-2018-8014|GHSA-r4x2-3cq5-hqvp|critical|tomcat||8.5.0|8.5.32||The defaults settings for the CORS filter provided in Apache Tomcat are insecure and enable 'supportsCredentials' for all origins
CVE-2018-8014|GHSA-r4x2-3cq5-hqvp|critical|tomcat||9.0.0.M1|9.0.9||The defaults settings for the CORS filter provided in Apache Tomcat are insecure and enable 'supportsCredentials' for all origins
CVE-2018-8034|GHSA-46j3-r4pj-4835|high|tomcat||7.0.35|7.0.90||The host name verification missing in Apache Tomcat
CVE-2018-8034|GHSA-46j3-r4pj-4835|high|tomcat||8.0.0|8.0.53||The host name verification missing in Apache Tomcat
CVE-2018-8034|GHSA-46j3-r4pj-4835|high|tomcat||8.5.0|8.5.32||The host name verification missing in Apache Tomcat
CVE-2018-8034|GHSA-46j3-r4pj-4835|high|tomcat||9.0.0|9.0.10||The host name verification missing in Apache Tomcat
CVE-2018-8037|GHSA-6v52-mj5r-7j2m|moderate|tomcat||8.5.5|8.5.32||Apache Tomcat Race Condition vulnerability
CVE-2018-8037|GHSA-6v52-mj5r-7j2m|moderate|tomcat||9.0.0.M9|9.0.10||Apache Tomcat Race Condition vulnerability
CVE-2019-0199|GHSA-qcxh-w3j9-58qr|high|tomcat||8.0.0|8.5.38||Apache Tomcat Denial of Service vulnerability
CVE-2019-0199|GHSA-qcxh-w3j9-58qr|high|tomcat||9.0.0|9.0.16||Apache Tomcat Denial of Service vulnerability
CVE-2019-0221|GHSA-jjpq-gp5q-8q6w|moderate|tomcat||7.0.0|7.0.94||Cross-site scripting in Apache Tomcat
CVE-2019-0221|GHSA-jjpq-gp5q-8q6w|moderate|tomcat||8.5.0|8.5.40||Cross-site scripting in Apache Tomcat
CVE-2019-0221|GHSA-jjpq-gp5q-8q6w|moderate|tomcat||9.0.0|9.0.17||Cross-site scripting in Apache Tomcat
CVE-2019-0232|GHSA-8vmx-qmch-mpqg|high|tomcat||7.0.0|7.0.94||Apache Tomcat OS Command Injection vulnerability
CVE-2019-0232|GHSA-8vmx-qmch-mpqg|high|tomcat||8.0.0|8.5.40||Apache Tomcat OS Command Injection vulnerability
CVE-2019-0232|GHSA-8vmx-qmch-mpqg|high|tomcat||9.0.0.M1|9.0.17||Apache Tomcat OS Command Injection vulnerability
CVE-2019-10072|GHSA-q4hg-rmq2-52q9|high|tomcat||8.5.0|8.5.41||Improper Locking in Apache Tomcat
CVE-2019-10072|GHSA-q4hg-rmq2-52q9|high|tomcat||9.0.0.M1|9.0.20||Improper Locking in Apache Tomcat
CVE-2019-12418|GHSA-hh3j-x4mc-g48r|high|tomcat||0|7.0.99||Insufficiently Protected Credentials in Apache Tomcat
CVE-2019-12418|GHSA-hh3j-x4mc-g48r|high|tomcat||8.0.0|8.5.49||Insufficiently Protected Credentials in Apache Tomcat
CVE-2019-12418|GHSA-hh3j-x4mc-g48r|high|tomcat||9.0.0|9.0.29||Insufficiently Protected Credentials in Apache Tomcat
CVE-2019-17563|GHSA-9xcj-c8cr-8c3c|high|tomcat||0|7.0.99||In Apache Tomcat, when using FORM authentication there was a narrow window where an attacker could perform a session fixation attack
CVE-2019-17563|GHSA-9xcj-c8cr-8c3c|high|tomcat||8.0.0|8.5.50||In Apache Tomcat, when using FORM authentication there was a narrow window where an attacker could perform a session fixation attack
CVE-2019-17563|GHSA-9xcj-c8cr-8c3c|high|tomcat||9.0.0|9.0.30||In Apache Tomcat, when using FORM authentication there was a narrow window where an attacker could perform a session fixation attack
CVE-2019-17569|GHSA-767j-jfh2-jvrc|moderate|tomcat||7.0.98|7.0.100||Potential HTTP request smuggling in Apache Tomcat
CVE-2019-17569|GHSA-767j-jfh2-jvrc|moderate|tomcat||8.5.48|8.5.51||Potential HTTP request smuggling in Apache Tomcat
CVE-2019-17569|GHSA-767j-jfh2-jvrc|moderate|tomcat||9.0.28|9.0.31||Potential HTTP request smuggling in Apache Tomcat
CVE-2020-11996|GHSA-53hp-jpwq-2jgq|high|tomcat||10.0.0-M1|10.0.0-M5||Uncontrolled Resource Consumption in Apache Tomcat
CVE-2020-11996|GHSA-53hp-jpwq-2jgq|high|tomcat||8.5.0|8.5.55||Uncontrolled Resource Consumption in Apache Tomcat
CVE-2020-11996|GHSA-53hp-jpwq-2jgq|high|tomcat||9.0.0.M1|9.0.35||Uncontrolled Resource Consumption in Apache Tomcat
CVE-2020-13934|GHSA-vf77-8h7g-gghp|high|tomcat||10.0.0-M1|10.0.0-M6||Improper Restriction of Operations within the Bounds of a Memory Buffer in Apache Tomcat
CVE-2020-13934|GHSA-vf77-8h7g-gghp|high|tomcat||8.5.1|8.5.56||Improper Restriction of Operations within the Bounds of a Memory Buffer in Apache Tomcat
CVE-2020-13934|GHSA-vf77-8h7g-gghp|high|tomcat||9.0.0.M5|9.0.36||Improper Restriction of Operations within the Bounds of a Memory Buffer in Apache Tomcat
CVE-2020-13935|GHSA-m7jv-hq7h-mq7c|high|tomcat||10.0.0-M1|10.0.0-M7||Infinite Loop in Apache Tomcat
CVE-2020-13935|GHSA-m7jv-hq7h-mq7c|high|tomcat||7.0.27|7.0.105||Infinite Loop in Apache Tomcat
CVE-2020-13935|GHSA-m7jv-hq7h-mq7c|high|tomcat||8.5.0|8.5.57||Infinite Loop in Apache Tomcat
CVE-2020-13935|GHSA-m7jv-hq7h-mq7c|high|tomcat||9.0.0.M1|9.0.37||Infinite Loop in Apache Tomcat
CVE-2020-13943|GHSA-f268-65qc-98vg|moderate|tomcat||10.0.0-M1|10.0.0-M8||Exposure of Sensitive Information to an Unauthorized Actor in Apache Tomcat
CVE-2020-13943|GHSA-f268-65qc-98vg|moderate|tomcat||8.5.0|8.5.58||Exposure of Sensitive Information to an Unauthorized Actor in Apache Tomcat
CVE-2020-13943|GHSA-f268-65qc-98vg|moderate|tomcat||9.0.0-M1|9.0.38||Exposure of Sensitive Information to an Unauthorized Actor in Apache Tomcat
CVE-2020-17527|GHSA-vvw4-rfwf-p6hx|high|tomcat||10.0.0-M1|10.0.0-M10||Exposure of Sensitive Information to an Unauthorized Actor in Apache Tomcat
CVE-2020-17527|GHSA-vvw4-rfwf-p6hx|high|tomcat||8.5.0|8.5.60||Exposure of Sensitive Information to an Unauthorized Actor in Apache Tomcat
CVE-2020-17527|GHSA-vvw4-rfwf-p6hx|high|tomcat||9.0.0-M1|9.0.40||Exposure of Sensitive Information to an Unauthorized Actor in Apache Tomcat
CVE-2020-1935|GHSA-qxf4-chvg-4r8r|moderate|tomcat||0|7.0.100||Potential HTTP request smuggling in Apache Tomcat
CVE-2020-1935|GHSA-qxf4-chvg-4r8r|moderate|tomcat||8.0.0|8.5.51||Potential HTTP request smuggling in Apache Tomcat
CVE-2020-1935|GHSA-qxf4-chvg-4r8r|moderate|tomcat||9.0.0|9.0.31||Potential HTTP request smuggling in Apache Tomcat
CVE-2020-1938|GHSA-c9hw-wf7x-jp9j|critical|tomcat||7.0.0|7.0.100||Improper Privilege Management in Tomcat
CVE-2020-1938|GHSA-c9hw-wf7x-jp9j|critical|tomcat||8.0.0|8.5.51||Improper Privilege Management in Tomcat
CVE-2020-1938|GHSA-c9hw-wf7x-jp9j|critical|tomcat||9.0.0|9.0.31||Improper Privilege Management in Tomcat
CVE-2020-9484|GHSA-344f-f5vg-2jfj|high|tomcat||10.0.0-M1|10.0.0-M5||Potential remote code execution in Apache Tomcat
CVE-2020-9484|GHSA-344f-f5vg-2jfj|high|tomcat||7.0.0|7.0.104||Potential remote code execution in Apache Tomcat
CVE-2020-9484|GHSA-344f-f5vg-2jfj|high|tomcat||8.0.0|8.5.55||Potential remote code execution in Apache Tomcat
CVE-2020-9484|GHSA-344f-f5vg-2jfj|high|tomcat||9.0.0|9.0.35||Potential remote code execution in Apache Tomcat
CVE-2021-24122|GHSA-2rvv-w9r2-rg7m|moderate|tomcat||10.0.0-M1|10.0.0-M10||Information Disclosure in Apache Tomcat
CVE-2021-24122|GHSA-2rvv-w9r2-rg7m|moderate|tomcat||7.0.0|7.0.107||Information Disclosure in Apache Tomcat
CVE-2021-24122|GHSA-2rvv-w9r2-rg7m|moderate|tomcat||8.5.0|8.5.60||Information Disclosure in Apache Tomcat
CVE-2021-24122|GHSA-2rvv-w9r2-rg7m|moderate|tomcat||9.0.0|9.0.40||Information Disclosure in Apache Tomcat
CVE-2021-25122|GHSA-j39c-c8hj-x4j3|high|tomcat||10.0.0-M1|10.0.2||Exposure of Sensitive Information to an Unauthorized Actor in Apache Tomcat
CVE-2021-25122|GHSA-j39c-c8hj-x4j3|high|tomcat||8.5.0|8.5.63||Exposure of Sensitive Information to an Unauthorized Actor in Apache Tomcat
CVE-2021-25122|GHSA-j39c-c8hj-x4j3|high|tomcat||9.0.0-M1|9.0.43||Exposure of Sensitive Information to an Unauthorized Actor in Apache Tomcat
CVE-2021-25329|GHSA-jgwr-3qm3-26f3|high|tomcat||10.0.0-M1|10.0.2||Potential remote code execution in Apache Tomcat
CVE-2021-25329|GHSA-jgwr-3qm3-26f3|high|tomcat||7.0.0|7.0.108||Potential remote code execution in Apache Tomcat
CVE-2021-25329|GHSA-jgwr-3qm3-26f3|high|tomcat||8.0.0|8.5.61||Potential remote code execution in Apache Tomcat
CVE-2021-25329|GHSA-jgwr-3qm3-26f3|high|tomcat||9.0.0|9.0.41||Potential remote code execution in Apache Tomcat
CVE-2021-30639|GHSA-44qp-qhfv-c7f6|high|tomcat||0|8.5.65||Improper Handling of Exceptional Conditions in Apache Tomcat
CVE-2021-30639|GHSA-44qp-qhfv-c7f6|high|tomcat||10.0.3|10.0.5||Improper Handling of Exceptional Conditions in Apache Tomcat
CVE-2021-30639|GHSA-44qp-qhfv-c7f6|high|tomcat||9.0.0|9.0.45||Improper Handling of Exceptional Conditions in Apache Tomcat
CVE-2021-30640|GHSA-36qh-35cm-5w2w|moderate|tomcat||10.0.0-M1|10.0.5||Authentication Bypass by Alternate Name in Apache Tomcat
CVE-2021-30640|GHSA-36qh-35cm-5w2w|moderate|tomcat||8.5.0|8.5.65||Authentication Bypass by Alternate Name in Apache Tomcat
CVE-2021-30640|GHSA-36qh-35cm-5w2w|moderate|tomcat||9.0.0M1|9.0.45||Authentication Bypass by Alternate Name in Apache Tomcat
CVE-2021-33037|GHSA-4vww-mc66-62m6|moderate|tomcat||10.0.0-M1|10.0.7||HTTP Request Smuggling in Apache Tomcat
CVE-2021-33037|GHSA-4vww-mc66-62m6|moderate|tomcat||8.5.0|8.5.68||HTTP Request Smuggling in Apache Tomcat
CVE-2021-33037|GHSA-4vww-mc66-62m6|moderate|tomcat||9.0.0-M1|9.0.48||HTTP Request Smuggling in Apache Tomcat
CVE-2021-41079|GHSA-59g9-7gfx-c72p|high|tomcat||10.0.0|10.0.4||Infinite loop in Tomcat due to parsing error
CVE-2021-41079|GHSA-59g9-7gfx-c72p|high|tomcat||8.5.0|8.5.64||Infinite loop in Tomcat due to parsing error
CVE-2021-41079|GHSA-59g9-7gfx-c72p|high|tomcat||9.0.0|9.0.44||Infinite loop in Tomcat due to parsing error
CVE-2021-42340|GHSA-wph7-x527-w3h5|high|tomcat||10.0.0-M1|10.0.12||Missing Release of Resource after Effective Lifetime in Apache Tomcat
CVE-2021-42340|GHSA-wph7-x527-w3h5|high|tomcat||10.1.0-M1|10.1.0-M6||Missing Release of Resource after Effective Lifetime in Apache Tomcat
CVE-2021-42340|GHSA-wph7-x527-w3h5|high|tomcat||8.5.60|8.5.72||Missing Release of Resource after Effective Lifetime in Apache Tomcat
CVE-2021-42340|GHSA-wph7-x527-w3h5|high|tomcat||9.0.40|9.0.54||Missing Release of Resource after Effective Lifetime in Apache Tomcat
CVE-2021-43980|GHSA-jx7c-7mj5-9438|low|tomcat||10.0.0-M1|10.0.20||Apache Tomcat Race Condition vulnerability
CVE-2021-43980|GHSA-jx7c-7mj5-9438|low|tomcat||10.1.0-M1|10.1.0-M14||Apache Tomcat Race Condition vulnerability
CVE-2021-43980|GHSA-jx7c-7mj5-9438|low|tomcat||8.5.0|8.5.78||Apache Tomcat Race Condition vulnerability
CVE-2021-43980|GHSA-jx7c-7mj5-9438|low|tomcat||9.0.0-M1|9.0.62||Apache Tomcat Race Condition vulnerability
CVE-2022-23181|GHSA-9f3j-pm6f-9fm5|high|tomcat||0|8.5.75||Race condition in Apache Tomcat
CVE-2022-23181|GHSA-9f3j-pm6f-9fm5|high|tomcat||10.0.0|10.0.16||Race condition in Apache Tomcat
CVE-2022-23181|GHSA-9f3j-pm6f-9fm5|high|tomcat||9.0.0|9.0.58||Race condition in Apache Tomcat
CVE-2022-25762|GHSA-h3ch-5pp2-vh6w|high|tomcat||8.5.0|8.5.75||Improper socket reuse in Apache Tomcat
CVE-2022-25762|GHSA-h3ch-5pp2-vh6w|high|tomcat||9.0.0M1|9.0.20||Improper socket reuse in Apache Tomcat
CVE-2022-29885|GHSA-r84p-88g2-2vx2|high|tomcat||10.0.0-M1|10.0.21||Apache Tomcat EncryptInterceptor error leads to Uncontrolled Resource Consumption
CVE-2022-29885|GHSA-r84p-88g2-2vx2|high|tomcat||10.1.0-M1|10.1.0-M15||Apache Tomcat EncryptInterceptor error leads to Uncontrolled Resource Consumption
CVE-2022-29885|GHSA-r84p-88g2-2vx2|high|tomcat||8.5.38|8.5.79||Apache Tomcat EncryptInterceptor error leads to Uncontrolled Resource Consumption
CVE-2022-29885|GHSA-r84p-88g2-2vx2|high|tomcat||9.0.13|9.0.63||Apache Tomcat EncryptInterceptor error leads to Uncontrolled Resource Consumption
CVE-2022-34305|GHSA-6j88-6whg-x687|moderate|tomcat||10.0.0-M1|10.0.22||Cross-site Scripting in Apache Tomcat
CVE-2022-34305|GHSA-6j88-6whg-x687|moderate|tomcat||10.1.0-M1|10.1.0-M17||Cross-site Scripting in Apache Tomcat
CVE-2022-34305|GHSA-6j88-6whg-x687|moderate|tomcat||8.5.50|8.5.82||Cross-site Scripting in Apache Tomcat
CVE-2022-34305|GHSA-6j88-6whg-x687|moderate|tomcat||9.0.30|9.0.65||Cross-site Scripting in Apache Tomcat
CVE-2022-42252|GHSA-p22x-g9px-3945|high|tomcat||10.0.0-M1|10.0.27||Apache Tomcat may reject request containing invalid Content-Length header
CVE-2022-42252|GHSA-p22x-g9px-3945|high|tomcat||10.1.0-M1|10.1.1||Apache Tomcat may reject request containing invalid Content-Length header
CVE-2022-42252|GHSA-p22x-g9px-3945|high|tomcat||8.5.0|8.5.83||Apache Tomcat may reject request containing invalid Content-Length header
CVE-2022-42252|GHSA-p22x-g9px-3945|high|tomcat||9.0.0-M1|9.0.68||Apache Tomcat may reject request containing invalid Content-Length header
CVE-2022-45143|GHSA-rq2w-37h9-vg94|high|tomcat||10.1.0|10.1.2||Apache Tomcat improperly escapes input from JsonErrorReportValve
CVE-2022-45143|GHSA-rq2w-37h9-vg94|high|tomcat||8.5.83|8.5.84||Apache Tomcat improperly escapes input from JsonErrorReportValve
CVE-2022-45143|GHSA-rq2w-37h9-vg94|high|tomcat||9.0.40|9.0.69||Apache Tomcat improperly escapes input from JsonErrorReportValve
CVE-2023-24998|GHSA-hfrx-6qgj-fp6c|high|tomcat||10.1.0-M1|10.1.5||Apache Commons FileUpload denial of service vulnerability
CVE-2023-24998|GHSA-hfrx-6qgj-fp6c|high|tomcat||11.0.0-M2|11.0.0-M5||Apache Commons FileUpload denial of service vulnerability
CVE-2023-24998|GHSA-hfrx-6qgj-fp6c|high|tomcat||8.5.85|8.5.88||Apache Commons FileUpload denial of service vulnerability
CVE-2023-24998|GHSA-hfrx-6qgj-fp6c|high|tomcat||9.0.0-M1|9.0.71||Apache Commons FileUpload denial of service vulnerability
CVE-2023-28708|GHSA-2c9m-w27f-53rm|moderate|tomcat||10.1.0-M1|10.1.6||Apache Tomcat vulnerable to Unprotected Transport of Credentials
CVE-2023-28708|GHSA-2c9m-w27f-53rm|moderate|tomcat||11.0.0-M1|11.0.0-M3||Apache Tomcat vulnerable to Unprotected Transport of Credentials
CVE-2023-28708|GHSA-2c9m-w27f-53rm|moderate|tomcat||8.5.0|8.5.86||Apache Tomcat vulnerable to Unprotected Transport of Credentials
CVE-2023-28708|GHSA-2c9m-w27f-53rm|moderate|tomcat||9.0.0-M1|9.0.72||Apache Tomcat vulnerable to Unprotected Transport of Credentials
CVE-2023-28709|GHSA-cx6h-86xw-9x34|high|tomcat||10.1.5|10.1.8||Apache Tomcat - Fix for CVE-2023-24998 was incomplete
CVE-2023-28709|GHSA-cx6h-86xw-9x34|high|tomcat||11.0.0-M2|11.0.0-M5||Apache Tomcat - Fix for CVE-2023-24998 was incomplete
CVE-2023-28709|GHSA-cx6h-86xw-9x34|high|tomcat||8.5.85|8.5.88||Apache Tomcat - Fix for CVE-2023-24998 was incomplete
CVE-2023-28709|GHSA-cx6h-86xw-9x34|high|tomcat||9.0.71|9.0.74||Apache Tomcat - Fix for CVE-2023-24998 was incomplete
CVE-2023-34981|GHSA-mppv-79ch-vw6q|high|tomcat||10.1.8|10.1.9||Apache Tomcat vulnerable to information leak
CVE-2023-34981|GHSA-mppv-79ch-vw6q|high|tomcat||11.0.0-M5|11.0.0-M6||Apache Tomcat vulnerable to information leak
CVE-2023-34981|GHSA-mppv-79ch-vw6q|high|tomcat||8.5.88|8.5.89||Apache Tomcat vulnerable to information leak
CVE-2023-34981|GHSA-mppv-79ch-vw6q|high|tomcat||9.0.74|9.0.75||Apache Tomcat vulnerable to information leak
CVE-2023-41080|GHSA-q3mw-pvr8-9ggc|moderate|tomcat||10.1.0-M1|10.1.13||Apache Tomcat Open Redirect vulnerability
CVE-2023-41080|GHSA-q3mw-pvr8-9ggc|moderate|tomcat||11.0.0-M1|11.0.0-M11||Apache Tomcat Open Redirect vulnerability
CVE-2023-41080|GHSA-q3mw-pvr8-9ggc|moderate|tomcat||8.5.0|8.5.93||Apache Tomcat Open Redirect vulnerability
CVE-2023-41080|GHSA-q3mw-pvr8-9ggc|moderate|tomcat||9.0.0-M1|9.0.80||Apache Tomcat Open Redirect vulnerability
CVE-2023-42794|GHSA-jm7m-8jh6-29hp|moderate|tomcat||8.5.85|8.5.94||Apache Tomcat Incomplete Cleanup vulnerability
CVE-2023-42794|GHSA-jm7m-8jh6-29hp|moderate|tomcat||9.0.70|9.0.81||Apache Tomcat Incomplete Cleanup vulnerability
CVE-2023-42795|GHSA-g8pj-r55q-5c2v|moderate|tomcat||10.1.0-M1|10.1.14||Apache Tomcat Incomplete Cleanup vulnerability
CVE-2023-42795|GHSA-g8pj-r55q-5c2v|moderate|tomcat||11.0.0-M1|11.0.0-M12||Apache Tomcat Incomplete Cleanup vulnerability
CVE-2023-42795|GHSA-g8pj-r55q-5c2v|moderate|tomcat||8.5.0|8.5.94||Apache Tomcat Incomplete Cleanup vulnerability
CVE-2023-42795|GHSA-g8pj-r55q-5c2v|moderate|tomcat||9.0.0-M1|9.0.81||Apache Tomcat Incomplete Cleanup vulnerability
CVE-2023-44487|GHSA-qppj-fm5r-hxr3|moderate|tomcat||10.0.0|10.1.14||HTTP/2 Stream Cancellation Attack
CVE-2023-44487|GHSA-qppj-fm5r-hxr3|moderate|tomcat||11.0.0-M1|11.0.0-M12||HTTP/2 Stream Cancellation Attack
CVE-2023-44487|GHSA-qppj-fm5r-hxr3|moderate|tomcat||8.5.0|8.5.94||HTTP/2 Stream Cancellation Attack
CVE-2023-44487|GHSA-qppj-fm5r-hxr3|moderate|tomcat||9.0.0|9.0.81||HTTP/2 Stream Cancellation Attack
CVE-2023-45648|GHSA-r6j3-px5g-cq3x|moderate|tomcat||10.1.0-M1|10.1.14||Apache Tomcat Improper Input Validation vulnerability
CVE-2023-45648|GHSA-r6j3-px5g-cq3x|moderate|tomcat||11.0.0-M1|11.0.0-M12||Apache Tomcat Improper Input Validation vulnerability
CVE-2023-45648|GHSA-r6j3-px5g-cq3x|moderate|tomcat||8.5.0|8.5.94||Apache Tomcat Improper Input Validation vulnerability
CVE-2023-45648|GHSA-r6j3-px5g-cq3x|moderate|tomcat||9.0.0-M1|9.0.81||Apache Tomcat Improper Input Validation vulnerability
CVE-2023-46589|GHSA-fccv-jmmp-qg76|high|tomcat||10.1.0-M1|10.1.16||Apache Tomcat Improper Input Validation vulnerability
CVE-2023-46589|GHSA-fccv-jmmp-qg76|high|tomcat||11.0.0-M1|11.0.0-M11||Apache Tomcat Improper Input Validation vulnerability
CVE-2023-46589|GHSA-fccv-jmmp-qg76|high|tomcat||8.5.0|8.5.96||Apache Tomcat Improper Input Validation vulnerability
CVE-2023-46589|GHSA-fccv-jmmp-qg76|high|tomcat||9.0.0-M1|9.0.83||Apache Tomcat Improper Input Validation vulnerability
CVE-2024-21733|GHSA-f4qf-m5gf-8jm8|moderate|tomcat||8.5.7|8.5.64||Apache Tomcat vulnerable to Generation of Error Message Containing Sensitive Information
CVE-2024-21733|GHSA-f4qf-m5gf-8jm8|moderate|tomcat||9.0.0-M11|9.0.44||Apache Tomcat vulnerable to Generation of Error Message Containing Sensitive Information
CVE-2024-24549|GHSA-7w75-32cg-r6g2|moderate|tomcat||10.1.0-M1|10.1.19||Apache Tomcat Denial of Service due to improper input validation vulnerability for HTTP/2 requests
CVE-2024-24549|GHSA-7w75-32cg-r6g2|moderate|tomcat||11.0.0-M1|11.0.0-M17||Apache Tomcat Denial of Service due to improper input validation vulnerability for HTTP/2 requests
CVE-2024-24549|GHSA-7w75-32cg-r6g2|moderate|tomcat||8.5.0|8.5.99||Apache Tomcat Denial of Service due to improper input validation vulnerability for HTTP/2 requests
CVE-2024-24549|GHSA-7w75-32cg-r6g2|moderate|tomcat||9.0.0-M1|9.0.86||Apache Tomcat Denial of Service due to improper input validation vulnerability for HTTP/2 requests
CVE-2024-34750|GHSA-wm9w-rjj3-j356|high|tomcat||10.1.0-M1|10.1.25||Apache Tomcat - Denial of Service
CVE-2024-34750|GHSA-wm9w-rjj3-j356|high|tomcat||11.0.0-M1|11.0.0-M21||Apache Tomcat - Denial of Service
CVE-2024-34750|GHSA-wm9w-rjj3-j356|high|tomcat||8.5.0||8.5.100|Apache Tomcat - Denial of Service
CVE-2024-34750|GHSA-wm9w-rjj3-j356|high|tomcat||9.0.0-M1|9.0.90||Apache Tomcat - Denial of Service
CVE-2024-38286|GHSA-7jqf-v358-p8g7|high|tomcat||10.1.0-M1|10.1.25||Apache Tomcat Allocation of Resources Without Limits or Throttling vulnerability
CVE-2024-38286|GHSA-7jqf-v358-p8g7|high|tomcat||11.0.0-M1|11.0.0-M21||Apache Tomcat Allocation of Resources Without Limits or Throttling vulnerability
CVE-2024-38286|GHSA-7jqf-v358-p8g7|high|tomcat||7.0.92||7.0.109|Apache Tomcat Allocation of Resources Without Limits or Throttling vulnerability
CVE-2024-38286|GHSA-7jqf-v358-p8g7|high|tomcat||8.5.35||8.5.100|Apache Tomcat Allocation of Resources Without Limits or Throttling vulnerability
CVE-2024-38286|GHSA-7jqf-v358-p8g7|high|tomcat||9.0.13|9.0.90||Apache Tomcat Allocation of Resources Without Limits or Throttling vulnerability
CVE-2024-50379|GHSA-5j33-cvvr-w245|high|tomcat||10.1.0-M1|10.1.34||Apache Tomcat Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability
CVE-2024-50379|GHSA-5j33-cvvr-w245|high|tomcat||11.0.0-M1|11.0.2||Apache Tomcat Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability
CVE-2024-50379|GHSA-5j33-cvvr-w245|high|tomcat||8.5.0||8.5.100|Apache Tomcat Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability
CVE-2024-50379|GHSA-5j33-cvvr-w245|high|tomcat||9.0.0.M1|9.0.98||Apache Tomcat Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability
CVE-2024-52316|GHSA-xcpr-7mr4-h4xq|critical|tomcat||0|9.0.96||Apache Tomcat - Authentication Bypass
CVE-2024-52316|GHSA-xcpr-7mr4-h4xq|critical|tomcat||10.1.0-M1|10.1.30||Apache Tomcat - Authentication Bypass
CVE-2024-52316|GHSA-xcpr-7mr4-h4xq|critical|tomcat||11.0.0-M1|11.0.1||Apache Tomcat - Authentication Bypass
CVE-2024-52317|GHSA-qvf5-hvjx-wm27|moderate|tomcat||10.1.27|10.1.31||Apache Tomcat Request and/or response mix-up
CVE-2024-52317|GHSA-qvf5-hvjx-wm27|moderate|tomcat||11.0.0-M23|11.0.0||Apache Tomcat Request and/or response mix-up
CVE-2024-52317|GHSA-qvf5-hvjx-wm27|moderate|tomcat||9.0.92|9.0.96||Apache Tomcat Request and/or response mix-up
CVE-2024-52318|GHSA-f632-9449-3j4w|moderate|tomcat||10.1.31|10.1.32||Apache Tomcat - XSS in generated JSPs
CVE-2024-52318|GHSA-f632-9449-3j4w|moderate|tomcat||11.0.0|11.0.1||Apache Tomcat - XSS in generated JSPs
CVE-2024-52318|GHSA-f632-9449-3j4w|moderate|tomcat||9.0.96|9.0.97||Apache Tomcat - XSS in generated JSPs
CVE-2024-54677|GHSA-653p-vg55-5652|moderate|tomcat||10.1.0-M1|10.1.34||Apache Tomcat Uncontrolled Resource Consumption vulnerability
CVE-2024-54677|GHSA-653p-vg55-5652|moderate|tomcat||11.0.0-M1|11.0.2||Apache Tomcat Uncontrolled Resource Consumption vulnerability
CVE-2024-54677|GHSA-653p-vg55-5652|moderate|tomcat||9.0.0.M1|9.0.98||Apache Tomcat Uncontrolled Resource Consumption vulnerability
CVE-2024-56337|GHSA-27hp-xhwr-wr2m|high|tomcat||10.1.0-M1|10.1.34||Apache Tomcat Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability
CVE-2024-56337|GHSA-27hp-xhwr-wr2m|high|tomcat||11.0.0-M1|11.0.2||Apache Tomcat Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability
CVE-2024-56337|GHSA-27hp-xhwr-wr2m|high|tomcat||9.0.0.M1|9.0.98||Apache Tomcat Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability
CVE-2025-24813|GHSA-83qj-6fr2-vhqg|critical|tomcat||10.1.0-M1|10.1.35||Apache Tomcat: Potential RCE and/or information disclosure and/or information corruption with partial PUT
CVE-2025-24813|GHSA-83qj-6fr2-vhqg|critical|tomcat||11.0.0-M1|11.0.3||Apache Tomcat: Potential RCE and/or information disclosure and/or information corruption with partial PUT
CVE-2025-24813|GHSA-83qj-6fr2-vhqg|critical|tomcat||8.5.0||8.5.100|Apache Tomcat: Potential RCE and/or information disclosure and/or information corruption with partial PUT
CVE-2025-24813|GHSA-83qj-6fr2-vhqg|critical|tomcat||9.0.0.M1|9.0.99||Apache Tomcat: Potential RCE and/or information disclosure and/or information corruption with partial PUT
CVE-2025-31650|GHSA-3p2h-wqq4-wf4h|moderate|tomcat||10.1.10|10.1.40||Apache Tomcat Denial of Service via invalid HTTP priority header
CVE-2025-31650|GHSA-3p2h-wqq4-wf4h|moderate|tomcat||11.0.0-M2|11.0.6||Apache Tomcat Denial of Service via invalid HTTP priority header
CVE-2025-31650|GHSA-3p2h-wqq4-wf4h|moderate|tomcat||8.5.0||8.5.100|Apache Tomcat Denial of Service via invalid HTTP priority header
CVE-2025-31650|GHSA-3p2h-wqq4-wf4h|moderate|tomcat||9.0.76|9.0.104||Apache Tomcat Denial of Service via invalid HTTP priority header
CVE-2025-31651|GHSA-ff77-26x5-69cr|low|tomcat||10.1.10|10.1.40||Apache Tomcat Rewrite rule bypass
CVE-2025-31651|GHSA-ff77-26x5-69cr|low|tomcat||11.0.0-M2|11.0.6||Apache Tomcat Rewrite rule bypass
CVE-2025-31651|GHSA-ff77-26x5-69cr|low|tomcat||8.5.0||8.5.100|Apache Tomcat Rewrite rule bypass
CVE-2025-31651|GHSA-ff77-26x5-69cr|low|tomcat||9.0.76|9.0.104||Apache Tomcat Rewrite rule bypass
CVE-2025-46701|GHSA-h2fw-rfh5-95r3|low|tomcat||10.1.0-M1|10.1.41||Apache Tomcat - CGI security constraint bypass
CVE-2025-46701|GHSA-h2fw-rfh5-95r3|low|tomcat||11.0.0-M1|11.0.7||Apache Tomcat - CGI security constraint bypass
CVE-2025-46701|GHSA-h2fw-rfh5-95r3|low|tomcat||8.5.0||8.5.100|Apache Tomcat - CGI security constraint bypass
CVE-2025-46701|GHSA-h2fw-rfh5-95r3|low|tomcat||9.0.0.M1|9.0.105||Apache Tomcat - CGI security constraint bypass
CVE-2025-48988|GHSA-h3gc-qfqq-6h8f|high|tomcat||10.1.0-M1|10.1.42||Apache Tomcat - DoS in multipart upload
CVE-2025-48988|GHSA-h3gc-qfqq-6h8f|high|tomcat||11.0.0-M1|11.0.8||Apache Tomcat - DoS in multipart upload
CVE-2025-48988|GHSA-h3gc-qfqq-6h8f|high|tomcat||8.5.0||8.5.100|Apache Tomcat - DoS in multipart upload
CVE-2025-48988|GHSA-h3gc-qfqq-6h8f|high|tomcat||9.0.0.M1|9.0.106||Apache Tomcat - DoS in multipart upload
CVE-2025-48989|GHSA-gqp3-2cvr-x8m3|high|tomcat||10.1.0-M1|10.1.44||Apache Tomcat Improper Resource Shutdown or Release vulnerability
CVE-2025-48989|GHSA-gqp3-2cvr-x8m3|high|tomcat||11.0.0-M1|11.0.10||Apache Tomcat Improper Resource Shutdown or Release vulnerability
CVE-2025-48989|GHSA-gqp3-2cvr-x8m3|high|tomcat||9.0.0.M1|9.0.108||Apache Tomcat Improper Resource Shutdown or Release vulnerability
CVE-2025-49124|GHSA-42wg-hm62-jcwg|moderate|tomcat||10.1.0|10.1.42||Apache Tomcat installer for Windows has an untrusted search path vulnerability
CVE-2025-49124|GHSA-42wg-hm62-jcwg|moderate|tomcat||11.0.0-M1|11.0.8||Apache Tomcat installer for Windows has an untrusted search path vulnerability
CVE-2025-49124|GHSA-42wg-hm62-jcwg|moderate|tomcat||9.0.23|9.0.106||Apache Tomcat installer for Windows has an untrusted search path vulnerability
CVE-2025-49125|GHSA-wc4r-xq3c-5cf3|moderate|tomcat||10.1.0-M1|10.1.42||Apache Tomcat - Security constraint bypass for pre/post-resources
CVE-2025-49125|GHSA-wc4r-xq3c-5cf3|moderate|tomcat||11.0.0-M1|11.0.8||Apache Tomcat - Security constraint bypass for pre/post-resources
CVE-2025-49125|GHSA-wc4r-xq3c-5cf3|moderate|tomcat||8.5.0||8.5.100|Apache Tomcat - Security constraint bypass for pre/post-resources
CVE-2025-49125|GHSA-wc4r-xq3c-5cf3|moderate|tomcat||9.0.0.M1|9.0.106||Apache Tomcat - Security constraint bypass for pre/post-resources
CVE-2025-52434|GHSA-4j3c-42xv-3f84|moderate|tomcat||8.5.0||8.5.100|Apache Tomcat is vulnerable to resource exhaustion when using the APR/Native connector
CVE-2025-52434|GHSA-4j3c-42xv-3f84|moderate|tomcat||9.0.0.M1|9.0.107||Apache Tomcat is vulnerable to resource exhaustion when using the APR/Native connector
CVE-2025-52520|GHSA-wr62-c79q-cv37|high|tomcat||10.1.0-M1|10.1.43||Apache Tomcat Catalina is vulnerable to DoS attack through bypassing of size limits
CVE-2025-52520|GHSA-wr62-c79q-cv37|high|tomcat||11.0.0-M1|11.0.9||Apache Tomcat Catalina is vulnerable to DoS attack through bypassing of size limits
CVE-2025-52520|GHSA-wr62-c79q-cv37|high|tomcat||8.5.0||8.5.100|Apache Tomcat Catalina is vulnerable to DoS attack through bypassing of size limits
CVE-2025-52520|GHSA-wr62-c79q-cv37|high|tomcat||9.0.0.M1|9.0.107||Apache Tomcat Catalina is vulnerable to DoS attack through bypassing of size limits
CVE-2025-53506|GHSA-25xr-qj8w-c4vf|high|tomcat||10.1.0-M1|10.1.43||Apache Tomcat Coyote vulnerable to Denial of Service via excessive HTTP/2 streams
CVE-2025-53506|GHSA-25xr-qj8w-c4vf|high|tomcat||11.0.0-M1|11.0.9||Apache Tomcat Coyote vulnerable to Denial of Service via excessive HTTP/2 streams
CVE-2025-53506|GHSA-25xr-qj8w-c4vf|high|tomcat||8.5.0||8.5.100|Apache Tomcat Coyote vulnerable to Denial of Service via excessive HTTP/2 streams
CVE-2025-53506|GHSA-25xr-qj8w-c4vf|high|tomcat||9.0.0.M1|9.0.107||Apache Tomcat Coyote vulnerable to Denial of Service via excessive HTTP/2 streams
CVE-2025-55668|GHSA-23hv-mwm6-g8jf|moderate|tomcat||10.1.0-M1|10.1.42||Apache Tomcat Session Fixation vulnerability
CVE-2025-55668|GHSA-23hv-mwm6-g8jf|moderate|tomcat||11.0.0-M1|11.0.8||Apache Tomcat Session Fixation vulnerability
CVE-2025-55668|GHSA-23hv-mwm6-g8jf|moderate|tomcat||9.0.0.M1|9.0.106||Apache Tomcat Session Fixation vulnerability
CVE-2025-55752|GHSA-wmwf-9ccg-fff5|high|tomcat||10.1.0-M1|10.1.45||Apache Tomcat Vulnerable to Relative Path Traversal
CVE-2025-55752|GHSA-wmwf-9ccg-fff5|high|tomcat||11.0.0-M1|11.0.11||Apache Tomcat Vulnerable to Relative Path Traversal
CVE-2025-55752|GHSA-wmwf-9ccg-fff5|high|tomcat||8.5.6||8.5.100|Apache Tomcat Vulnerable to Relative Path Traversal
CVE-2025-55752|GHSA-wmwf-9ccg-fff5|high|tomcat||9.0.0-M11|9.0.109||Apache Tomcat Vulnerable to Relative Path Traversal
CVE-2025-55754|GHSA-vfww-5hm6-hx2j|low|tomcat||10.1.0-M1|10.1.45||Apache Tomcat Vulnerable to Improper Neutralization of Escape, Meta, or Control Sequences
CVE-2025-55754|GHSA-vfww-5hm6-hx2j|low|tomcat||11.0.0-M1|11.0.11||Apache Tomcat Vulnerable to Improper Neutralization of Escape, Meta, or Control Sequences
CVE-2025-55754|GHSA-vfww-5hm6-hx2j|low|tomcat||8.5.60||8.5.100|Apache Tomcat Vulnerable to Improper Neutralization of Escape, Meta, or Control Sequences
CVE-2025-55754|GHSA-vfww-5hm6-hx2j|low|tomcat||9.0.40|9.0.109||Apache Tomcat Vulnerable to Improper Neutralization of Escape, Meta, or Control Sequences
CVE-2025-61795|GHSA-hgrr-935x-pq79|low|tomcat||10.1.0-M1|10.1.47||Apache Tomcat Vulnerable to Improper Resource Shutdown or Release
CVE-2025-61795|GHSA-hgrr-935x-pq79|low|tomcat||11.0.0-M1|11.0.12||Apache Tomcat Vulnerable to Improper Resource Shutdown or Release
CVE-2025-61795|GHSA-hgrr-935x-pq79|low|tomcat||8.5.0||8.5.100|Apache Tomcat Vulnerable to Improper Resource Shutdown or Release
CVE-2025-61795|GHSA-hgrr-935x-pq79|low|tomcat||9.0.0.M1|9.0.110||Apache Tomcat Vulnerable to Improper Resource Shutdown or Release
CVE-2025-66614|GHSA-fpj8-gq4v-p354|moderate|tomcat||10.1.0-M1|10.1.50||Apache Tomcat - Client certificate verification bypass
CVE-2025-66614|GHSA-fpj8-gq4v-p354|moderate|tomcat||11.0.0-M1|11.0.15||Apache Tomcat - Client certificate verification bypass
CVE-2025-66614|GHSA-fpj8-gq4v-p354|moderate|tomcat||8.5.0||8.5.100|Apache Tomcat - Client certificate verification bypass
CVE-2025-66614|GHSA-fpj8-gq4v-p354|moderate|tomcat||9.0.0-M1|9.0.113||Apache Tomcat - Client certificate verification bypass
CVE-2026-24733|GHSA-qq5r-98hh-rxc9|low|tomcat||0|9.0.113||Apache Tomcat - Security constraint bypass with HTTP/0.9
CVE-2026-24733|GHSA-qq5r-98hh-rxc9|low|tomcat||10.1.0-M1|10.1.50||Apache Tomcat - Security constraint bypass with HTTP/0.9
CVE-2026-24733|GHSA-qq5r-98hh-rxc9|low|tomcat||11.0.0-M1|11.0.15||Apache Tomcat - Security constraint bypass with HTTP/0.9
CVE-2026-24734|GHSA-mgp5-rv84-w37q|high|tomcat||10.1.0-M7|10.1.52||Apache Tomcat has an Improper Input Validation vulnerability
CVE-2026-24734|GHSA-mgp5-rv84-w37q|high|tomcat||11.0.0-M1|11.0.18||Apache Tomcat has an Improper Input Validation vulnerability
CVE-2026-24734|GHSA-mgp5-rv84-w37q|high|tomcat||9.0.83|9.0.115||Apache Tomcat has an Improper Input Validation vulnerability
CVE-2026-24880|GHSA-563x-q5rq-57qp|high|tomcat||10.1.0-M1|10.1.52||Apache Tomcat has an HTTP Request/Response Smuggling vulnerability
CVE-2026-24880|GHSA-563x-q5rq-57qp|high|tomcat||11.0.0-M1|11.0.20||Apache Tomcat has an HTTP Request/Response Smuggling vulnerability
CVE-2026-24880|GHSA-563x-q5rq-57qp|high|tomcat||7.0.0|9.0.116||Apache Tomcat has an HTTP Request/Response Smuggling vulnerability
CVE-2026-25854|GHSA-9m3c-qcxr-9x87|moderate|tomcat||10.1.0-M1|10.1.53||Apache Tomcat has an Open Redirect vulnerability
CVE-2026-25854|GHSA-9m3c-qcxr-9x87|moderate|tomcat||11.0.0-M1|11.0.20||Apache Tomcat has an Open Redirect vulnerability
CVE-2026-25854|GHSA-9m3c-qcxr-9x87|moderate|tomcat||8.5.30|9.0.116||Apache Tomcat has an Open Redirect vulnerability
CVE-2026-29129|GHSA-69cc-cv78-qc8g|high|tomcat||10.1.51|10.1.53||Apache Tomcat: Configured cipher preference order not preserved
CVE-2026-29129|GHSA-69cc-cv78-qc8g|high|tomcat||11.0.16|11.0.20||Apache Tomcat: Configured cipher preference order not preserved
CVE-2026-29129|GHSA-69cc-cv78-qc8g|high|tomcat||9.0.114|9.0.116||Apache Tomcat: Configured cipher preference order not preserved
CVE-2026-29145|GHSA-95jq-rwvf-vjx4|critical|tomcat||10.1.0-M7|10.1.53||Apache Tomcat: CLIENT_CERT authentication does not fail as expected
CVE-2026-29145|GHSA-95jq-rwvf-vjx4|critical|tomcat||11.0.0-M1|11.0.20||Apache Tomcat: CLIENT_CERT authentication does not fail as expected
CVE-2026-29145|GHSA-95jq-rwvf-vjx4|critical|tomcat||9.0.83|9.0.116||Apache Tomcat: CLIENT_CERT authentication does not fail as expected
CVE-2026-29146|GHSA-h468-7pvh-8vr8|high|tomcat||10.1.50|10.1.53||Apache Tomcat: Padding Oracle vulnerability in EncryptInterceptor
CVE-2026-29146|GHSA-h468-7pvh-8vr8|high|tomcat||11.0.0-M1|11.0.20||Apache Tomcat: Padding Oracle vulnerability in EncryptInterceptor
CVE-2026-29146|GHSA-h468-7pvh-8vr8|high|tomcat||7.0.100||7.0.109|Apache Tomcat: Padding Oracle vulnerability in EncryptInterceptor
CVE-2026-29146|GHSA-h468-7pvh-8vr8|high|tomcat||8.5.38||8.5.100|Apache Tomcat: Padding Oracle vulnerability in EncryptInterceptor
CVE-2026-29146|GHSA-h468-7pvh-8vr8|high|tomcat||9.0.13|9.0.116||Apache Tomcat: Padding Oracle vulnerability in EncryptInterceptor
CVE-2026-32990|GHSA-8mc5-53m5-3qj2|moderate|tomcat||10.1.50|10.1.53||Apache Tomcat has an Improper Input Validation vulnerability
CVE-2026-32990|GHSA-8mc5-53m5-3qj2|moderate|tomcat||11.0.15|11.0.20||Apache Tomcat has an Improper Input Validation vulnerability
CVE-2026-32990|GHSA-8mc5-53m5-3qj2|moderate|tomcat||9.0.113|9.0.116||Apache Tomcat has an Improper Input Validation vulnerability
CVE-2026-34483|GHSA-rv64-5gf8-9qq8|high|tomcat||10.1.0-M1|10.1.54||Apache Tomcat has an Improper Encoding or Escaping of Output vulnerability in the JsonAccessLogValve
CVE-2026-34483|GHSA-rv64-5gf8-9qq8|high|tomcat||11.0.0-M1|11.0.21||Apache Tomcat has an Improper Encoding or Escaping of Output vulnerability in the JsonAccessLogValve
CVE-2026-34483|GHSA-rv64-5gf8-9qq8|high|tomcat||9.0.40|9.0.116||Apache Tomcat has an Improper Encoding or Escaping of Output vulnerability in the JsonAccessLogValve
CVE-2026-34486|GHSA-69r9-qgr7-g2wj|high|tomcat||10.1.53|10.1.54||Apache Tomcat Missing Encryption of Sensitive Data vulnerability
CVE-2026-34486|GHSA-69r9-qgr7-g2wj|high|tomcat||11.0.20|11.0.21||Apache Tomcat Missing Encryption of Sensitive Data vulnerability
CVE-2026-34486|GHSA-69r9-qgr7-g2wj|high|tomcat||9.0.116|9.0.117||Apache Tomcat Missing Encryption of Sensitive Data vulnerability
CVE-2026-34487|GHSA-x4m4-345f-5h5g|high|tomcat||10.1.0-M1|10.1.54||Apache Tomcat vulnerable to Insertion of Sensitive Information into Log File
CVE-2026-34487|GHSA-x4m4-345f-5h5g|high|tomcat||11.0.0-M1|11.0.21||Apache Tomcat vulnerable to Insertion of Sensitive Information into Log File
CVE-2026-34487|GHSA-x4m4-345f-5h5g|high|tomcat||9.0.13|9.0.117||Apache Tomcat vulnerable to Insertion of Sensitive Information into Log File
CVE-2026-41284|GHSA-gx5v-xp9w-j4cg|high|tomcat||0|9.0.118||Apache Tomcat: Unbounded read in WebDAV LOCK and PROPFIND handling
CVE-2026-41284|GHSA-gx5v-xp9w-j4cg|high|tomcat||10.1.0-M1|10.1.55||Apache Tomcat: Unbounded read in WebDAV LOCK and PROPFIND handling
CVE-2026-41284|GHSA-gx5v-xp9w-j4cg|high|tomcat||11.0.0-M1|11.0.22||Apache Tomcat: Unbounded read in WebDAV LOCK and PROPFIND handling
CVE-2026-41293|GHSA-r29c-68gh-xp6x|critical|tomcat||10.1.0-M1|10.1.55||Apache Tomcat - HTTP/2 request headers not validated
CVE-2026-41293|GHSA-r29c-68gh-xp6x|critical|tomcat||11.0.0-M1|11.0.22||Apache Tomcat - HTTP/2 request headers not validated
CVE-2026-41293|GHSA-r29c-68gh-xp6x|critical|tomcat||8.5.0|9.0.118||Apache Tomcat - HTTP/2 request headers not validated
CVE-2026-42498|GHSA-fv25-8xcx-gqjc|high|tomcat||0|9.0.118||Apache Tomcat - WebSocket authentication header exposure
CVE-2026-42498|GHSA-fv25-8xcx-gqjc|high|tomcat||10.1.0-M1|10.1.55||Apache Tomcat - WebSocket authentication header exposure
CVE-2026-42498|GHSA-fv25-8xcx-gqjc|high|tomcat||11.0.0-M1|11.0.22||Apache Tomcat - WebSocket authentication header exposure
CVE-2026-43512|GHSA-h6fc-48rj-7qqh|critical|tomcat||0|9.0.118||Apache Tomcat - Digest authenticator will authenticate any unknown user
CVE-2026-43512|GHSA-h6fc-48rj-7qqh|critical|tomcat||10.1.0-M1|10.1.55||Apache Tomcat - Digest authenticator will authenticate any unknown user
CVE-2026-43512|GHSA-h6fc-48rj-7qqh|critical|tomcat||11.0.0-M1|11.0.22||Apache Tomcat - Digest authenticator will authenticate any unknown user
CVE-2026-43513|GHSA-5mp6-jrq3-r938|high|tomcat||0|9.0.118||Apache Tomcat: LockOutRealm treats user names as case-sensitive
CVE-2026-43513|GHSA-5mp6-jrq3-r938|high|tomcat||10.1.0-M1|10.1.55||Apache Tomcat: LockOutRealm treats user names as case-sensitive
CVE-2026-43513|GHSA-5mp6-jrq3-r938|high|tomcat||11.0.0-M1|11.0.22||Apache Tomcat: LockOutRealm treats user names as case-sensitive
CVE-2026-43514|GHSA-9m89-8frq-c98c|low|tomcat||0|9.0.118||Apache Tomcat - AJP secret compared in non-constant time
CVE-2026-43514|GHSA-9m89-8frq-c98c|low|tomcat||10.1.0-M1|10.1.55||Apache Tomcat - AJP secret compared in non-constant time
CVE-2026-43514|GHSA-9m89-8frq-c98c|low|tomcat||11.0.0-M1|11.0.22||Apache Tomcat - AJP secret compared in non-constant time
CVE-2026-43515|GHSA-5m62-pw8w-7w9f|critical|tomcat||0|9.0.118||Apache Tomcat - Security constraints not correctly applied
CVE-2026-43515|GHSA-5m62-pw8w-7w9f|critical|tomcat||10.1.0-M1|10.1.55||Apache Tomcat - Security constraints not correctly applied
CVE-2026-43515|GHSA-5m62-pw8w-7w9f|critical|tomcat||11.0.0-M1|11.0.22||Apache Tomcat - Security constraints not correctly applied
CVE-2026-53434|GHSA-4x29-79gh-6v8q|critical|tomcat||10.1.0-M7|10.1.56||Apache Tomcat util accepted misconfigured CRLs
CVE-2026-53434|GHSA-4x29-79gh-6v8q|critical|tomcat||11.0.0-M1|11.0.23||Apache Tomcat util accepted misconfigured CRLs
CVE-2026-53434|GHSA-4x29-79gh-6v8q|critical|tomcat||9.0.83|9.0.119||Apache Tomcat util accepted misconfigured CRLs
CVE-2026-65182|GHSA-gcx9-497g-6cp6|critical|tomcat||10.1.0-M1|10.1.58||Apache Tomcat has an Improper Access Control, Incorrect Authorization vulnerability
CVE-2026-65182|GHSA-gcx9-497g-6cp6|critical|tomcat||11.0.0-M1|11.0.25||Apache Tomcat has an Improper Access Control, Incorrect Authorization vulnerability
CVE-2026-65182|GHSA-gcx9-497g-6cp6|critical|tomcat||7.0.0||7.0.109|Apache Tomcat has an Improper Access Control, Incorrect Authorization vulnerability
CVE-2026-65182|GHSA-gcx9-497g-6cp6|critical|tomcat||8.5.0||8.5.100|Apache Tomcat has an Improper Access Control, Incorrect Authorization vulnerability
CVE-2026-65182|GHSA-gcx9-497g-6cp6|critical|tomcat||9.0.0-M1|9.0.121||Apache Tomcat has an Improper Access Control, Incorrect Authorization vulnerability
CVE-2026-65637|GHSA-f525-44xv-f2qj|critical|tomcat||10.1.53|10.1.59||Apache Tomcat - HTTP/2 no-authority bypass of strict SNI validation
CVE-2026-65637|GHSA-f525-44xv-f2qj|critical|tomcat||11.0.20|11.0.25||Apache Tomcat - HTTP/2 no-authority bypass of strict SNI validation
CVE-2026-65637|GHSA-f525-44xv-f2qj|critical|tomcat||9.0.115|9.0.121||Apache Tomcat - HTTP/2 no-authority bypass of strict SNI validation
CVE-2026-65905|GHSA-9xv2-5v5q-p794|critical|tomcat||10.1.0-M1|10.1.58||Apache Tomcat's DIGEST authenticator has an Authentication Bypass by Capture-replay vulnerability
CVE-2026-65905|GHSA-9xv2-5v5q-p794|critical|tomcat||11.0.0-M1|11.0.25||Apache Tomcat's DIGEST authenticator has an Authentication Bypass by Capture-replay vulnerability
CVE-2026-65905|GHSA-9xv2-5v5q-p794|critical|tomcat||7.0.30||7.0.109|Apache Tomcat's DIGEST authenticator has an Authentication Bypass by Capture-replay vulnerability
CVE-2026-65905|GHSA-9xv2-5v5q-p794|critical|tomcat||8.5.0||8.5.100|Apache Tomcat's DIGEST authenticator has an Authentication Bypass by Capture-replay vulnerability
CVE-2026-65905|GHSA-9xv2-5v5q-p794|critical|tomcat||9.0.0.M1|9.0.121||Apache Tomcat's DIGEST authenticator has an Authentication Bypass by Capture-replay vulnerability
CVE-2026-68525|GHSA-h3x4-894j-xpx5|critical|tomcat||10.1.0-M1|10.1.58||Apache Tomcat's FORM authentication process has an Incorrect Authorization vulnerability
CVE-2026-68525|GHSA-h3x4-894j-xpx5|critical|tomcat||11.0.0-M1|11.0.25||Apache Tomcat's FORM authentication process has an Incorrect Authorization vulnerability
CVE-2026-68525|GHSA-h3x4-894j-xpx5|critical|tomcat||7.0.0||7.0.109|Apache Tomcat's FORM authentication process has an Incorrect Authorization vulnerability
CVE-2026-68525|GHSA-h3x4-894j-xpx5|critical|tomcat||8.5.0||8.5.100|Apache Tomcat's FORM authentication process has an Incorrect Authorization vulnerability
CVE-2026-68525|GHSA-h3x4-894j-xpx5|critical|tomcat||9.0.0-M1|9.0.121||Apache Tomcat's FORM authentication process has an Incorrect Authorization vulnerability
CVE-2016-8735|GHSA-cw54-59pw-4g8c|critical|tomcat-catalina-jmx-remote||0|6.0.48||Apache Tomcat Improper Access Control vulnerability
CVE-2016-8735|GHSA-cw54-59pw-4g8c|critical|tomcat-catalina-jmx-remote||7.0.0|7.0.73||Apache Tomcat Improper Access Control vulnerability
CVE-2016-8735|GHSA-cw54-59pw-4g8c|critical|tomcat-catalina-jmx-remote||8.0.0|8.0.39||Apache Tomcat Improper Access Control vulnerability
CVE-2016-8735|GHSA-cw54-59pw-4g8c|critical|tomcat-catalina-jmx-remote||8.5.0|8.5.7||Apache Tomcat Improper Access Control vulnerability
CVE-2016-8735|GHSA-cw54-59pw-4g8c|critical|tomcat-catalina-jmx-remote||9.0.0.M1|9.0.0.M12||Apache Tomcat Improper Access Control vulnerability
CVE-2026-29145|GHSA-95jq-rwvf-vjx4|critical|tomcat-coyote-ffm||10.1.0-M7|10.1.53||Apache Tomcat: CLIENT_CERT authentication does not fail as expected
CVE-2026-29145|GHSA-95jq-rwvf-vjx4|critical|tomcat-coyote-ffm||11.0.0-M1|11.0.20||Apache Tomcat: CLIENT_CERT authentication does not fail as expected
CVE-2026-29145|GHSA-95jq-rwvf-vjx4|critical|tomcat-coyote-ffm||9.0.83|9.0.116||Apache Tomcat: CLIENT_CERT authentication does not fail as expected
CVE-2026-34500|GHSA-24j9-x2wg-9qv6|moderate|tomcat-coyote-ffm||10.1.22|10.1.54||Apache Tomcat: CLIENT_CERT authentication does not fail as expected
CVE-2026-34500|GHSA-24j9-x2wg-9qv6|moderate|tomcat-coyote-ffm||11.0.0-M14|11.0.21||Apache Tomcat: CLIENT_CERT authentication does not fail as expected
CVE-2026-34500|GHSA-24j9-x2wg-9qv6|moderate|tomcat-coyote-ffm||9.0.92|9.0.117||Apache Tomcat: CLIENT_CERT authentication does not fail as expected
CVE-2014-0119|GHSA-prc3-7f44-w48j|moderate|tomcat-jasper||0|6.0.40||Missing XML Validation in Apache Tomcat
CVE-2014-0119|GHSA-prc3-7f44-w48j|moderate|tomcat-jasper||7.0.0|7.0.54||Missing XML Validation in Apache Tomcat
CVE-2014-0119|GHSA-prc3-7f44-w48j|moderate|tomcat-jasper||8.0.0|8.0.6||Missing XML Validation in Apache Tomcat
CVE-2016-5018|GHSA-4v3g-g84w-hv7r|critical|tomcat-jasper||6.0.0|6.0.47||Authentication Bypass Using an Alternate Path or Channel in Apache Tomcat
CVE-2016-5018|GHSA-4v3g-g84w-hv7r|critical|tomcat-jasper||7.0.0|7.0.72||Authentication Bypass Using an Alternate Path or Channel in Apache Tomcat
CVE-2016-5018|GHSA-4v3g-g84w-hv7r|critical|tomcat-jasper||8.0.0RC1|8.0.37||Authentication Bypass Using an Alternate Path or Channel in Apache Tomcat
CVE-2016-5018|GHSA-4v3g-g84w-hv7r|critical|tomcat-jasper||8.5.0|8.5.5||Authentication Bypass Using an Alternate Path or Channel in Apache Tomcat
CVE-2016-5018|GHSA-4v3g-g84w-hv7r|critical|tomcat-jasper||9.0.0.M1|9.0.0.M10||Authentication Bypass Using an Alternate Path or Channel in Apache Tomcat
CVE-2024-52318|GHSA-f632-9449-3j4w|moderate|tomcat-jasper||10.1.31|10.1.32||Apache Tomcat - XSS in generated JSPs
CVE-2024-52318|GHSA-f632-9449-3j4w|moderate|tomcat-jasper||11.0.0|11.0.1||Apache Tomcat - XSS in generated JSPs
CVE-2024-52318|GHSA-f632-9449-3j4w|moderate|tomcat-jasper||9.0.96|9.0.97||Apache Tomcat - XSS in generated JSPs
CVE-2026-29146|GHSA-h468-7pvh-8vr8|high|tomcat-tribes||10.1.50|10.1.53||Apache Tomcat: Padding Oracle vulnerability in EncryptInterceptor
CVE-2026-29146|GHSA-h468-7pvh-8vr8|high|tomcat-tribes||11.0.0-M1|11.0.20||Apache Tomcat: Padding Oracle vulnerability in EncryptInterceptor
CVE-2026-29146|GHSA-h468-7pvh-8vr8|high|tomcat-tribes||7.0.100||7.0.109|Apache Tomcat: Padding Oracle vulnerability in EncryptInterceptor
CVE-2026-29146|GHSA-h468-7pvh-8vr8|high|tomcat-tribes||8.5.38||8.5.100|Apache Tomcat: Padding Oracle vulnerability in EncryptInterceptor
CVE-2026-29146|GHSA-h468-7pvh-8vr8|high|tomcat-tribes||9.0.13|9.0.116||Apache Tomcat: Padding Oracle vulnerability in EncryptInterceptor
CVE-2026-34486|GHSA-69r9-qgr7-g2wj|high|tomcat-tribes||10.1.53|10.1.54||Apache Tomcat Missing Encryption of Sensitive Data vulnerability
CVE-2026-34486|GHSA-69r9-qgr7-g2wj|high|tomcat-tribes||11.0.20|11.0.21||Apache Tomcat Missing Encryption of Sensitive Data vulnerability
CVE-2026-34486|GHSA-69r9-qgr7-g2wj|high|tomcat-tribes||9.0.116|9.0.117||Apache Tomcat Missing Encryption of Sensitive Data vulnerability
CVE-2026-34487|GHSA-x4m4-345f-5h5g|high|tomcat-tribes||10.1.0-M1|10.1.54||Apache Tomcat vulnerable to Insertion of Sensitive Information into Log File
CVE-2026-34487|GHSA-x4m4-345f-5h5g|high|tomcat-tribes||11.0.0-M1|11.0.21||Apache Tomcat vulnerable to Insertion of Sensitive Information into Log File
CVE-2026-34487|GHSA-x4m4-345f-5h5g|high|tomcat-tribes||9.0.13|9.0.117||Apache Tomcat vulnerable to Insertion of Sensitive Information into Log File
CVE-2020-13935|GHSA-m7jv-hq7h-mq7c|high|tomcat-websocket||10.0.0-M1|10.0.0-M7||Infinite Loop in Apache Tomcat
CVE-2020-13935|GHSA-m7jv-hq7h-mq7c|high|tomcat-websocket||7.0.27|7.0.105||Infinite Loop in Apache Tomcat
CVE-2020-13935|GHSA-m7jv-hq7h-mq7c|high|tomcat-websocket||8.5.0|8.5.57||Infinite Loop in Apache Tomcat
CVE-2020-13935|GHSA-m7jv-hq7h-mq7c|high|tomcat-websocket||9.0.0.M1|9.0.37||Infinite Loop in Apache Tomcat
CVE-2024-23672|GHSA-v682-8vv8-vpwr|moderate|tomcat-websocket||10.1.0-M1|10.1.19||Denial of Service via incomplete cleanup vulnerability in Apache Tomcat
CVE-2024-23672|GHSA-v682-8vv8-vpwr|moderate|tomcat-websocket||11.0.0-M1|11.0.0-M17||Denial of Service via incomplete cleanup vulnerability in Apache Tomcat
CVE-2024-23672|GHSA-v682-8vv8-vpwr|moderate|tomcat-websocket||8.5.0|8.5.99||Denial of Service via incomplete cleanup vulnerability in Apache Tomcat
CVE-2024-23672|GHSA-v682-8vv8-vpwr|moderate|tomcat-websocket||9.0.0-M1|9.0.86||Denial of Service via incomplete cleanup vulnerability in Apache Tomcat
# --- CVE_DB 끝 ---
EOF
CVE_SRC="스크립트 내장본 (OSV 2026-11-02 기준, $(grep -c '^CVE-' "$CVE_DB" | tr -d ' ')줄)"
# 대시보드가 내려 준 최신 목록이 있으면 그것을 사용 (형식에 맞는 줄만 받아들임)
if [ -n "${PRECHECK_CVE_DB:-}" ] && [ -r "$PRECHECK_CVE_DB" ]; then
  grep -E '^CVE-[0-9]{4}-[0-9]{4,7}\|[A-Za-z0-9-]*\|[a-z]+\|[A-Za-z0-9._-]+\|[A-Za-z0-9._-]*\|[A-Za-z0-9._-]*\|[A-Za-z0-9._-]*\|[A-Za-z0-9._-]*\|[^|]*$' "$PRECHECK_CVE_DB" > "$WORK/cve_ext.txt"
  if [ -s "$WORK/cve_ext.txt" ]; then
    mv "$WORK/cve_ext.txt" "$CVE_DB"
    GEN="$(sed -n 's/^# GENERATED=//p' "$PRECHECK_CVE_DB" | head -n1 | tr -cd '[:alnum:] :._-')"
    CVE_SRC="대시보드 자동 업데이트본 (생성 ${GEN:-?}, $(wc -l < "$CVE_DB" | tr -d ' ')줄)"
  else
    warn "지정한 CVE 목록 파일($PRECHECK_CVE_DB)에 올바른 줄이 없어 스크립트 내장 목록을 사용합니다."
  fi
fi
info "CVE 목록 출처: $CVE_SRC"

N_APPLY=0; N_NA=0
SEEN="$WORK/seen.txt"; : > "$SEEN"; NA="$WORK/na.txt"; : > "$NA"
# 버전이 같은 메이저인 줄만 비교 (속도: 수백 줄을 모두 awk 로 비교하지 않도록 먼저 거름)
MAJOR="${TC_VER%%.*}"
while IFS='|' read -r cve ghsa sev comp group intro fixed last desc; do
  case "$cve" in ''|\#*) continue ;; esac
  grep -qx "$cve" "$SEEN" && continue
  jar="$(comp_jar "$comp")"
  if [ -z "$jar" ] || [ ! -f "$jar" ]; then
    grep -q "^$cve|" "$NA" || printf '%s|%s|%s\n' "$cve" "$sev" "$comp" >> "$NA"
    continue
  fi
  # 빠른 거르기: 수정/마지막 버전의 메이저가 설치 버전보다 작으면 해당 없음
  endv="${fixed:-$last}"
  if [ -n "$endv" ] && [ "${endv%%.*}" -lt "$MAJOR" ] 2>/dev/null; then continue; fi
  if [ "$intro" != "0" ] && [ "${intro%%.*}" -gt "$MAJOR" ] 2>/dev/null; then continue; fi
  hit=0
  if [ "$intro" = "0" ] || vle "$intro" "$TC_VER"; then
    if [ -n "$fixed" ]; then vlt "$TC_VER" "$fixed" && hit=1
    elif [ -n "$last" ]; then vle "$TC_VER" "$last" && hit=1
    else hit=1
    fi
  fi
  if [ "$hit" -eq 1 ]; then
    echo "$cve" >> "$SEEN"
    if [ -n "$fixed" ]; then range="$intro~$fixed 미만"
    elif [ -n "$last" ]; then range="$intro~$last 이하"
    else range="$intro~수정 버전 없음"
    fi
    [ "$comp" = "tomcat" ] && cname="Tomcat" || cname="$comp"
    line="$cve [$sev] $desc (영향: Tomcat $range, 조건: $cname $TC_VER 설치됨, 출처: $ghsa)"
    case "$sev" in critical|high) risk "$line" ;; *) warn "$line" ;; esac
    N_APPLY=$((N_APPLY+1))
  fi
done < "$CVE_DB"
# 구성요소(jar)가 없어 미해당인 CVE (해당 CVE 로 이미 나온 것은 제외)
while IFS='|' read -r cve sev comp; do
  grep -qx "$cve" "$SEEN" && continue
  printf '[미해당] %s (%s) - 필요 모듈(%s) 미사용\n' "$cve" "$sev" "$comp" >> "$REPORT"
  N_NA=$((N_NA+1))
done < "$NA"
N_TOTAL="$(grep -vE '^(#|$)' "$CVE_DB" | cut -d'|' -f1 | sort -u | wc -l)"
log ""
log "  → 해당 CVE: ${N_APPLY}건 / 구성요소가 없어 미해당: ${N_NA}건 / 나머지는 수정된 버전이라 미해당 (전체 ${N_TOTAL}건 중)"
if [ "$N_APPLY" -eq 0 ]; then
  ok "이 스크립트의 CVE 목록 기준으로 해당하는 CVE 가 없습니다."
fi

# =====================================================================
section "[3] 위험 설정 점검 (셧다운 포트·커넥터·관리자 앱·계정·실행 옵션·파일 권한)"
# =====================================================================
CFG="$WORK/server.xml"; WEBXML="$WORK/web.xml"; USERS="$WORK/users.xml"
# 주석(<!-- -->) 제거본 (여러 줄 주석 포함)
strip_comments() { [ -r "$1" ] && perl -0pe 's/<!--.*?-->//gs' "$1" 2>/dev/null || sed -e ':a' -e 's/<!--[^>]*-->//g' -e '/<!--/{N;ba' -e '}' "$1" 2>/dev/null; }
if [ ! -r "$CONFIG" ]; then
  warn "메인 설정 파일을 읽지 못했습니다: $CONFIG  (설정 기반 점검 일부를 건너뜁니다)"
  : > "$CFG"
else
  strip_comments "$CONFIG" > "$CFG"
fi
strip_comments "$CONF_DIR/web.xml" > "$WEBXML"
strip_comments "$CONF_DIR/tomcat-users.xml" > "$USERS"
# 태그 하나를 한 줄로 (속성이 여러 줄에 걸친 <Connector ...> 대비)
tags() { tr '\n' ' ' < "$1" | sed 's/>/>\n/g' | grep -E "<$2[ />]" | sed 's/^[^<]*//; s/[[:space:]]\{2,\}/ /g'; }
attr() { printf '%s' "$1" | sed -n "s/.*[[:space:]]$2=\"\([^\"]*\)\".*/\1/p" | head -n1; }
# ${prop} 값 풀기 (명령줄 -Dprop 값)
resolve() { local e="$1"; if [[ "$e" =~ ^\$\{([^}]+)\}$ ]]; then sysprop "${BASH_REMATCH[1]}"; else printf '%s' "$e"; fi; }
# [::ffff:127.0.0.1] = Java 가 IPv6 방식으로 연 127.0.0.1 (ss 에 이렇게 보임, 외부 접속 불가)
is_loopback() { [[ "$1" =~ ^(127\.|::1$|localhost$|\[::1\]$|\[?::ffff:127\.) ]]; }

LISTEN=""
if [ -n "${PRECHECK_PID:-}" ] && command -v ss >/dev/null 2>&1; then
  LISTEN="$(ss -ltnpH 2>/dev/null | grep "pid=$PRECHECK_PID," | awk '{print $4}' | sort -u)"
fi
if [ -n "$LISTEN" ]; then
  info "이 Tomcat 프로세스가 열어 둔 포트"
  printf '%s\n' "$LISTEN" | show
fi

# 3-1 셧다운 포트
SRV="$(tags "$CFG" Server | head -n1)"
SPORT="$(resolve "$(attr "$SRV" port)")"; SCMD="$(attr "$SRV" shutdown)"; SADDR="$(attr "$SRV" address)"
if [ -z "$SRV" ]; then
  info "server.xml 의 <Server> 설정을 확인하지 못함"
elif [ "$SPORT" = "-1" ]; then
  ok "셧다운 포트 비활성화(port=\"-1\")"
elif [ -n "$SADDR" ] && ! is_loopback "$SADDR"; then
  risk "셧다운 포트($SPORT)가 외부 주소($SADDR)에서 열림 → 네트워크에서 명령어 한 줄로 Tomcat 종료 가능. port=\"-1\" 권장"
elif [ "$SCMD" = "SHUTDOWN" ]; then
  warn "셧다운 포트($SPORT)가 기본 명령어(SHUTDOWN)로 열려 있음 → 서버의 다른 계정이 Tomcat 을 종료할 수 있음. port=\"-1\" 또는 추측하기 어려운 명령어로 변경 권장"
else
  ok "셧다운 포트($SPORT)는 루프백 전용 + 기본이 아닌 명령어"
fi

# 3-2 커넥터 (AJP / HTTP / 버전 노출)
AJP="$(tags "$CFG" Connector | grep -E 'protocol="(AJP/1\.3|org\.apache\.coyote\.ajp[^"]*)"')"
if [ -n "$AJP" ]; then
  while IFS= read -r c; do
    ap="$(resolve "$(attr "$c" port)")"; aa="$(attr "$c" address)"
    sec="$(attr "$c" secret)"; [ -z "$sec" ] && sec="$(attr "$c" requiredSecret)"
    sreq="$(attr "$c" secretRequired)"
    # 루프백(127.x, ::1, [::ffff:127.x])이 아닌 주소에 열린 것만 = 외부에서 접속 가능
    open="$(printf '%s\n' "$LISTEN" | grep -E ":$ap$" | grep -vE '^(127\.|\[::1\]|::1|\[?::ffff:127\.)')"
    if [ "$sreq" = "false" ] || [ -z "$sec" ]; then
      if [ -n "$open" ] || { [ -z "$LISTEN" ] && [ -n "$aa" ] && ! is_loopback "$aa"; }; then
        risk "AJP 커넥터(포트 $ap)가 secret 없이 외부 주소에서 열림 → Ghostcat(CVE-2020-1938)류 파일 읽기·코드 실행 위험. 미사용 시 제거, 사용 시 secret 설정 + address=\"127.0.0.1\""
      else
        warn "AJP 커넥터(포트 $ap)에 secret 미설정 → 같은 서버·내부망에서 악용 가능. secret 설정 또는 미사용 시 제거 권장"
      fi
    else
      if [ -n "$open" ]; then warn "AJP 커넥터(포트 $ap)가 외부 주소에서 열림(secret 설정됨) → 프록시 외 접근 방화벽 차단 권장"
      else ok "AJP 커넥터(포트 $ap) secret 설정됨"; fi
    fi
    detail "$(printf '%s' "$c" | sed -E 's/(secret|requiredSecret)="[^"]*"/\1="****"/g' | cut -c1-200)"
  done <<< "$AJP"
else
  ok "AJP 커넥터 없음"
fi
HTTPC="$(tags "$CFG" Connector | grep -vE 'protocol="(AJP/1\.3|org\.apache\.coyote\.ajp[^"]*)"')"
if printf '%s' "$HTTPC" | grep -q 'UpgradeProtocol' || grep -q 'Http2Protocol' "$CFG"; then
  info "HTTP/2(Http2Protocol) 사용 → HTTP/2 계열 CVE 대상. 불필요하면 제거 검토"
fi
if ! printf '%s' "$HTTPC" | grep -qE 'SSLEnabled="true"|secure="true"' && ! grep -q '<SSLHostConfig' "$CFG"; then
  info "Tomcat 에 HTTPS 커넥터 없음 (앞단 프록시/로드밸런서에서 TLS 를 처리하는지 확인)"
fi
SV="$(printf '%s\n' "$HTTPC" | grep -E ' server="[^"]*[0-9]+\.[0-9]' | head -n 3)"
[ -n "$SV" ] && { warn "커넥터 server 속성에 버전 번호 노출"; printf '%s\n' "$SV" | cut -c1-200 | show; }
if grep -qE 'xpoweredBy="true"' "$CFG" || grep -qE '<param-name>xpoweredBy</param-name>[[:space:]]*<param-value>true' "$WEBXML"; then
  warn "X-Powered-By 헤더 사용(xpoweredBy=\"true\") → 서버 정보 노출"
fi
# 오류 페이지의 버전 노출 (ErrorReportValve showServerInfo 기본값 true)
ERV="$(tags "$CFG" Valve | grep 'ErrorReportValve')"
if [ -z "$ERV" ] || ! printf '%s' "$ERV" | grep -q 'showServerInfo="false"'; then
  warn "오류 페이지에 Tomcat 버전 노출 (ErrorReportValve showServerInfo=\"false\" showReport=\"false\" 미설정) → 공격자가 버전별 CVE 를 골라 공격 가능"
else
  ok "오류 페이지 버전 노출 차단(ErrorReportValve showServerInfo=\"false\")"
fi
HPORT="$(printf '%s\n' "$HTTPC" | grep -vE 'SSLEnabled="true"' | head -n1)"; HPORT="$(resolve "$(attr "$HPORT" port)")"
if [[ "$HPORT" =~ ^[0-9]+$ ]] && command -v curl >/dev/null 2>&1 && [ -n "${PRECHECK_PID:-}" ]; then
  HDR="$(curl -sS -m 5 -o /dev/null -D - "http://127.0.0.1:$HPORT/" 2>/dev/null | grep -iE '^(server|x-powered-by):' | tr -d '\r')"
  if printf '%s' "$HDR" | grep -qE '[0-9]+\.[0-9]'; then warn "HTTP 응답 헤더에 버전 번호 노출"; printf '%s\n' "$HDR" | show
  elif [ -n "$HDR" ]; then info "HTTP 응답 헤더: $(printf '%s' "$HDR" | tr '\n' ' ')"
  else ok "HTTP 응답 헤더에 서버 정보(Server/X-Powered-By) 없음"; fi
fi

# 3-3 기본 servlet(conf/web.xml): 쓰기(readonly=false) / 디렉터리 목록 / CGI
DS="$(awk '/<servlet>/{b=""; f=1} f{b=b $0 "\n"} /<\/servlet>/{if (b ~ /DefaultServlet/) printf "%s", b; f=0}' "$WEBXML")"
if printf '%s' "$DS" | tr -d ' \t\n' | grep -q '<param-name>readonly</param-name><param-value>false</param-value>'; then
  risk "DefaultServlet readonly=false → HTTP PUT 으로 JSP 업로드·원격 코드 실행 가능(CVE-2017-12617 유형). true(기본값)로 되돌릴 것"
else
  ok "DefaultServlet 쓰기(PUT) 비활성(readonly 기본값)"
fi
if printf '%s' "$DS" | tr -d ' \t\n' | grep -q '<param-name>listings</param-name><param-value>true</param-value>'; then
  warn "디렉터리 목록 노출(DefaultServlet listings=true)"
else
  ok "디렉터리 목록 노출 설정 없음"
fi
if grep -q 'org.apache.catalina.servlets.CGIServlet' "$WEBXML" && grep -qE '<servlet-name>cgi</servlet-name>' "$WEBXML" && grep -qE '<url-pattern>/cgi-bin/\*</url-pattern>' "$WEBXML"; then
  warn "CGI 서블릿이 켜져 있음 → CGI 계열 CVE(CVE-2019-0232 등) 대상. 미사용 시 비활성화"
fi

# 3-4 관리자 앱(manager / host-manager) 노출과 계정
APPBASE="$(attr "$(tags "$CFG" Host | head -n1)" appBase)"; APPBASE="${APPBASE:-webapps}"
case "$APPBASE" in /*) ;; *) APPBASE="$CATALINA_BASE/$APPBASE" ;; esac
for app in manager host-manager; do
  [ -d "$APPBASE/$app" ] || [ -f "$APPBASE/$app.war" ] || [ -f "$CONF_DIR/Catalina/localhost/$app.xml" ] || continue
  CTX="$APPBASE/$app/META-INF/context.xml"; [ -f "$CONF_DIR/Catalina/localhost/$app.xml" ] && CTX="$CONF_DIR/Catalina/localhost/$app.xml"
  RAV="$(strip_comments "$CTX" | tr '\n' ' ' | grep -oE '<Valve[^>]*(RemoteAddrValve|RemoteCIDRValve)[^>]*>' | head -n1)"
  ALLOW="$(attr "$RAV" allow)"
  if [ -z "$RAV" ]; then
    risk "관리자 앱($app)이 IP 제한(RemoteAddrValve) 없이 배포됨 → 외부에서 로그인 시도·WAR 업로드(웹쉘 배포) 가능. 미사용 시 삭제, 사용 시 관리망 IP 로 제한"
  elif printf '%s' "$ALLOW" | grep -qE '^\.\*$|0\.0\.0\.0|\.\*\|' ; then
    warn "관리자 앱($app)의 IP 제한이 넓음 (allow=\"$ALLOW\") → 관리망 IP 로 좁힐 것"
  else
    info "관리자 앱($app) 배포됨, 접근 IP 제한: ${ALLOW:-$(printf '%s' "$RAV" | cut -c1-120)}"
  fi
done
WEAK_PW="admin password passw0rd p@ssw0rd P@ssw0rd 1234 12345 123456 12345678 1q2w3e4r qwer1234 admin123 admin1234 admin@123 tomcat tomcat123 s3cret secret changeit changeme manager root test welcome1 role1"
if [ -s "$USERS" ]; then
  UL="$(tr '\n' ' ' < "$USERS" | sed 's/>/>\n/g' | grep -E '<user[[:space:]]')"
  if [ -n "$UL" ]; then
    MGR="$(printf '%s\n' "$UL" | grep -E 'roles="[^"]*(manager-gui|manager-script|manager-jmx|admin-gui|admin-script|manager)[^"]*"')"
    info "tomcat-users.xml 계정 $(printf '%s\n' "$UL" | wc -l)개 (관리 권한 $(printf '%s\n' "$MGR" | grep -c .)개): $(printf '%s\n' "$UL" | while read -r u; do attr "$u" username; printf ' '; done)"
    weak=""
    while IFS= read -r u; do
      [ -z "$u" ] && continue
      un="$(attr "$u" username)"; pw="$(attr "$u" password)"
      for p in $WEAK_PW "$un"; do [ "$pw" = "$p" ] && { weak="$weak $un"; break; }; done
    done <<< "$MGR"
    if [ -n "$weak" ]; then risk "관리 계정에 추측하기 쉬운 비밀번호 사용:$weak → 즉시 변경 (tomcat-users.xml)"
    elif [ -n "$MGR" ]; then ok "관리 계정에 흔한 비밀번호(사전 $(printf '%s\n' $WEAK_PW | wc -l)개·아이디와 같은 비밀번호) 사용 없음"; fi
    if [ -n "$MGR" ] && ! grep -qE 'CredentialHandler|digest=' "$CFG"; then
      warn "tomcat-users.xml 비밀번호가 평문으로 저장됨 → CredentialHandler(예: SecretKeyCredentialHandler)로 해시 저장 권장"
    fi
  else
    ok "tomcat-users.xml 에 계정 없음 (관리자 앱 로그인 불가)"
  fi
  if [ -n "$(find "$CONF_DIR/tomcat-users.xml" -perm -004 2>/dev/null)" ]; then
    warn "tomcat-users.xml 을 모든 계정이 읽을 수 있음 → 비밀번호 유출 위험. chmod 640 권장"
  fi
fi

# 3-5 기본 예제·문서 앱
SAMPLES=""
for app in examples docs; do [ -d "$APPBASE/$app" ] || [ -f "$APPBASE/$app.war" ] && SAMPLES="$SAMPLES $app"; done
if [ -n "$SAMPLES" ]; then
  warn "기본 예제/문서 앱 배포됨:$SAMPLES → 예제 서블릿(세션 조작 등) 악용·버전 노출. 운영 서버에서는 삭제 권장"
else
  ok "기본 예제/문서 앱 없음"
fi
if [ -f "$APPBASE/ROOT/RELEASE-NOTES.txt" ] || [ -f "$APPBASE/ROOT/tomcat.svg" ] || [ -f "$APPBASE/ROOT/tomcat.png" ]; then
  warn "기본 ROOT 페이지(Tomcat 환영 화면)가 그대로 있음 → Tomcat 사용 사실·버전 노출. 운영 앱으로 교체하거나 삭제 권장"
fi

# 3-6 실행 계정
RUN_USER=""
[ -n "${PRECHECK_PID:-}" ] && RUN_USER="$(ps -o user= -p "$PRECHECK_PID" 2>/dev/null | tr -d ' ')"
if [ "$RUN_USER" = "root" ]; then risk "실행 계정이 root → 앱 취약점이 곧 서버 전체 장악으로 이어짐. 전용 계정(예: tomcat)으로 실행 권장"
elif [ -n "$RUN_USER" ]; then ok "실행 계정: $RUN_USER"
else info "실행 계정을 확인하지 못함 (Tomcat 이 실행 중이 아님)"; fi

# 3-7 원격 디버그 / JMX 원격 접속 옵션
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
if tags "$CFG" Listener | grep -q 'JmxRemoteLifecycleListener'; then
  warn "JmxRemoteLifecycleListener 사용 중 → JMX 원격 포트 인증·접근 제어 확인 필요"
fi

# 3-8 파일 권한 (모든 계정이 쓸 수 있으면 설정 변조·앱 바꿔치기 가능)
WW="$(find "$CONF_DIR" "$APPBASE" "$CATALINA_HOME/lib" "$CATALINA_HOME/bin" -maxdepth 2 -perm -002 ! -type l 2>/dev/null | head -n 10)"
if [ -n "$WW" ]; then risk "모든 계정이 쓸 수 있는 설정/배포/라이브러리/실행 파일·폴더 있음 → 설정 변조·악성 앱 배포 가능"; printf '%s\n' "$WW" | show
else ok "설정·배포·라이브러리·실행 폴더에 모든 계정 쓰기 권한 없음"; fi
if [ -n "$RUN_USER" ] && [ "$RUN_USER" != "root" ] && id "$RUN_USER" >/dev/null 2>&1; then
  # conf/Catalina(앱 배포 시 Tomcat 이 context 파일을 씀)는 제외
  OWN="$(find "$CONF_DIR" "$CATALINA_HOME/bin" "$CATALINA_HOME/lib" -maxdepth 1 -user "$RUN_USER" ! -path "$CONF_DIR/Catalina" 2>/dev/null | head -n 5)"
  if [ -n "$OWN" ]; then
    warn "실행 계정($RUN_USER)이 conf/bin/lib 를 소유 → 배포한 앱이 뚫리면(원격 코드 실행) 공격자가 server.xml·lib 의 jar 를 바꿔 재배포해도 남는 뒷문을 만들 수 있음. 이 폴더는 Tomcat 이 쓸 필요가 없으므로 root(또는 별도 관리 계정) 소유 + 실행 계정은 읽기만 권장"
    printf '%s\n' "$OWN" | while read -r o; do detail "$(ls -ld "$o" 2>/dev/null | awk '{print $1, $3":"$4, $NF}')"; done
    detail "→ 권한 상승 문제는 아님(Tomcat 은 원래 $RUN_USER 로 실행). 앱 침해 시 피해를 Tomcat 설치본까지 넓히지 않기 위한 강화 항목"
    detail "→ 쓰기가 필요한 곳: logs, temp, work, webapps(배포 방식에 따라), conf/Catalina. 예: sudo chown -R root:$RUN_USER $CATALINA_HOME/bin $CATALINA_HOME/lib && sudo chmod -R g-w,o-w $CATALINA_HOME/bin $CATALINA_HOME/lib (패치·업그레이드 작업 계정도 함께 정할 것)"
  fi
fi

# =====================================================================
section "[4] 침해 흔적 점검 (이미 해킹당했는지)"
# =====================================================================
# 4-1 접근 로그 (server.xml 의 AccessLogValve. 기본: logs/localhost_access_log.날짜.txt)
LOGS="$WORK/logs.txt"; : > "$LOGS"
if [ -n "$LOG_PATHS" ]; then
  for p in $LOG_PATHS; do
    # shellcheck disable=SC2086
    ls -d -- $p 2>/dev/null
  done >> "$LOGS"
  info "접근 로그 경로를 -l 옵션 값으로 사용: $LOG_PATHS"
else
  tags "$CFG" Valve | grep 'AccessLogValve' | while IFS= read -r v; do
    AD="$(resolve "$(attr "$v" directory)")"; AD="${AD:-logs}"
    case "$AD" in /*) ;; *) AD="$CATALINA_BASE/$AD" ;; esac
    AP="$(attr "$v" prefix)"; AP="${AP:-localhost_access_log}"
    find "$AD" -maxdepth 1 -type f -name "${AP}*" 2>/dev/null
  done >> "$LOGS"
  find "$LOG_DIR" -maxdepth 2 -type f -name '*access_log*' 2>/dev/null >> "$LOGS"
fi
sort -u "$LOGS" | while read -r f; do [ -f "$f" ] && [[ "$f" != "$REPORT" ]] && echo "$f"; done > "$WORK/logs2.txt"; mv "$WORK/logs2.txt" "$LOGS"

if [ ! -s "$LOGS" ]; then
  warn "접근 로그 파일을 찾지 못했습니다. 로그 기반 점검을 건너뜁니다. (server.xml 의 AccessLogValve 설정 확인)"
  detail "→ 앞단 프록시(Apache/Nginx) 로그가 있으면 -l 옵션으로 지정하세요. 예: sudo bash $0 -l '/var/log/httpd/access_log*'"
else
  info "점검 대상 접근 로그: $(wc -l < "$LOGS")개"
  head -n 10 "$LOGS" | show
  zg() { while read -r f; do zgrep -hE "$1" "$f" 2>/dev/null; done < "$LOGS"; }

  zg '(\.%2e|%2e\.|%2e%2e|%252e|\.\./|\.\.%2f|%c0%ae|/\.;/|\.\.;|;\.\./|/WEB-INF/|/META-INF/)' > "$WORK/trav.txt"
  T_ALL=$(wc -l < "$WORK/trav.txt"); T_200=$(grep -cE '" 200 ' "$WORK/trav.txt")
  if [ "$T_200" -gt 0 ]; then
    risk "경로 탐색·WEB-INF 접근 시도 중 200(성공) 응답 ${T_200}건 → 침해 가능성. 즉시 상세 분석 필요"
    grep -E '" 200 ' "$WORK/trav.txt" | head -n 5 | show
  elif [ "$T_ALL" -gt 0 ]; then warn "경로 탐색·WEB-INF 접근 시도 ${T_ALL}건 (성공 응답 없음) → 스캔 대상이 되고 있음"
  else ok "경로 탐색 시도 흔적 없음"; fi

  zg '(cmd=|exec=|shell=|whoami|/etc/passwd|/bin/(ba)?sh|wget(%20|\+)|curl(%20|\+)|\$\{jndi:|%24%7Bjndi|Runtime\.getRuntime|java\.lang\.ProcessBuilder|class\.module\.classLoader)' > "$WORK/shell.txt"
  S_200=$(grep -cE '" 200 ' "$WORK/shell.txt")
  if [ "$S_200" -gt 0 ]; then
    risk "명령실행/웹쉘/JNDI·클래스로더 주입 의심 요청 중 200 응답 ${S_200}건"
    grep -E '" 200 ' "$WORK/shell.txt" | head -n 5 | show
  elif [ -s "$WORK/shell.txt" ]; then warn "명령실행/웹쉘/JNDI 주입 의심 요청 $(wc -l < "$WORK/shell.txt")건 (성공 응답 없음)"
  else ok "명령실행/웹쉘/JNDI 주입 의심 요청 흔적 없음"; fi

  # 관리자 앱 WAR 배포 / PUT 으로 JSP 올리기 (Tomcat 을 노리는 대표 침투 경로)
  zg '"(PUT [^ ]*\.jspx?/? |(PUT|POST|GET) /manager/(text/deploy|html/upload|html/deploy))' > "$WORK/deploy.txt"
  D_OK=$(grep -cE '" (200|201|204) ' "$WORK/deploy.txt")
  if [ "$D_OK" -gt 0 ]; then
    risk "관리자 앱 배포/PUT JSP 업로드 요청 중 성공 응답 ${D_OK}건 → 정상 배포 이력과 대조 필요 (웹쉘 배포 가능성)"
    grep -E '" (200|201|204) ' "$WORK/deploy.txt" | head -n 5 | show
  elif [ -s "$WORK/deploy.txt" ]; then warn "관리자 앱 배포/PUT JSP 업로드 시도 $(wc -l < "$WORK/deploy.txt")건 (성공 응답 없음)"
  else ok "관리자 앱 배포/PUT 업로드 공격 흔적 없음"; fi

  zg '"(GET|POST|HEAD) /(manager|host-manager)/' | grep -vE '" (401|403|404) ' > "$WORK/mgr.txt"
  if [ -s "$WORK/mgr.txt" ]; then
    warn "관리자 앱 접속 기록 $(wc -l < "$WORK/mgr.txt")건(인증 실패·차단 제외) → 접속 IP 가 관리자 PC 인지 확인"
    awk '{print $1}' "$WORK/mgr.txt" | sort | uniq -c | sort -rn | head -n 5 | show
  fi

  cat "$WORK/trav.txt" "$WORK/shell.txt" "$WORK/deploy.txt" | awk '{print $1}' | sort | uniq -c | sort -rn | head -n 5 > "$WORK/topip.txt"
  [ -s "$WORK/topip.txt" ] && { info "의심 요청 상위 IP (차단 검토용)"; show < "$WORK/topip.txt"; }
fi

# 4-2 배포된 애플리케이션 (appBase + conf/Catalina/<호스트>/*.xml 로 다른 곳을 가리키는 앱)
DEPDIRS="$WORK/depdirs.txt"; : > "$DEPDIRS"
[ -d "$APPBASE" ] && echo "$APPBASE" >> "$DEPDIRS"
for x in "$CONF_DIR"/Catalina/*/*.xml; do
  [ -f "$x" ] || continue
  db="$(strip_comments "$x" | tr '\n' ' ' | sed -n 's/.*<Context[^>]*docBase="\([^"]*\)".*/\1/p')"
  case "$db" in /*) [ -e "$db" ] && echo "$db" >> "$DEPDIRS" ;; esac
done
if [ ! -s "$DEPDIRS" ]; then
  warn "배포 폴더를 찾지 못했습니다. 파일 기반 점검을 건너뜁니다. ($APPBASE)"
else
  DEPLOYED="$(find "$APPBASE" -mindepth 1 -maxdepth 1 \( -type d -o -name '*.war' \) -printf '%f\n' 2>/dev/null | sed 's/\.war$//' | sort -u)"
  if [ -n "$DEPLOYED" ]; then info "배포된 애플리케이션 $(printf '%s\n' "$DEPLOYED" | wc -l)개"; printf '%s\n' "$DEPLOYED" | head -n 20 | show
  else info "배포된 애플리케이션 없음"; fi

  WS_PAT='Runtime\.getRuntime\(\)\.exec|new[[:space:]]+ProcessBuilder|ScriptEngineManager|defineClass[[:space:]]*\(|ProcessImpl|getRuntime\(\)\.exec'
  : > "$WORK/ws.txt"
  while read -r d; do
    find "$d" -type f \( -iname '*.jsp' -o -iname '*.jspx' -o -iname '*.jspf' \) 2>/dev/null
  done < "$DEPDIRS" > "$WORK/jspfiles.txt"
  [ -s "$WORK/jspfiles.txt" ] && tr '\n' '\0' < "$WORK/jspfiles.txt" | xargs -0 -r grep -lE "$WS_PAT" 2>/dev/null >> "$WORK/ws.txt"
  # 압축(war) 안의 JSP (풀린 폴더가 같이 있으면 위에서 이미 점검)
  ARCH="$WORK/arch.txt"
  while read -r d; do find "$d" -maxdepth 1 -type f -name '*.war' 2>/dev/null; done < "$DEPDIRS" | while read -r w; do
    [ -d "${w%.war}" ] || echo "$w"
  done > "$ARCH"
  ZIPTOOL=""; command -v unzip >/dev/null 2>&1 && ZIPTOOL=unzip
  [ -z "$ZIPTOOL" ] && command -v python3 >/dev/null 2>&1 && ZIPTOOL=python3
  if [ -s "$ARCH" ] && [ -z "$ZIPTOOL" ]; then
    warn "unzip/python3 이 없어 압축된 배포 파일(war) 안의 JSP 를 점검하지 못했습니다."
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
    find "$d" -type f -mtime "-$RECENT_DAYS" \( -iname '*.jsp' -o -iname '*.jspx' -o -iname '*.war' -o -iname '*.class' -o -iname '*.jar' -o -iname '*.sh' \) 2>/dev/null
  done < "$DEPDIRS" >> "$WORK/recent.txt"
  if [ -s "$WORK/recent.txt" ]; then
    warn "최근 ${RECENT_DAYS}일 내 변경된 배포 파일(JSP/WAR/클래스/JAR) $(wc -l < "$WORK/recent.txt")개 → 배포 이력과 대조 필요"
    head -n 20 "$WORK/recent.txt" | while read -r f; do detail "$(ls -l --time-style=+%F_%T "$f" 2>/dev/null)"; done
  else
    ok "최근 ${RECENT_DAYS}일 내 변경된 배포 파일 없음"
  fi
fi

# 4-3 Tomcat 로그(catalina.out / catalina.*.log / localhost.*.log)의 공격·침해 흔적
CLOGS="$(find "$LOG_DIR" -maxdepth 2 -type f -mtime "-$RECENT_DAYS" \( -name 'catalina.out*' -o -name 'catalina.*.log*' -o -name 'localhost.*.log*' -o -name 'manager.*.log*' \) 2>/dev/null | sort)"
if [ -n "$SERVER_LOG_PATHS" ]; then
  # -s 로 지정한 경로 (와일드카드 가능)
  for p in $SERVER_LOG_PATHS; do
    # shellcheck disable=SC2086
    ls -d -- $p 2>/dev/null
  done | while read -r f; do [ -f "$f" ] && echo "$f"; done > "$WORK/clogs_s.txt"
  if [ -s "$WORK/clogs_s.txt" ]; then
    info "서버 로그 경로를 -s 옵션 값으로 추가: $SERVER_LOG_PATHS ($(wc -l < "$WORK/clogs_s.txt")개)"
    CLOGS="$( { [ -n "$CLOGS" ] && printf '%s\n' "$CLOGS"; cat "$WORK/clogs_s.txt"; } | sort -u)"
  else
    warn "-s 옵션으로 지정한 서버 로그 경로에 파일이 없습니다: $SERVER_LOG_PATHS (경로·와일드카드 확인)"
  fi
fi
if [ -z "$CLOGS" ]; then
  warn "catalina 로그를 찾지 못했습니다. Tomcat 로그 기반 공격 흔적 점검을 건너뜁니다. (찾아본 곳: $LOG_DIR)"
  detail "→ 다른 곳에 있으면 -s 옵션(에이전트는 설정 파일의 TOMCAT_SERVER_LOG_PATHS)으로 지정하세요. 예: -s '/applog/tomcat/catalina.out*'"
else
  info "점검 대상 Tomcat 로그: $(printf '%s\n' "$CLOGS" | wc -l)개"
  printf '%s\n' "$CLOGS" | head -n 10 | show
  GAD="$(printf '%s\n' "$CLOGS" | xargs -r zgrep -hE 'InvokerTransformer|TemplatesImpl|ysoserial|ChainedTransformer|JdbcRowSetImpl|\$\{jndi:(ldap|rmi|dns)|class\.module\.classLoader' 2>/dev/null | grep -vE 'serialFilter|Command line argument|-Djdk\.serial' | head -n 5)"
  if [ -n "$GAD" ]; then
    risk "Tomcat 로그에 역직렬화 공격 도구·JNDI·클래스로더 주입 흔적 → 침해 시도/성공 여부 상세 분석 필요"
    printf '%s\n' "$GAD" | cut -c1-200 | show
  else
    ok "Tomcat 로그에 역직렬화 공격·JNDI 주입 흔적 없음"
  fi
  DEP="$(printf '%s\n' "$CLOGS" | xargs -r zgrep -hE 'Deploying web application (archive|directory)|HTMLManager: (install|upload)|Manager: (deploy|install)' 2>/dev/null | tail -n 10)"
  [ -n "$DEP" ] && { info "최근 배포 기록 (Tomcat 로그, 최근 10건) → 배포 이력과 대조"; printf '%s\n' "$DEP" | cut -c1-200 | show; }
fi

# 4-4 실행 계정의 의심 프로세스 / 크론 / 임시파일 / 외부 연결
if [ -n "$RUN_USER" ] && [ "$RUN_USER" != "root" ] && id "$RUN_USER" >/dev/null 2>&1; then
  # 누가 띄웠는지로 나눔: Tomcat 이 띄운 것 = 위험, 사람의 로그인 터미널 = 정보, 그 밖 = 주의
  split_user_procs "$RUN_USER" 'org\.apache\.catalina\.startup\.Bootstrap|catalina\.sh|jsvc' 'java|jsvc'
  report_user_procs "Tomcat 실행계정($RUN_USER)" "Tomcat"

  CR="$(crontab -l -u "$RUN_USER" 2>/dev/null | grep -vE '^\s*(#|$)')"
  if [ -n "$CR" ]; then
    # 모든 크론을 위험으로 보지 않고, 공격자 지속성 패턴(원격 다운로드 실행·리버스쉘·인코딩 실행·임시폴더 실행 등)만 위험.
    #   그 밖(로그 압축·백업·정리 등 운영 작업)은 내용 확인용 주의로.
    CR_SUSP="$(printf '%s\n' "$CR" | grep -E '(\||;|&&)[[:space:]]*(ba)?sh([[:space:]]|$)|/dev/tcp/|/dev/shm|\b(ncat|netcat)\b|\bnc[[:space:]]+-|bash[[:space:]]+-i|mkfifo|base64[[:space:]]+(-d|--decode)|python[0-9]*[[:space:]]+-c|perl[[:space:]]+-e|php[[:space:]]+-r|ruby[[:space:]]+-e|[[:space:]]eval[[:space:]]|(bash|sh|source|\.)[[:space:]]+/(tmp|var/tmp)/|/(tmp|var/tmp)/[^[:space:]]*\.(sh|py|pl|bin|elf)')"
    if [ -n "$CR_SUSP" ]; then
      risk "실행계정($RUN_USER) 크론에 공격자 지속성 패턴 의심(원격 다운로드 실행·리버스쉘·인코딩 실행·임시폴더 실행 등) → 즉시 확인"
      printf '%s\n' "$CR_SUSP" | show
    else
      warn "실행계정($RUN_USER)에 크론 작업 등록됨 → 정상 운영 작업(로그 압축·백업·정리 등)인지 명령 내용 확인 필요"
    fi
    printf '%s\n' "$CR" | show
  else ok "실행계정 크론 작업 없음"; fi

  TMPF="$(find /tmp /var/tmp /dev/shm -xdev -user "$RUN_USER" -type f ! -path '*/hsperfdata_*' ! -path '*/tomcat-docbase.*' ! -path '*/tomcat.*' 2>/dev/null | head -n 20)"
  if [ -n "$TMPF" ]; then warn "임시 디렉터리에 실행계정 소유 파일 존재 → 실행파일/스크립트 여부 확인"; printf '%s\n' "$TMPF" | show
  else ok "임시 디렉터리에 실행계정 소유 파일 없음"; fi
elif [ "$RUN_USER" = "root" ]; then
  info "실행 계정이 root 라 계정 기준 의심 프로세스/크론 점검은 생략합니다. (전용 계정으로 바꾸면 점검 가능)"
fi
if [ -n "${PRECHECK_PID:-}" ] && command -v ss >/dev/null 2>&1; then
  CONN="$(ss -tnpH state established 2>/dev/null | grep "pid=$PRECHECK_PID," | awk '{print $3" -> "$4}' | sort | uniq -c | sort -rn | head -n 15)"
  if [ -n "$CONN" ]; then
    info "Tomcat 프로세스의 연결 목록 (DB·프록시 외의 외부 IP로 나가는 연결이 있으면 의심)"
    printf '%s\n' "$CONN" | show
  fi
fi

# 4-5 OS 로그인 기록 (/var/log/secure 등): 로그인 공격 성공, 실행 계정의 직접 로그인·sudo, 계정 생성
check_auth_log "$RUN_USER"

# =====================================================================
section "점검 요약"
# =====================================================================
log "  [위험] ${CNT_RISK}건   [주의] ${CNT_WARN}건   [양호] ${CNT_OK}건   [정보] ${CNT_INFO}건"
log ""
log "  ※ 이 결과는 '알려진 패턴' 기준이며 안전을 보증하지 않습니다."
log "    - [위험] 중 침해 흔적(로그 200 응답, 웹쉘, 비정상 프로세스)이 있으면 설정 보완보다 침해사고 대응이 우선입니다."
log "    - CVE 판정은 Tomcat 버전과 OSV 영향 구간 기준이며, 패키지 설치본은 배포판 보안 공지로 최종 확인하세요."
log "    - 근본 대책은 같은 브랜치의 최신 버전(${LATEST_SAME:-지원 브랜치로 교체}) 이상으로의 업그레이드입니다."
log ""
log "  리포트 파일: $REPORT"
