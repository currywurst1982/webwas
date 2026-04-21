#!/usr/bin/env bash
# ============================================================
# 테스트용 CSV 데이터 피더 파일 생성 스크립트
# - Gatling / JMeter 피더 파일 생성
# - DB에서 실제 ID를 추출하거나, 더미 데이터를 생성
# 사용법:
#   ./generate-test-data.sh [옵션]
#
# 옵션:
#   --count   숫자          추출/생성할 건수 (기본: 200)
#   --db-extract            DB에서 실제 데이터 추출
#   --db-type postgresql    DB 종류 지정 (postgresql | mysql, 기본: postgresql)
#
# PostgreSQL 예시:
#   DB_HOST=localhost DB_PORT=5432 DB_NAME=mydb \
#   DB_USER=myuser   DB_PASS=mypass \
#   ITEM_TABLE=tb_item   ITEM_ID_COL=item_id   ITEM_STATUS_COL=use_yn \
#   USER_TABLE=tb_member USER_LOGIN_COL=user_id USER_STATUS_COL=use_yn \
#   ./generate-test-data.sh --db-extract --db-type postgresql --count 500
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESOURCES_DIR="${SCRIPT_DIR}/../gatling/resources"
ITEM_COUNT=200
DB_EXTRACT=false
DB_TYPE=${DB_TYPE:-"postgresql"}

# ── DB 접속 정보 (환경변수로 오버라이드) ────────────────────────────────────
DB_HOST=${DB_HOST:-"localhost"}
DB_PORT=${DB_PORT:-"5432"}        # PostgreSQL 기본 포트
DB_NAME=${DB_NAME:-"mydb"}
DB_USER=${DB_USER:-"postgres"}
DB_PASS=${DB_PASS:-""}

# ── 테이블/컬럼명 (실제 DB 스키마에 맞게 환경변수로 변경) ──────────────────
# 아이템 테이블
ITEM_TABLE=${ITEM_TABLE:-"items"}
ITEM_ID_COL=${ITEM_ID_COL:-"id"}
ITEM_STATUS_COL=${ITEM_STATUS_COL:-"status"}
ITEM_STATUS_VAL=${ITEM_STATUS_VAL:-"ACTIVE"}   # 활성 상태 값

# 사용자 테이블
USER_TABLE=${USER_TABLE:-"users"}
USER_LOGIN_COL=${USER_LOGIN_COL:-"login_id"}
USER_STATUS_COL=${USER_STATUS_COL:-"status"}
USER_STATUS_VAL=${USER_STATUS_VAL:-"ACTIVE"}
USER_DEFAULT_PW=${USER_DEFAULT_PW:-"Test1234!"}  # 테스트 계정 비밀번호

log()  { echo "[$(date '+%H:%M:%S')] $*"; }
die()  { echo "ERROR: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --count)      ITEM_COUNT="$2";  shift 2 ;;
    --db-extract) DB_EXTRACT=true;  shift   ;;
    --db-type)    DB_TYPE="$2";     shift 2 ;;
    *) die "알 수 없는 옵션: $1 (--count | --db-extract | --db-type)" ;;
  esac
done

mkdir -p "${RESOURCES_DIR}"

# ── DB 접속 테스트 ────────────────────────────────────────────────────────────
check_db_connection() {
  log "DB 접속 확인 중... (${DB_TYPE}://${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME})"
  case "${DB_TYPE}" in
    postgresql|postgres)
      if ! PGPASSWORD="${DB_PASS}" psql \
          -h "${DB_HOST}" -p "${DB_PORT}" \
          -U "${DB_USER}" -d "${DB_NAME}" \
          -c "SELECT 1;" -q -t &>/dev/null; then
        die "PostgreSQL 접속 실패. DB_HOST/PORT/USER/PASS/NAME 환경변수를 확인하세요."
      fi
      ;;
    mysql|mariadb)
      if ! mysql -h "${DB_HOST}" -P "${DB_PORT}" \
          -u "${DB_USER}" -p"${DB_PASS}" \
          "${DB_NAME}" -e "SELECT 1;" &>/dev/null; then
        die "MySQL 접속 실패. DB_HOST/PORT/USER/PASS/NAME 환경변수를 확인하세요."
      fi
      ;;
    *) die "지원하지 않는 DB 타입: ${DB_TYPE} (postgresql | mysql)" ;;
  esac
  log "  DB 접속 성공"
}

# ── PostgreSQL 쿼리 실행 헬퍼 ────────────────────────────────────────────────
# -t: 튜플만 출력 (헤더/푸터 제거)
# -A: 정렬 없는 출력 (공백 패딩 제거)
# -F',': 필드 구분자 쉼표
run_psql() {
  local sql="$1"
  PGPASSWORD="${DB_PASS}" psql \
    -h "${DB_HOST}" -p "${DB_PORT}" \
    -U "${DB_USER}" -d "${DB_NAME}" \
    -t -A -F',' \
    -c "${sql}"
}

# ── MySQL 쿼리 실행 헬퍼 ─────────────────────────────────────────────────────
run_mysql() {
  local sql="$1"
  mysql -h "${DB_HOST}" -P "${DB_PORT}" \
    -u "${DB_USER}" -p"${DB_PASS}" \
    "${DB_NAME}" --batch --skip-column-names \
    -e "${sql}"
}

# ── DB 타입별 쿼리 분기 실행 ─────────────────────────────────────────────────
run_query() {
  local sql="$1"
  case "${DB_TYPE}" in
    postgresql|postgres) run_psql "${sql}" ;;
    mysql|mariadb)       run_mysql "${sql}" ;;
  esac
}

# ── item_ids.csv 생성 ────────────────────────────────────────────────────────
generate_item_ids() {
  local out="${RESOURCES_DIR}/item_ids.csv"
  log "item_ids.csv 생성 (${ITEM_COUNT}건) → ${out}"

  if ${DB_EXTRACT}; then
    # PostgreSQL: RANDOM() / MySQL: RAND()
    local order_func="RANDOM()"
    [[ "${DB_TYPE}" == "mysql" || "${DB_TYPE}" == "mariadb" ]] && order_func="RAND()"

    local sql="SELECT ${ITEM_ID_COL}
               FROM ${ITEM_TABLE}
               WHERE ${ITEM_STATUS_COL} = '${ITEM_STATUS_VAL}'
               ORDER BY ${order_func}
               LIMIT ${ITEM_COUNT};"

    log "  실행 쿼리: ${sql}"
    {
      echo "itemId"
      run_query "${sql}"
    } > "${out}"

    local extracted=$(( $(wc -l < "${out}") - 1 ))
    if (( extracted == 0 )); then
      die "추출된 데이터가 없습니다. 테이블명/컬럼명/상태값을 확인하세요.
  ITEM_TABLE=${ITEM_TABLE}  ITEM_ID_COL=${ITEM_ID_COL}
  ITEM_STATUS_COL=${ITEM_STATUS_COL}  ITEM_STATUS_VAL=${ITEM_STATUS_VAL}"
    fi
    log "  DB에서 ${extracted}건 추출 완료"
  else
    {
      echo "itemId"
      seq 1 "${ITEM_COUNT}"
    } > "${out}"
    log "  더미 ID ${ITEM_COUNT}건 생성 완료"
    log "  ⚠ 실제 테스트에서는 운영 DB 수준의 데이터로 교체 권장"
  fi
}

# ── users_with_auth.csv 생성 ─────────────────────────────────────────────────
generate_users() {
  local out="${RESOURCES_DIR}/users_with_auth.csv"
  log "users_with_auth.csv 생성 → ${out}"

  if ${DB_EXTRACT}; then
    local sql="SELECT ${USER_LOGIN_COL}, '${USER_DEFAULT_PW}'
               FROM ${USER_TABLE}
               WHERE ${USER_STATUS_COL} = '${USER_STATUS_VAL}'
               LIMIT ${ITEM_COUNT};"

    log "  실행 쿼리: ${sql}"
    {
      echo "userId,password"
      run_query "${sql}"
    } > "${out}"

    local extracted=$(( $(wc -l < "${out}") - 1 ))
    if (( extracted == 0 )); then
      die "추출된 사용자가 없습니다. 테이블명/컬럼명/상태값을 확인하세요.
  USER_TABLE=${USER_TABLE}  USER_LOGIN_COL=${USER_LOGIN_COL}
  USER_STATUS_COL=${USER_STATUS_COL}  USER_STATUS_VAL=${USER_STATUS_VAL}"
    fi
    log "  DB에서 ${extracted}건 추출 완료"
  else
    {
      echo "userId,password"
      for i in $(seq 1 "${ITEM_COUNT}"); do
        printf "testuser%04d,Test1234!\n" "${i}"
      done
    } > "${out}"
    log "  더미 사용자 ${ITEM_COUNT}건 생성 완료"
  fi
}

# ── search_keywords.csv 생성 ─────────────────────────────────────────────────
generate_keywords() {
  local out="${RESOURCES_DIR}/search_keywords.csv"
  log "search_keywords.csv 생성 → ${out}"

  {
    echo "keyword"
    # 실제 사용 빈도 분포를 모사: 짧은 키워드가 많고 긴 키워드는 적게
    local KEYWORDS=(
      "노트북" "스마트폰" "TV" "냉장고" "세탁기"
      "에어컨" "청소기" "카메라" "헤드폰" "키보드"
      "마우스" "모니터" "태블릿" "스피커" "프린터"
      "공유기" "USB" "SSD" "메모리" "그래픽카드"
      "삼성 노트북" "애플 맥북" "LG 그램" "OLED TV"
      "무선 청소기" "공기청정기" "전기밥솥" "커피머신"
      "블루투스 이어폰" "기계식 키보드" "4K 모니터"
      "삼성 갤럭시" "아이폰" "갤럭시탭" "아이패드"
      "CPU" "SSD 1TB" "DDR5 메모리" "RTX 그래픽"
    )

    for kw in "${KEYWORDS[@]}"; do
      # 각 키워드를 여러 번 반복해 빈도 분포 모사 (80/20 법칙)
      for _ in $(seq 1 3); do echo "${kw}"; done
    done

    # 긴꼬리 키워드 (한 번씩)
    for i in $(seq 1 50); do
      echo "검색어-${i}"
    done
  } > "${out}"

  log "  검색 키워드 $(wc -l < "${out}")건 생성 완료"
}

# ── 피더 파일 유효성 검증 ────────────────────────────────────────────────────
validate_feeds() {
  log ""
  log "[ 피더 파일 검증 ]"
  local all_ok=true

  for f in item_ids.csv users_with_auth.csv search_keywords.csv; do
    local fpath="${RESOURCES_DIR}/${f}"
    if [[ -f "${fpath}" ]]; then
      local lines
      lines=$(wc -l < "${fpath}")
      if (( lines < 2 )); then
        echo "  ✗ ${f}: 데이터 없음"
        all_ok=false
      else
        echo "  ✓ ${f}: $((lines-1))건 (헤더 제외)"
      fi
    else
      echo "  ✗ ${f}: 파일 없음"
      all_ok=false
    fi
  done

  if ${all_ok}; then
    log "모든 피더 파일 준비 완료"
  else
    log "일부 파일 생성 실패 - 확인 필요"
    exit 1
  fi
}

${DB_EXTRACT} && check_db_connection

generate_item_ids
generate_users
generate_keywords
validate_feeds

log ""
log "피더 파일 위치: ${RESOURCES_DIR}"
log "JMeter 사용 시: resources/ 경로를 jmeter/ 하위로도 복사 필요"
log "  cp -r ${RESOURCES_DIR} ${SCRIPT_DIR}/../jmeter/resources"
