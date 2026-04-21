#!/usr/bin/env bash
# ============================================================
# 테스트용 CSV 데이터 피더 파일 생성 스크립트
# - Gatling / JMeter 피더 파일 생성
# - DB에서 실제 ID를 추출하거나, 더미 데이터를 생성
# 사용법:
#   ./generate-test-data.sh [--count 숫자] [--db-extract]
#   ./generate-test-data.sh --count 500
#   ./generate-test-data.sh --db-extract  (DB에서 실제 데이터 추출)
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESOURCES_DIR="${SCRIPT_DIR}/../gatling/resources"
ITEM_COUNT=200
DB_EXTRACT=false

# DB 접속 정보 (--db-extract 옵션 사용 시)
DB_HOST=${DB_HOST:-"localhost"}
DB_PORT=${DB_PORT:-"3306"}
DB_NAME=${DB_NAME:-"mydb"}
DB_USER=${DB_USER:-"testuser"}
DB_PASS=${DB_PASS:-"testpass"}

log() { echo "[$(date '+%H:%M:%S')] $*"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --count)      ITEM_COUNT="$2"; shift 2 ;;
    --db-extract) DB_EXTRACT=true;  shift   ;;
    *) echo "알 수 없는 옵션: $1"; exit 1   ;;
  esac
done

mkdir -p "${RESOURCES_DIR}"

# ── item_ids.csv 생성 ────────────────────────────────────────────────────────
generate_item_ids() {
  local out="${RESOURCES_DIR}/item_ids.csv"
  log "item_ids.csv 생성 (${ITEM_COUNT}건) → ${out}"

  if ${DB_EXTRACT}; then
    # DB에서 실제 아이템 ID 추출 (MySQL/MariaDB 기준)
    mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASS}" \
      "${DB_NAME}" --batch --skip-column-names \
      -e "SELECT id FROM items WHERE status='ACTIVE' ORDER BY RAND() LIMIT ${ITEM_COUNT};" \
      | awk 'BEGIN{print "itemId"} {print}' > "${out}"
    log "  DB에서 $(wc -l < "${out}")건 추출 완료"
  else
    # 더미 ID 생성 (1 ~ ITEM_COUNT)
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
    mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASS}" \
      "${DB_NAME}" --batch --skip-column-names \
      -e "SELECT login_id, 'Test1234!' FROM users WHERE status='ACTIVE' LIMIT ${ITEM_COUNT};" \
      | awk 'BEGIN{print "userId,password"} {print $1","$2}' > "${out}"
    log "  DB에서 $(wc -l < "${out}")건 추출 완료"
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

generate_item_ids
generate_users
generate_keywords
validate_feeds

log ""
log "피더 파일 위치: ${RESOURCES_DIR}"
log "JMeter 사용 시: resources/ 경로를 jmeter/ 하위로도 복사 필요"
log "  cp -r ${RESOURCES_DIR} ${SCRIPT_DIR}/../jmeter/resources"
