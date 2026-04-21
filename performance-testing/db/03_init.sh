#!/usr/bin/env bash
# ============================================================
# DB 초기화 및 테스트 데이터 적재 스크립트
# 실행: bash db/03_init.sh
# ============================================================

set -euo pipefail

DB_HOST=${DB_HOST:-"43.203.161.30"}
DB_PORT=${DB_PORT:-"5432"}
DB_NAME=${DB_NAME:-"claude"}
DB_USER=${DB_USER:-"claude"}
DB_PASS=${DB_PASS:-"claude"}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

export PGPASSWORD="${DB_PASS}"

PSQL="psql -h ${DB_HOST} -p ${DB_PORT} -U ${DB_USER} -d ${DB_NAME}"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

log "DB 접속 확인..."
${PSQL} -c "SELECT version();" -t -q | head -1
log "접속 성공"

log "1/2 DDL 실행 (테이블 생성)..."
${PSQL} -f "${SCRIPT_DIR}/01_ddl.sql"
log "테이블 생성 완료"

log "2/2 DML 실행 (샘플 데이터 적재)..."
${PSQL} -f "${SCRIPT_DIR}/02_dml.sql"
log "데이터 적재 완료"

log ""
log "=== 최종 데이터 현황 ==="
${PSQL} -c "
SELECT tablename AS 테이블, cnt AS 건수 FROM (
    SELECT 'categories'  AS tablename, COUNT(*) AS cnt FROM categories UNION ALL
    SELECT 'items',        COUNT(*) FROM items       UNION ALL
    SELECT 'users',        COUNT(*) FROM users       UNION ALL
    SELECT 'user_history', COUNT(*) FROM user_history UNION ALL
    SELECT 'orders',       COUNT(*) FROM orders      UNION ALL
    SELECT 'order_items',  COUNT(*) FROM order_items
) t ORDER BY tablename;
"

log ""
log "완료. 이제 피더 파일 생성을 실행하세요:"
log ""
log "  DB_HOST=${DB_HOST} DB_PORT=${DB_PORT} DB_NAME=${DB_NAME} \\"
log "  DB_USER=${DB_USER} DB_PASS=${DB_PASS} \\"
log "  ITEM_TABLE=items   ITEM_ID_COL=id   ITEM_STATUS_COL=status \\"
log "  USER_TABLE=users   USER_LOGIN_COL=login_id USER_STATUS_COL=status \\"
log "  bash scripts/generate-test-data.sh --db-extract --db-type postgresql --count 300"
