#!/usr/bin/env bash
# ============================================================
# DB 테스트 WAR 빌드 & WildFly 배포 스크립트
# 사용법: ./deploy.sh [WILDFLY_HOME]
# 예)     ./deploy.sh /opt/wildfly-26
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WEBAPP_DIR="${SCRIPT_DIR}/src/main/webapp"
WILDFLY_HOME="${1:-/opt/wildfly-26}"
DEPLOY_DIR="${WILDFLY_HOME}/standalone/deployments"
WAR_NAME="db-perf-test.war"
WAR_PATH="${DEPLOY_DIR}/${WAR_NAME}"

# ── WAR 빌드 (jar 명령 이용) ────────────────────────────────────────────────
echo "[1/3] WAR 빌드 중..."
TMP_DIR=$(mktemp -d)
cp -r "${WEBAPP_DIR}/." "${TMP_DIR}/"
cd "${TMP_DIR}"
jar -cf "${SCRIPT_DIR}/${WAR_NAME}" .
cd "${SCRIPT_DIR}"
rm -rf "${TMP_DIR}"
echo "  → ${WAR_NAME} 생성 완료"

# ── WildFly deployments 디렉토리에 복사 ─────────────────────────────────────
echo "[2/3] WildFly에 배포 중... (${DEPLOY_DIR})"
cp "${SCRIPT_DIR}/${WAR_NAME}" "${WAR_PATH}"
echo "  → 복사 완료"

# ── 배포 완료 대기 ───────────────────────────────────────────────────────────
echo "[3/3] 배포 완료 대기 중..."
for i in $(seq 1 30); do
    if [[ -f "${WAR_PATH}.deployed" ]]; then
        echo "  ✓ 배포 완료!"
        break
    elif [[ -f "${WAR_PATH}.failed" ]]; then
        echo "  ✗ 배포 실패! ${WAR_PATH}.failed 확인"
        cat "${WAR_PATH}.failed" 2>/dev/null || true
        exit 1
    fi
    echo "  대기 중... (${i}/30)"
    sleep 2
done

# ── 접속 확인 ─────────────────────────────────────────────────────────────────
BASE_URL="${BASE_URL:-http://localhost:8080}"
echo ""
echo "배포 완료. 엔드포인트 테스트:"
echo "  DB Ping:   curl '${BASE_URL}/db-perf-test/db-ping.jsp'"
echo "  DB SELECT: curl '${BASE_URL}/db-perf-test/db-query.jsp?type=select'"
echo "  DB INSERT: curl '${BASE_URL}/db-perf-test/db-query.jsp?type=insert'"
