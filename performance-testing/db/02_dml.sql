-- ============================================================
-- WildFly 26 성능테스트용 PostgreSQL 샘플 데이터 (DML)
-- 실행: psql -h 43.203.161.30 -p 5432 -U claude -d claude -f 02_dml.sql
--
-- 데이터 구성:
--   categories : 10건
--   items      : 1,000건  (성능테스트 시 SELECT 부하 대상)
--   users      : 500건   (로그인 / 이력 조회 대상)
--   user_history: 5,000건
--   orders     : 2,000건
--   order_items: 6,000건
-- ============================================================

-- ── 카테고리 10건 ────────────────────────────────────────────────────────────
INSERT INTO categories (name, description, status) VALUES
    ('전자제품',   '노트북, 스마트폰, 태블릿 등',       'ACTIVE'),
    ('가전제품',   '냉장고, 세탁기, 에어컨 등',         'ACTIVE'),
    ('컴퓨터부품', 'CPU, RAM, SSD, 그래픽카드 등',       'ACTIVE'),
    ('음향기기',   '헤드폰, 스피커, 이어폰 등',         'ACTIVE'),
    ('주변기기',   '키보드, 마우스, 모니터 등',         'ACTIVE'),
    ('카메라',     '디지털카메라, 렌즈, 액세서리 등',   'ACTIVE'),
    ('스마트홈',   '공기청정기, 로봇청소기, IoT 등',    'ACTIVE'),
    ('생활가전',   '전기밥솥, 커피머신, 믹서기 등',     'ACTIVE'),
    ('네트워크',   '공유기, 스위치, 케이블 등',         'ACTIVE'),
    ('기타',       '기타 전자 제품',                    'ACTIVE');

-- ── 상품 1,000건 ─────────────────────────────────────────────────────────────
INSERT INTO items (category_id, name, price, stock, status)
SELECT
    (mod(gs.n, 10) + 1)                         AS category_id,
    '상품-' || LPAD(gs.n::TEXT, 4, '0')         AS name,
    (FLOOR(RANDOM() * 990 + 1) * 1000)::INTEGER AS price,
    (FLOOR(RANDOM() * 500 + 10))::INTEGER       AS stock,
    CASE WHEN gs.n % 20 = 0 THEN 'INACTIVE' ELSE 'ACTIVE' END AS status
FROM generate_series(1, 1000) AS gs(n);

-- ── 사용자 500건 (비밀번호: Test1234! → BCrypt 해시값) ──────────────────────
-- 실제 애플리케이션 인증 방식에 따라 password 컬럼값 변경 필요
-- 아래는 평문 저장 예시 (테스트 전용 DB에서만 허용)
INSERT INTO users (login_id, password, name, email, status)
SELECT
    'testuser' || LPAD(gs.n::TEXT, 4, '0')           AS login_id,
    'Test1234!'                                        AS password,
    '테스트사용자-' || gs.n                           AS name,
    'testuser' || gs.n || '@perf-test.local'          AS email,
    CASE WHEN gs.n % 50 = 0 THEN 'INACTIVE' ELSE 'ACTIVE' END AS status
FROM generate_series(1, 500) AS gs(n);

-- ── 사용자 이력 5,000건 ──────────────────────────────────────────────────────
INSERT INTO user_history (user_id, action, target_type, target_id, detail, created_at)
SELECT
    (FLOOR(RANDOM() * 500 + 1))::INTEGER AS user_id,
    (ARRAY['LOGIN','LOGOUT','VIEW_ITEM','ADD_CART','PURCHASE',
           'CANCEL_ORDER','CHANGE_PW','UPDATE_PROFILE'])[
        FLOOR(RANDOM() * 8 + 1)::INTEGER]  AS action,
    'ITEM'                               AS target_type,
    (FLOOR(RANDOM() * 1000 + 1))::INTEGER AS target_id,
    '성능테스트 이력 데이터 ' || gs.n    AS detail,
    NOW() - (FLOOR(RANDOM() * 90) || ' days')::INTERVAL AS created_at
FROM generate_series(1, 5000) AS gs(n);

-- ── 주문 2,000건 ─────────────────────────────────────────────────────────────
INSERT INTO orders (user_id, status, total_amount, payment_method, delivery_addr, created_at)
SELECT
    (FLOOR(RANDOM() * 500 + 1))::INTEGER AS user_id,
    (ARRAY['CONFIRMED','SHIPPING','DELIVERED','CANCELLED'])[
        FLOOR(RANDOM() * 4 + 1)::INTEGER] AS status,
    (FLOOR(RANDOM() * 500 + 1) * 1000)::INTEGER AS total_amount,
    (ARRAY['CARD','BANK_TRANSFER','POINT','KAKAO_PAY'])[
        FLOOR(RANDOM() * 4 + 1)::INTEGER] AS payment_method,
    '서울시 테스트구 성능동 ' || gs.n || '번지' AS delivery_addr,
    NOW() - (FLOOR(RANDOM() * 180) || ' days')::INTERVAL AS created_at
FROM generate_series(1, 2000) AS gs(n);

-- ── 주문 상품 (주문당 1~3건, 총 약 6,000건) ──────────────────────────────────
INSERT INTO order_items (order_id, item_id, quantity, unit_price, total_price)
SELECT
    o.id                                          AS order_id,
    (FLOOR(RANDOM() * 1000 + 1))::INTEGER         AS item_id,
    (FLOOR(RANDOM() * 3 + 1))::INTEGER            AS quantity,
    (FLOOR(RANDOM() * 100 + 1) * 1000)::INTEGER   AS unit_price,
    (FLOOR(RANDOM() * 3 + 1) *
     FLOOR(RANDOM() * 100 + 1) * 1000)::INTEGER   AS total_price
FROM orders o
CROSS JOIN generate_series(1, 3) AS gs(n)
WHERE RANDOM() > 0.1;  -- 일부 주문은 1~2건만

-- ── 데이터 건수 확인 ─────────────────────────────────────────────────────────
SELECT
    'categories'  AS tablename, COUNT(*) AS cnt FROM categories UNION ALL
SELECT 'items',        COUNT(*) FROM items       UNION ALL
SELECT 'users',        COUNT(*) FROM users       UNION ALL
SELECT 'user_history', COUNT(*) FROM user_history UNION ALL
SELECT 'orders',       COUNT(*) FROM orders      UNION ALL
SELECT 'order_items',  COUNT(*) FROM order_items
ORDER BY tablename;
