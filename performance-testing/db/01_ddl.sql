-- ============================================================
-- WildFly 26 성능테스트용 PostgreSQL DDL
-- 실행: psql -h 43.203.161.30 -p 5432 -U claude -d claude -f 01_ddl.sql
-- ============================================================

-- ── 기존 테이블 정리 (재실행 시) ────────────────────────────────────────────
DROP TABLE IF EXISTS order_items   CASCADE;
DROP TABLE IF EXISTS orders        CASCADE;
DROP TABLE IF EXISTS user_history  CASCADE;
DROP TABLE IF EXISTS users         CASCADE;
DROP TABLE IF EXISTS items         CASCADE;
DROP TABLE IF EXISTS categories    CASCADE;

-- ── 카테고리 ─────────────────────────────────────────────────────────────────
CREATE TABLE categories (
    id          SERIAL          PRIMARY KEY,
    name        VARCHAR(100)    NOT NULL,
    description VARCHAR(500),
    status      VARCHAR(20)     NOT NULL DEFAULT 'ACTIVE',
    created_at  TIMESTAMP       NOT NULL DEFAULT NOW()
);

-- ── 상품 ─────────────────────────────────────────────────────────────────────
CREATE TABLE items (
    id          SERIAL          PRIMARY KEY,
    category_id INTEGER         REFERENCES categories(id),
    name        VARCHAR(200)    NOT NULL,
    description TEXT,
    price       INTEGER         NOT NULL DEFAULT 0,
    stock       INTEGER         NOT NULL DEFAULT 0,
    status      VARCHAR(20)     NOT NULL DEFAULT 'ACTIVE',
    created_at  TIMESTAMP       NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMP       NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_items_status      ON items(status);
CREATE INDEX idx_items_category_id ON items(category_id);
CREATE INDEX idx_items_name        ON items(name);

-- ── 사용자 ───────────────────────────────────────────────────────────────────
CREATE TABLE users (
    id          SERIAL          PRIMARY KEY,
    login_id    VARCHAR(100)    NOT NULL UNIQUE,
    password    VARCHAR(255)    NOT NULL,
    name        VARCHAR(100)    NOT NULL,
    email       VARCHAR(200),
    status      VARCHAR(20)     NOT NULL DEFAULT 'ACTIVE',
    last_login  TIMESTAMP,
    created_at  TIMESTAMP       NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_login_id ON users(login_id);
CREATE INDEX idx_users_status   ON users(status);

-- ── 사용자 이력 ──────────────────────────────────────────────────────────────
CREATE TABLE user_history (
    id          BIGSERIAL       PRIMARY KEY,
    user_id     INTEGER         NOT NULL REFERENCES users(id),
    action      VARCHAR(100)    NOT NULL,
    target_type VARCHAR(50),
    target_id   INTEGER,
    detail      TEXT,
    created_at  TIMESTAMP       NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_user_history_user_id    ON user_history(user_id);
CREATE INDEX idx_user_history_created_at ON user_history(created_at);

-- ── 주문 ─────────────────────────────────────────────────────────────────────
CREATE TABLE orders (
    id              BIGSERIAL       PRIMARY KEY,
    user_id         INTEGER         NOT NULL REFERENCES users(id),
    status          VARCHAR(30)     NOT NULL DEFAULT 'CONFIRMED',
    total_amount    INTEGER         NOT NULL DEFAULT 0,
    payment_method  VARCHAR(50)     NOT NULL DEFAULT 'CARD',
    delivery_addr   VARCHAR(500),
    created_at      TIMESTAMP       NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP       NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_orders_user_id    ON orders(user_id);
CREATE INDEX idx_orders_status     ON orders(status);
CREATE INDEX idx_orders_created_at ON orders(created_at);

-- ── 주문 상품 ────────────────────────────────────────────────────────────────
CREATE TABLE order_items (
    id          BIGSERIAL   PRIMARY KEY,
    order_id    BIGINT      NOT NULL REFERENCES orders(id),
    item_id     INTEGER     NOT NULL REFERENCES items(id),
    quantity    INTEGER     NOT NULL DEFAULT 1,
    unit_price  INTEGER     NOT NULL DEFAULT 0,
    total_price INTEGER     NOT NULL DEFAULT 0
);

CREATE INDEX idx_order_items_order_id ON order_items(order_id);
CREATE INDEX idx_order_items_item_id  ON order_items(item_id);

-- ── 완료 메시지 ──────────────────────────────────────────────────────────────
DO $$
BEGIN
    RAISE NOTICE '테이블 생성 완료: categories, items, users, user_history, orders, order_items';
END $$;
