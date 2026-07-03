#!/usr/bin/env python3
"""
KISA 보호나라(boho.or.kr) 보안공지 감시 — SQLite data access layer.

Schema:
    security_notice — one row per KISA 보안공지 post that mentions a
                      watched product (Apache/Tomcat/WildFly/Nginx),
                      keyed by the post's nttId so re-checking never
                      creates duplicates.
    security_meta   — small key/value store for the last check time
                      and last error, so the UI can show watch health.
"""
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional

DB_PATH = Path(__file__).parent / "security_watch.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS security_notice (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ntt_id         TEXT NOT NULL UNIQUE,
    product        TEXT NOT NULL,
    title          TEXT NOT NULL,
    posted_date    TEXT,
    recommendation TEXT,
    min_version    TEXT,
    url            TEXT NOT NULL,
    checked_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS security_meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE INDEX IF NOT EXISTS idx_security_notice_product ON security_notice(product);
"""


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = _conn()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def _row(r: Optional[sqlite3.Row]) -> Optional[Dict]:
    return dict(r) if r is not None else None


def _rows(rs: List[sqlite3.Row]) -> List[Dict]:
    return [dict(r) for r in rs]


def list_notices(product: Optional[str] = None, since: Optional[str] = None) -> List[Dict]:
    """since가 주어지면 posted_date가 그보다 오래된 글은 제외한다
    (posted_date를 못 읽은 글은 날짜를 알 수 없으므로 계속 보여준다)."""
    conditions = []
    params: List[str] = []
    if product:
        conditions.append("product = ?")
        params.append(product)
    if since:
        conditions.append("(posted_date IS NULL OR posted_date >= ?)")
        params.append(since)
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    conn = _conn()
    try:
        rows = conn.execute(
            f"SELECT * FROM security_notice {where} ORDER BY posted_date DESC, id DESC",
            params,
        ).fetchall()
        return _rows(rows)
    finally:
        conn.close()


def upsert_notice(*, ntt_id: str, product: str, title: str, posted_date: Optional[str],
                   recommendation: Optional[str], min_version: Optional[str], url: str) -> bool:
    """Insert a notice if its nttId is new; update it if the recommendation
    text changed (KISA sometimes edits a notice after publishing). Returns
    True if this was a new notice."""
    conn = _conn()
    try:
        existing = conn.execute(
            "SELECT id, recommendation FROM security_notice WHERE ntt_id = ?", (ntt_id,)
        ).fetchone()
        if existing is None:
            conn.execute(
                "INSERT INTO security_notice "
                "(ntt_id, product, title, posted_date, recommendation, min_version, url) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (ntt_id, product, title, posted_date, recommendation, min_version, url),
            )
            conn.commit()
            return True
        if existing["recommendation"] != recommendation:
            conn.execute(
                "UPDATE security_notice SET title=?, posted_date=?, recommendation=?, "
                "min_version=?, url=?, checked_at=datetime('now') WHERE ntt_id=?",
                (title, posted_date, recommendation, min_version, url, ntt_id),
            )
            conn.commit()
        return False
    finally:
        conn.close()


def delete_notice(ntt_id: str) -> bool:
    conn = _conn()
    try:
        cur = conn.execute("DELETE FROM security_notice WHERE ntt_id = ?", (ntt_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def get_meta(key: str) -> Optional[str]:
    conn = _conn()
    try:
        row = conn.execute("SELECT value FROM security_meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None
    finally:
        conn.close()


def set_meta(key: str, value: str) -> None:
    conn = _conn()
    try:
        conn.execute(
            "INSERT INTO security_meta (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        conn.commit()
    finally:
        conn.close()
