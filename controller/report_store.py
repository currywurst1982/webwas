#!/usr/bin/env python3
"""
Weekly WEB/WAS Operations Report — SQLite data access layer.

Schema:
    report_week      — one row per weekly report (date range for "this week"
                        and, optionally, the upcoming "next week")
    operation_status  — per-client WEB/WAS/개발 server counts (last week vs
                        this week), one report_week has many rows
    work_log          — 진행 내역 rows, tagged section='current' (금주) or
                        section='next' (차주)
    special_note      — 특이 사항 rows (incident/장애 log)
"""
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional

DB_PATH = Path(__file__).parent / "report.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS report_week (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    start_date       TEXT NOT NULL,
    end_date         TEXT NOT NULL,
    next_start_date  TEXT,
    next_end_date    TEXT,
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(start_date, end_date)
);

CREATE TABLE IF NOT EXISTS operation_status (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    report_week_id   INTEGER NOT NULL REFERENCES report_week(id) ON DELETE CASCADE,
    sort_order       INTEGER NOT NULL DEFAULT 0,
    client_name      TEXT NOT NULL,
    last_web         INTEGER NOT NULL DEFAULT 0,
    last_was         INTEGER NOT NULL DEFAULT 0,
    last_dev         INTEGER NOT NULL DEFAULT 0,
    this_web         INTEGER NOT NULL DEFAULT 0,
    this_was         INTEGER NOT NULL DEFAULT 0,
    this_dev         INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS work_log (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    report_week_id   INTEGER NOT NULL REFERENCES report_week(id) ON DELETE CASCADE,
    section          TEXT NOT NULL CHECK(section IN ('current','next')),
    sort_order       INTEGER NOT NULL DEFAULT 0,
    category         TEXT,
    request_date     TEXT,
    requester        TEXT,
    work_date        TEXT,
    work_content     TEXT,
    web_count        INTEGER NOT NULL DEFAULT 0,
    was_count        INTEGER NOT NULL DEFAULT 0,
    etc_count        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS special_note (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    report_week_id   INTEGER NOT NULL REFERENCES report_week(id) ON DELETE CASCADE,
    sort_order       INTEGER NOT NULL DEFAULT 0,
    category         TEXT,
    note_date        TEXT,
    title            TEXT,
    service_name     TEXT,
    detail           TEXT
);

CREATE INDEX IF NOT EXISTS idx_operation_status_week ON operation_status(report_week_id);
CREATE INDEX IF NOT EXISTS idx_work_log_week          ON work_log(report_week_id);
CREATE INDEX IF NOT EXISTS idx_special_note_week      ON special_note(report_week_id);
"""


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
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


# ─── report_week ────────────────────────────────────────────────────────────
def list_weeks() -> List[Dict]:
    conn = _conn()
    try:
        return _rows(conn.execute(
            "SELECT * FROM report_week ORDER BY start_date DESC, id DESC"
        ).fetchall())
    finally:
        conn.close()


def get_week(week_id: int) -> Optional[Dict]:
    conn = _conn()
    try:
        return _row(conn.execute(
            "SELECT * FROM report_week WHERE id = ?", (week_id,)
        ).fetchone())
    finally:
        conn.close()


def find_week_by_dates(start_date: str, end_date: str) -> Optional[Dict]:
    conn = _conn()
    try:
        return _row(conn.execute(
            "SELECT * FROM report_week WHERE start_date = ? AND end_date = ?",
            (start_date, end_date),
        ).fetchone())
    finally:
        conn.close()


def create_week(start_date: str, end_date: str,
                 next_start_date: Optional[str] = None,
                 next_end_date: Optional[str] = None) -> Dict:
    conn = _conn()
    try:
        cur = conn.execute(
            "INSERT INTO report_week (start_date, end_date, next_start_date, next_end_date) "
            "VALUES (?, ?, ?, ?)",
            (start_date, end_date, next_start_date, next_end_date),
        )
        conn.commit()
        return get_week(cur.lastrowid)
    finally:
        conn.close()


def update_week(week_id: int, start_date: str, end_date: str,
                 next_start_date: Optional[str], next_end_date: Optional[str]) -> Optional[Dict]:
    conn = _conn()
    try:
        conn.execute(
            "UPDATE report_week SET start_date=?, end_date=?, next_start_date=?, next_end_date=? "
            "WHERE id=?",
            (start_date, end_date, next_start_date, next_end_date, week_id),
        )
        conn.commit()
        return get_week(week_id)
    finally:
        conn.close()


def delete_week(week_id: int) -> bool:
    conn = _conn()
    try:
        cur = conn.execute("DELETE FROM report_week WHERE id = ?", (week_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def get_report_bundle(week_id: int) -> Optional[Dict]:
    """Everything the report screen needs for one week, in a single call."""
    week = get_week(week_id)
    if not week:
        return None
    conn = _conn()
    try:
        ops = _rows(conn.execute(
            "SELECT * FROM operation_status WHERE report_week_id=? ORDER BY sort_order, id",
            (week_id,),
        ).fetchall())
        logs = _rows(conn.execute(
            "SELECT * FROM work_log WHERE report_week_id=? ORDER BY section, sort_order, id",
            (week_id,),
        ).fetchall())
        notes = _rows(conn.execute(
            "SELECT * FROM special_note WHERE report_week_id=? ORDER BY sort_order, id",
            (week_id,),
        ).fetchall())
    finally:
        conn.close()
    return {
        "week": week,
        "operation_status": ops,
        "work_log_current": [r for r in logs if r["section"] == "current"],
        "work_log_next": [r for r in logs if r["section"] == "next"],
        "special_notes": notes,
    }


# ─── operation_status ───────────────────────────────────────────────────────
def add_operation_status(week_id: int, client_name: str, sort_order: int,
                          last_web: int, last_was: int, last_dev: int,
                          this_web: int, this_was: int, this_dev: int) -> Dict:
    conn = _conn()
    try:
        cur = conn.execute(
            "INSERT INTO operation_status "
            "(report_week_id, client_name, sort_order, last_web, last_was, last_dev, "
            " this_web, this_was, this_dev) VALUES (?,?,?,?,?,?,?,?,?)",
            (week_id, client_name, sort_order, last_web, last_was, last_dev,
             this_web, this_was, this_dev),
        )
        conn.commit()
        return _row(conn.execute("SELECT * FROM operation_status WHERE id=?", (cur.lastrowid,)).fetchone())
    finally:
        conn.close()


def update_operation_status(row_id: int, client_name: str, sort_order: int,
                             last_web: int, last_was: int, last_dev: int,
                             this_web: int, this_was: int, this_dev: int) -> Optional[Dict]:
    conn = _conn()
    try:
        conn.execute(
            "UPDATE operation_status SET client_name=?, sort_order=?, last_web=?, last_was=?, "
            "last_dev=?, this_web=?, this_was=?, this_dev=? WHERE id=?",
            (client_name, sort_order, last_web, last_was, last_dev,
             this_web, this_was, this_dev, row_id),
        )
        conn.commit()
        return _row(conn.execute("SELECT * FROM operation_status WHERE id=?", (row_id,)).fetchone())
    finally:
        conn.close()


def delete_operation_status(row_id: int) -> bool:
    conn = _conn()
    try:
        cur = conn.execute("DELETE FROM operation_status WHERE id = ?", (row_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


# ─── work_log ───────────────────────────────────────────────────────────────
def add_work_log(week_id: int, section: str, sort_order: int, category: str,
                  request_date: str, requester: str, work_date: str, work_content: str,
                  web_count: int, was_count: int, etc_count: int) -> Dict:
    conn = _conn()
    try:
        cur = conn.execute(
            "INSERT INTO work_log (report_week_id, section, sort_order, category, request_date, "
            "requester, work_date, work_content, web_count, was_count, etc_count) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (week_id, section, sort_order, category, request_date, requester,
             work_date, work_content, web_count, was_count, etc_count),
        )
        conn.commit()
        return _row(conn.execute("SELECT * FROM work_log WHERE id=?", (cur.lastrowid,)).fetchone())
    finally:
        conn.close()


def update_work_log(row_id: int, section: str, sort_order: int, category: str,
                     request_date: str, requester: str, work_date: str, work_content: str,
                     web_count: int, was_count: int, etc_count: int) -> Optional[Dict]:
    conn = _conn()
    try:
        conn.execute(
            "UPDATE work_log SET section=?, sort_order=?, category=?, request_date=?, requester=?, "
            "work_date=?, work_content=?, web_count=?, was_count=?, etc_count=? WHERE id=?",
            (section, sort_order, category, request_date, requester, work_date, work_content,
             web_count, was_count, etc_count, row_id),
        )
        conn.commit()
        return _row(conn.execute("SELECT * FROM work_log WHERE id=?", (row_id,)).fetchone())
    finally:
        conn.close()


def delete_work_log(row_id: int) -> bool:
    conn = _conn()
    try:
        cur = conn.execute("DELETE FROM work_log WHERE id = ?", (row_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


# ─── special_note ───────────────────────────────────────────────────────────
def add_special_note(week_id: int, sort_order: int, category: str, note_date: str,
                      title: str, service_name: str, detail: str) -> Dict:
    conn = _conn()
    try:
        cur = conn.execute(
            "INSERT INTO special_note (report_week_id, sort_order, category, note_date, title, "
            "service_name, detail) VALUES (?,?,?,?,?,?,?)",
            (week_id, sort_order, category, note_date, title, service_name, detail),
        )
        conn.commit()
        return _row(conn.execute("SELECT * FROM special_note WHERE id=?", (cur.lastrowid,)).fetchone())
    finally:
        conn.close()


def update_special_note(row_id: int, sort_order: int, category: str, note_date: str,
                         title: str, service_name: str, detail: str) -> Optional[Dict]:
    conn = _conn()
    try:
        conn.execute(
            "UPDATE special_note SET sort_order=?, category=?, note_date=?, title=?, "
            "service_name=?, detail=? WHERE id=?",
            (sort_order, category, note_date, title, service_name, detail, row_id),
        )
        conn.commit()
        return _row(conn.execute("SELECT * FROM special_note WHERE id=?", (row_id,)).fetchone())
    finally:
        conn.close()


def delete_special_note(row_id: int) -> bool:
    conn = _conn()
    try:
        cur = conn.execute("DELETE FROM special_note WHERE id = ?", (row_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()
