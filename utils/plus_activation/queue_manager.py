"""SQLite 持久队列 — Plus 激活任务"""

import json
import time
from typing import Optional

from utils.db_manager import get_db_conn, get_cursor, execute_sql


def _now_ts():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def enqueue(email: str, password: str, token_data: str) -> int:
    with get_db_conn(is_write=True) as conn:
        c = get_cursor(conn)
        execute_sql(c, (
            "SELECT id FROM plus_queue WHERE email = ? AND status IN ('pending', 'processing') LIMIT 1"
        ), (email,))
        if c.fetchone():
            return -1
        execute_sql(c, (
            "INSERT INTO plus_queue (email, password, token_data, status, created_at, updated_at) "
            "VALUES (?, ?, ?, 'pending', ?, ?)"
        ), (email, password, token_data, _now_ts(), _now_ts()))
        return c.lastrowid


def dequeue() -> Optional[dict]:
    with get_db_conn(is_write=True) as conn:
        c = get_cursor(conn, as_dict=True)
        execute_sql(c, (
            "SELECT * FROM plus_queue WHERE status = 'pending' "
            "ORDER BY id ASC LIMIT 1"
        ))
        row = c.fetchone()
        if not row:
            return None
        item = dict(row)
        execute_sql(c, (
            "UPDATE plus_queue SET status = 'processing', updated_at = ? WHERE id = ?"
        ), (_now_ts(), item["id"]))
        return item


def mark_done(item_id: int):
    with get_db_conn(is_write=True) as conn:
        c = get_cursor(conn)
        execute_sql(c, (
            "UPDATE plus_queue SET status = 'done', updated_at = ? WHERE id = ?"
        ), (_now_ts(), item_id))


def mark_failed(item_id: int, error_msg: str, max_retries: int = 3):
    with get_db_conn(is_write=True) as conn:
        c = get_cursor(conn, as_dict=True)
        execute_sql(c, "SELECT retry_count FROM plus_queue WHERE id = ?", (item_id,))
        row = c.fetchone()
        if not row:
            return
        retry_count = int(row["retry_count"] if isinstance(row, dict) else row[0]) + 1
        if retry_count >= max_retries:
            execute_sql(c, (
                "UPDATE plus_queue SET status = 'failed', retry_count = ?, error_msg = ?, updated_at = ? WHERE id = ?"
            ), (retry_count, error_msg[:500], _now_ts(), item_id))
        else:
            execute_sql(c, (
                "UPDATE plus_queue SET status = 'pending', retry_count = ?, error_msg = ?, updated_at = ? WHERE id = ?"
            ), (retry_count, error_msg[:500], _now_ts(), item_id))


def get_queue_stats() -> dict:
    with get_db_conn() as conn:
        c = get_cursor(conn)
        stats = {}
        for status in ("pending", "processing", "done", "failed"):
            execute_sql(c, "SELECT COUNT(*) FROM plus_queue WHERE status = ?", (status,))
            count = c.fetchone()
            stats[status] = count[0] if count else 0
        return stats


def get_queue_items(status: str = None, limit: int = 50, offset: int = 0) -> list:
    with get_db_conn() as conn:
        c = get_cursor(conn, as_dict=True)
        if status:
            execute_sql(c, (
                "SELECT id, email, status, retry_count, error_msg, created_at, updated_at "
                "FROM plus_queue WHERE status = ? ORDER BY id DESC LIMIT ? OFFSET ?"
            ), (status, limit, offset))
        else:
            execute_sql(c, (
                "SELECT id, email, status, retry_count, error_msg, created_at, updated_at "
                "FROM plus_queue ORDER BY id DESC LIMIT ? OFFSET ?"
            ), (limit, offset))
        return [dict(row) for row in c.fetchall()]


def reset_failed():
    with get_db_conn(is_write=True) as conn:
        c = get_cursor(conn)
        execute_sql(c, (
            "UPDATE plus_queue SET status = 'pending', retry_count = 0, updated_at = ? "
            "WHERE status = 'failed'"
        ), (_now_ts(),))


def cleanup_done(days: int = 7):
    cutoff = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - days * 86400))
    with get_db_conn(is_write=True) as conn:
        c = get_cursor(conn)
        execute_sql(c, "DELETE FROM plus_queue WHERE status = 'done' AND updated_at < ?", (cutoff,))


def recover_stuck(timeout_minutes: int = 30):
    cutoff = time.strftime("%Y-%m-%d %H:%M:%S",
                           time.localtime(time.time() - timeout_minutes * 60))
    with get_db_conn(is_write=True) as conn:
        c = get_cursor(conn)
        execute_sql(c, (
            "UPDATE plus_queue SET status = 'pending', updated_at = ? "
            "WHERE status = 'processing' AND updated_at < ?"
        ), (_now_ts(), cutoff))
