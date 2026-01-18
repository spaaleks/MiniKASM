import sqlite3
import logging
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("DB_PATH", "/data/minikasm.db")

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    container_id TEXT NOT NULL,
    username TEXT NOT NULL,
    image_key TEXT,
    alias TEXT,
    state TEXT DEFAULT 'running',
    delete_protected INTEGER DEFAULT 0,
    created_at REAL NOT NULL,
    last_seen REAL NOT NULL,
    container_ip TEXT,
    vnc_password TEXT
);

CREATE TABLE IF NOT EXISTS session_volumes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    volume_name TEXT NOT NULL,
    mount_path TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username);
CREATE INDEX IF NOT EXISTS idx_sessions_state ON sessions(state);
CREATE INDEX IF NOT EXISTS idx_session_volumes_session ON session_volumes(session_id);
"""


@dataclass
class SessionRow:
    session_id: str
    container_id: str
    username: str
    image_key: str | None
    alias: str | None
    state: str
    delete_protected: bool
    created_at: float
    last_seen: float
    container_ip: str | None
    vnc_password: str | None


def _ensure_db_dir():
    db_dir = os.path.dirname(DB_PATH)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)


@contextmanager
def get_connection():
    _ensure_db_dir()
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_connection() as conn:
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
        )
        if not cursor.fetchone():
            logger.info("Initializing database schema...")
            conn.executescript(SCHEMA)
            conn.execute("INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,))
            logger.info(f"Database initialized with schema version {SCHEMA_VERSION}")
        else:
            cursor = conn.execute("SELECT version FROM schema_version")
            row = cursor.fetchone()
            current_version = row["version"] if row else 0
            if current_version < SCHEMA_VERSION:
                _run_migrations(conn, current_version)


def _run_migrations(conn: sqlite3.Connection, from_version: int):
    logger.info(f"Migrating database from version {from_version} to {SCHEMA_VERSION}")
    conn.execute("UPDATE schema_version SET version = ?", (SCHEMA_VERSION,))
    logger.info(f"Database migrated to version {SCHEMA_VERSION}")


def create_session(
    session_id: str,
    container_id: str,
    username: str,
    created_at: float,
    container_ip: str | None = None,
    vnc_password: str | None = None,
    image_key: str | None = None,
    alias: str | None = None,
    state: str = "running",
) -> SessionRow:
    now = time.time()
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO sessions
            (session_id, container_id, username, image_key, alias, state,
             delete_protected, created_at, last_seen, container_ip, vnc_password)
            VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
            """,
            (session_id, container_id, username, image_key, alias, state,
             created_at, now, container_ip, vnc_password)
        )
    logger.debug(f"Created session record: {session_id}")
    return SessionRow(
        session_id=session_id,
        container_id=container_id,
        username=username,
        image_key=image_key,
        alias=alias,
        state=state,
        delete_protected=False,
        created_at=created_at,
        last_seen=now,
        container_ip=container_ip,
        vnc_password=vnc_password,
    )


def get_session(session_id: str) -> SessionRow | None:
    with get_connection() as conn:
        cursor = conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        )
        row = cursor.fetchone()
        if row:
            return _row_to_session(row)
    return None


def get_sessions_for_user(username: str) -> list[SessionRow]:
    with get_connection() as conn:
        cursor = conn.execute(
            "SELECT * FROM sessions WHERE username = ? ORDER BY created_at DESC",
            (username,)
        )
        return [_row_to_session(row) for row in cursor.fetchall()]


def get_all_sessions() -> list[SessionRow]:
    with get_connection() as conn:
        cursor = conn.execute("SELECT * FROM sessions ORDER BY created_at DESC")
        return [_row_to_session(row) for row in cursor.fetchall()]


def update_session_activity(session_id: str) -> bool:
    with get_connection() as conn:
        cursor = conn.execute(
            "UPDATE sessions SET last_seen = ? WHERE session_id = ?",
            (time.time(), session_id)
        )
        return cursor.rowcount > 0


def update_session_ip(session_id: str, container_ip: str) -> bool:
    with get_connection() as conn:
        cursor = conn.execute(
            "UPDATE sessions SET container_ip = ? WHERE session_id = ?",
            (container_ip, session_id)
        )
        return cursor.rowcount > 0


def update_session_state(session_id: str, state: str) -> bool:
    with get_connection() as conn:
        cursor = conn.execute(
            "UPDATE sessions SET state = ? WHERE session_id = ?",
            (state, session_id)
        )
        return cursor.rowcount > 0


def update_session_alias(session_id: str, alias: str | None) -> bool:
    with get_connection() as conn:
        cursor = conn.execute(
            "UPDATE sessions SET alias = ? WHERE session_id = ?",
            (alias, session_id)
        )
        return cursor.rowcount > 0


def update_session_protection(session_id: str, protected: bool) -> bool:
    with get_connection() as conn:
        cursor = conn.execute(
            "UPDATE sessions SET delete_protected = ? WHERE session_id = ?",
            (1 if protected else 0, session_id)
        )
        return cursor.rowcount > 0


def is_session_protected(session_id: str) -> bool:
    with get_connection() as conn:
        cursor = conn.execute(
            "SELECT delete_protected FROM sessions WHERE session_id = ?",
            (session_id,)
        )
        row = cursor.fetchone()
        return bool(row and row["delete_protected"])


def delete_session(session_id: str) -> bool:
    with get_connection() as conn:
        cursor = conn.execute(
            "DELETE FROM sessions WHERE session_id = ?", (session_id,)
        )
        deleted = cursor.rowcount > 0
        if deleted:
            logger.debug(f"Deleted session record: {session_id}")
        return deleted


def session_exists(session_id: str) -> bool:
    with get_connection() as conn:
        cursor = conn.execute(
            "SELECT 1 FROM sessions WHERE session_id = ?", (session_id,)
        )
        return cursor.fetchone() is not None


def add_session_volume(session_id: str, volume_name: str, mount_path: str) -> int:
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO session_volumes (session_id, volume_name, mount_path)
            VALUES (?, ?, ?)
            """,
            (session_id, volume_name, mount_path)
        )
        return cursor.lastrowid


def get_session_volumes(session_id: str) -> list[dict[str, str]]:
    with get_connection() as conn:
        cursor = conn.execute(
            "SELECT volume_name, mount_path FROM session_volumes WHERE session_id = ?",
            (session_id,)
        )
        return [{"volume_name": row["volume_name"], "mount_path": row["mount_path"]}
                for row in cursor.fetchall()]


def _row_to_session(row: sqlite3.Row) -> SessionRow:
    return SessionRow(
        session_id=row["session_id"],
        container_id=row["container_id"],
        username=row["username"],
        image_key=row["image_key"],
        alias=row["alias"],
        state=row["state"],
        delete_protected=bool(row["delete_protected"]),
        created_at=row["created_at"],
        last_seen=row["last_seen"],
        container_ip=row["container_ip"],
        vnc_password=row["vnc_password"],
    )


def migrate_container_to_db(
    session_id: str,
    container_id: str,
    username: str,
    created_at: float,
    container_ip: str | None = None,
    vnc_password: str | None = None,
    state: str = "running",
) -> SessionRow | None:
    if session_exists(session_id):
        if container_ip:
            update_session_ip(session_id, container_ip)
        return get_session(session_id)

    return create_session(
        session_id=session_id,
        container_id=container_id,
        username=username,
        created_at=created_at,
        container_ip=container_ip,
        vnc_password=vnc_password,
        state=state,
    )
