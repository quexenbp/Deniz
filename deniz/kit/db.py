"""Database abstraction: SQLite by default, Postgres when configured.

Stores speak ``?`` placeholders. This layer translates to ``%s`` for psycopg
and hides cursor differences. Only the four state stores use it; the HTTP
cache stays SQLite.
"""

from __future__ import annotations

import sqlite3
from contextlib import suppress
from pathlib import Path
from typing import Any


class Cursor:
    def __init__(self, raw) -> None:
        self._raw = raw

    def fetchone(self):
        return self._raw.fetchone()

    def fetchall(self):
        return self._raw.fetchall()

    @property
    def rowcount(self) -> int:
        return int(self._raw.rowcount or 0)

    @property
    def description(self):
        return self._raw.description

    @property
    def lastrowid(self):
        return getattr(self._raw, "lastrowid", None)


class Database:
    dialect = "sqlite"

    def __init__(self, raw) -> None:
        self._raw = raw

    def execute(self, sql: str, args: tuple | list = ()) -> Cursor:
        return Cursor(self._raw.execute(sql, tuple(args)))

    def executescript(self, script: str) -> None:
        self._raw.executescript(script)

    def columns(self, table: str) -> set[str]:
        rows = self._raw.execute(f"PRAGMA table_info({table})").fetchall()
        return {row[1] for row in rows}

    def executemany(self, sql: str, rows) -> None:
        self._raw.executemany(sql, rows)

    def commit(self) -> None:
        self._raw.commit()

    def close(self) -> None:
        with suppress(Exception):
            self._raw.close()


class _PgProxy:
    """Translate ``?`` placeholders and multi-statement scripts."""

    def __init__(self, conn) -> None:
        self._conn = conn

    def execute(self, sql: str, args: tuple | list = ()):
        return self._conn.execute(sql.replace("?", "%s"), tuple(args))

    def executemany(self, sql: str, rows):
        return self._conn.executemany(sql.replace("?", "%s"), rows)

    def executescript(self, script: str) -> None:
        for statement in script.strip().split(";"):
            if statement.strip():
                self._conn.execute(statement)

    def commit(self) -> None:
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __getattr__(self, name):
        return getattr(self._conn, name)


class PostgresDatabase(Database):
    dialect = "postgres"

    def __init__(self, raw) -> None:
        self._raw = _PgProxy(raw)

    def execute(self, sql: str, args: tuple | list = ()) -> Cursor:
        return Cursor(self._raw.execute(sql, tuple(args)))

    def executescript(self, script: str) -> None:
        self._raw.executescript(script)

    def columns(self, table: str) -> set[str]:
        cur = self._raw.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name=%s", (table,)
        )
        return {row[0] for row in cur.fetchall()}

    def executemany(self, sql: str, rows) -> None:
        self._raw.executemany(sql, rows)

    @staticmethod
    def serial() -> str:
        return "BIGSERIAL PRIMARY KEY"


def connect(target: Path | str) -> Database:
    if isinstance(target, str) and target.startswith(("postgres://", "postgresql://")):
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover - optional extra
            raise RuntimeError("Postgres needs: pip install 'deniz[postgres]'") from exc
        db = PostgresDatabase(psycopg.connect(target, autocommit=False, connect_timeout=10))
        return db
    path = Path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = sqlite3.connect(path, check_same_thread=False)
    raw.execute("PRAGMA journal_mode=WAL")
    return Database(raw)


def is_dsn(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(("postgres://", "postgresql://"))
