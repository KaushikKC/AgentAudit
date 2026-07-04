"""Append-only (WORM-style) storage for audit entries and checkpoints.

An audit log is only trustworthy if the *substrate* resists tampering too. In
production this would be object-lock / WORM object storage or a Postgres table
with immutability triggers; for the reference implementation we use SQLite with
``UPDATE``/``DELETE`` triggers that raise, so the store is insert-only from the
application's point of view.

Two tables:
  * ``entries``     -- one row per sealed :class:`~agentaudit.schema.LogEntry`.
  * ``checkpoints`` -- one row per sealed Merkle root (size, root, signature),
    i.e. the points we can sign and externally anchor.

This is deliberately behind a small interface so the engine can later target
Postgres or an object store without changing its callers.
"""

from __future__ import annotations

import abc
import json
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Optional

from agentaudit.schema import LogEntry

__all__ = ["Checkpoint", "StorageBackend", "SQLiteStore"]


@dataclass
class Checkpoint:
    """A signed commitment to the log state at a given size."""

    session_id: str
    tree_size: int
    root_hash: str            # hex
    timestamp: str
    signature: Optional[str] = None   # hex Ed25519 sig over the checkpoint body
    public_key: Optional[str] = None  # PEM, for convenience / self-contained bundles
    anchor: Optional[str] = None      # external anchor receipt (Rekor/TSA), if any


class StorageBackend(abc.ABC):
    """The append-only persistence contract the engine depends on.

    Formalized so production backends (Postgres with immutability triggers, or an
    object-lock / WORM object store) can drop in without touching the engine. The
    only hard requirement is that entries are **insert-only** -- the substrate,
    not just the application, should refuse edits and deletes. :class:`SQLiteStore`
    is the reference implementation.
    """

    # -- entries --
    @abc.abstractmethod
    def append_entry(self, entry: LogEntry) -> None: ...
    @abc.abstractmethod
    def last_seq(self, session_id: str) -> int: ...
    @abc.abstractmethod
    def iter_entries(self, session_id: str) -> Iterator[LogEntry]: ...
    @abc.abstractmethod
    def entries(self, session_id: str) -> List[LogEntry]: ...
    @abc.abstractmethod
    def sessions(self) -> List[str]: ...

    # -- checkpoints --
    @abc.abstractmethod
    def append_checkpoint(self, cp: "Checkpoint") -> None: ...
    @abc.abstractmethod
    def latest_checkpoint(self, session_id: str) -> Optional["Checkpoint"]: ...
    @abc.abstractmethod
    def checkpoints(self, session_id: str) -> List["Checkpoint"]: ...

    def close(self) -> None:  # optional
        pass


_SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    session_id  TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    entry_hash  TEXT NOT NULL,
    body        TEXT NOT NULL,          -- full LogEntry as canonical-ish JSON
    PRIMARY KEY (session_id, seq)
);

CREATE TABLE IF NOT EXISTS checkpoints (
    session_id  TEXT NOT NULL,
    tree_size   INTEGER NOT NULL,
    root_hash   TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    signature   TEXT,
    public_key  TEXT,
    anchor      TEXT,
    PRIMARY KEY (session_id, tree_size)
);

-- Append-only enforcement: the application may INSERT but never mutate history.
CREATE TRIGGER IF NOT EXISTS entries_no_update
    BEFORE UPDATE ON entries
    BEGIN SELECT RAISE(ABORT, 'entries are append-only'); END;

CREATE TRIGGER IF NOT EXISTS entries_no_delete
    BEFORE DELETE ON entries
    BEGIN SELECT RAISE(ABORT, 'entries are append-only'); END;
"""


class SQLiteStore(StorageBackend):
    """Insert-only SQLite persistence for one or more audit sessions."""

    def __init__(self, path: str | Path = ":memory:", check_same_thread: bool = False) -> None:
        self.path = str(path)
        # Thread-safe by default: a shared connection guarded by an internal lock,
        # so background sealers and the dashboard's worker threads are all safe.
        self._conn = sqlite3.connect(self.path, check_same_thread=check_same_thread)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._lock = threading.RLock()

    # -- entries -----------------------------------------------------------
    def append_entry(self, entry: LogEntry) -> None:
        body = json.dumps(entry.signed_body() | {"entry_hash": entry.entry_hash})
        with self._lock:
            self._conn.execute(
                "INSERT INTO entries (session_id, seq, entry_hash, body) VALUES (?,?,?,?)",
                (entry.session_id, entry.seq, entry.entry_hash, body),
            )
            self._conn.commit()

    def last_seq(self, session_id: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT MAX(seq) AS m FROM entries WHERE session_id = ?", (session_id,)
            ).fetchone()
        return -1 if row["m"] is None else row["m"]

    def iter_entries(self, session_id: str) -> Iterator[LogEntry]:
        return iter(self.entries(session_id))

    def entries(self, session_id: str) -> List[LogEntry]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT body FROM entries WHERE session_id = ? ORDER BY seq ASC",
                (session_id,),
            ).fetchall()
        return [LogEntry.from_dict(json.loads(r["body"])) for r in rows]

    def sessions(self) -> List[str]:
        with self._lock:
            rows = self._conn.execute("SELECT DISTINCT session_id FROM entries").fetchall()
        return [r["session_id"] for r in rows]

    # -- checkpoints -------------------------------------------------------
    def append_checkpoint(self, cp: Checkpoint) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO checkpoints "
                "(session_id, tree_size, root_hash, timestamp, signature, public_key, anchor) "
                "VALUES (?,?,?,?,?,?,?)",
                (cp.session_id, cp.tree_size, cp.root_hash, cp.timestamp,
                 cp.signature, cp.public_key, cp.anchor),
            )
            self._conn.commit()

    def latest_checkpoint(self, session_id: str) -> Optional[Checkpoint]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM checkpoints WHERE session_id = ? "
                "ORDER BY tree_size DESC LIMIT 1",
                (session_id,),
            ).fetchone()
        return _row_to_checkpoint(row) if row else None

    def checkpoints(self, session_id: str) -> List[Checkpoint]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM checkpoints WHERE session_id = ? ORDER BY tree_size ASC",
                (session_id,),
            ).fetchall()
        return [_row_to_checkpoint(r) for r in rows]

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "SQLiteStore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _row_to_checkpoint(row: sqlite3.Row) -> Checkpoint:
    return Checkpoint(
        session_id=row["session_id"],
        tree_size=row["tree_size"],
        root_hash=row["root_hash"],
        timestamp=row["timestamp"],
        signature=row["signature"],
        public_key=row["public_key"],
        anchor=row["anchor"],
    )
