from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from aegismeta.infra.logging_utils import LOGGER


SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS cases(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        created_at TEXT NOT NULL,
        investigator TEXT,
        notes TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS evidence_items(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER NOT NULL,
        path TEXT NOT NULL,
        logical_name TEXT NOT NULL,
        size INTEGER,
        sha256 TEXT,
        blake3 TEXT,
        acquired_at TEXT NOT NULL,
        source TEXT,
        notes TEXT,
        FOREIGN KEY(case_id) REFERENCES cases(id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS extraction_runs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER NOT NULL,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        tool_version TEXT,
        config_json TEXT,
        FOREIGN KEY(case_id) REFERENCES cases(id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS metadata_records(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        evidence_id INTEGER NOT NULL,
        extractor TEXT NOT NULL,
        key TEXT NOT NULL,
        value_json TEXT NOT NULL,
        raw_value TEXT,
        confidence REAL,
        evidence_json TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(evidence_id) REFERENCES evidence_items(id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS artifacts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        evidence_id INTEGER NOT NULL,
        type TEXT,
        description TEXT,
        offset_start INTEGER,
        offset_end INTEGER,
        bytes_sha256 TEXT,
        extracted_path TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(evidence_id) REFERENCES evidence_items(id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS anomalies(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER NOT NULL,
        evidence_id INTEGER,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        description TEXT NOT NULL,
        evidence_json TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(case_id) REFERENCES cases(id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS timeline_events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER NOT NULL,
        evidence_id INTEGER,
        event_time_utc TEXT NOT NULL,
        event_type TEXT NOT NULL,
        source TEXT,
        detail_json TEXT,
        confidence REAL,
        FOREIGN KEY(case_id) REFERENCES cases(id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER NOT NULL,
        ts TEXT NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        detail_json TEXT,
        prev_hash TEXT,
        entry_hash TEXT NOT NULL,
        FOREIGN KEY(case_id) REFERENCES cases(id)
    );
    """,
]


@dataclass
class AuditEntry:
    action: str
    actor: str
    details: Dict[str, Any]
    ts: datetime
    prev_hash: Optional[str]
    entry_hash: str


def connect_db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    for stmt in SCHEMA:
        cur.executescript(stmt)
    conn.commit()


def insert_case(conn: sqlite3.Connection, name: str, investigator: str, notes: str) -> int:
    ts = datetime.utcnow().isoformat() + "Z"
    cur = conn.execute(
        "INSERT INTO cases(name, created_at, investigator, notes) VALUES(?,?,?,?)",
        (name, ts, investigator, notes),
    )
    conn.commit()
    case_id = cur.lastrowid
    append_audit_log(conn, case_id, actor=investigator or "system", action="create_case", details={"name": name})
    return int(case_id)


def add_evidence_item(
    conn: sqlite3.Connection,
    case_id: int,
    path: str,
    logical_name: str,
    size: int,
    sha256: str,
    blake3_hash: str,
    source: str,
    notes: str,
) -> int:
    ts = datetime.utcnow().isoformat() + "Z"
    cur = conn.execute(
        """
        INSERT INTO evidence_items(case_id, path, logical_name, size, sha256, blake3, acquired_at, source, notes)
        VALUES(?,?,?,?,?,?,?,?,?)
        """,
        (case_id, path, logical_name, size, sha256, blake3_hash, ts, source, notes),
    )
    conn.commit()
    evidence_id = int(cur.lastrowid)
    append_audit_log(
        conn,
        case_id,
        actor="system",
        action="add_evidence",
        details={"evidence_id": evidence_id, "logical_name": logical_name},
    )
    return evidence_id


def start_extraction_run(conn: sqlite3.Connection, case_id: int, tool_version: str, config: Dict[str, Any]) -> int:
    started = datetime.utcnow().isoformat() + "Z"
    cur = conn.execute(
        "INSERT INTO extraction_runs(case_id, started_at, tool_version, config_json) VALUES(?,?,?,?)",
        (case_id, started, tool_version, json.dumps(config)),
    )
    conn.commit()
    return int(cur.lastrowid)


def finish_extraction_run(conn: sqlite3.Connection, run_id: int) -> None:
    finished = datetime.utcnow().isoformat() + "Z"
    conn.execute(
        "UPDATE extraction_runs SET finished_at=? WHERE id=?",
        (finished, run_id),
    )
    conn.commit()


def add_metadata_record(
    conn: sqlite3.Connection,
    evidence_id: int,
    extractor: str,
    key: str,
    value: Dict[str, Any],
    raw_value: str,
    confidence: float,
    evidence_json: Dict[str, Any],
) -> None:
    ts = datetime.utcnow().isoformat() + "Z"
    conn.execute(
        """
        INSERT INTO metadata_records(evidence_id, extractor, key, value_json, raw_value, confidence, evidence_json, created_at)
        VALUES(?,?,?,?,?,?,?,?)
        """,
        (evidence_id, extractor, key, json.dumps(value), raw_value, confidence, json.dumps(evidence_json), ts),
    )
    conn.commit()


def add_anomaly(
    conn: sqlite3.Connection,
    case_id: int,
    category: str,
    severity: str,
    description: str,
    evidence_json: Dict[str, Any],
    evidence_id: Optional[int] = None,
) -> None:
    ts = datetime.utcnow().isoformat() + "Z"
    conn.execute(
        """
        INSERT INTO anomalies(case_id, evidence_id, category, severity, description, evidence_json, created_at)
        VALUES(?,?,?,?,?,?,?)
        """,
        (case_id, evidence_id, category, severity, description, json.dumps(evidence_json), ts),
    )
    conn.commit()


def add_timeline_event(
    conn: sqlite3.Connection,
    case_id: int,
    evidence_id: Optional[int],
    event_time_utc: str,
    event_type: str,
    source: str,
    detail: Dict[str, Any],
    confidence: float,
) -> None:
    conn.execute(
        """
        INSERT INTO timeline_events(case_id, evidence_id, event_time_utc, event_type, source, detail_json, confidence)
        VALUES(?,?,?,?,?,?,?)
        """,
        (case_id, evidence_id, event_time_utc, event_type, source, json.dumps(detail), confidence),
    )
    conn.commit()


def append_audit_log(
    conn: sqlite3.Connection,
    case_id: int,
    actor: str,
    action: str,
    details: Dict[str, Any],
) -> AuditEntry:
    ts = datetime.utcnow().isoformat() + "Z"
    detail_json = json.dumps(details, sort_keys=True)
    prev_hash = get_last_audit_hash(conn, case_id)
    base = f"{ts}|{actor}|{action}|{detail_json}|{prev_hash or ''}"
    entry_hash = hashlib_sha256(base)
    conn.execute(
        """
        INSERT INTO audit_log(case_id, ts, actor, action, detail_json, prev_hash, entry_hash)
        VALUES(?,?,?,?,?,?,?)
        """,
        (case_id, ts, actor, action, detail_json, prev_hash, entry_hash),
    )
    conn.commit()
    return AuditEntry(action=action, actor=actor, details=details, ts=datetime.fromisoformat(ts.rstrip("Z")), prev_hash=prev_hash, entry_hash=entry_hash)


def get_last_audit_hash(conn: sqlite3.Connection, case_id: int) -> Optional[str]:
    row = conn.execute(
        "SELECT entry_hash FROM audit_log WHERE case_id=? ORDER BY id DESC LIMIT 1",
        (case_id,),
    ).fetchone()
    return row[0] if row else None


def hashlib_sha256(data: str) -> str:
    import hashlib

    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def fetch_metadata_records(conn: sqlite3.Connection, evidence_id: int) -> List[sqlite3.Row]:
    rows = conn.execute(
        "SELECT * FROM metadata_records WHERE evidence_id=? ORDER BY created_at",
        (evidence_id,),
    ).fetchall()
    return list(rows)


def fetch_evidence_items(conn: sqlite3.Connection, case_id: int) -> List[sqlite3.Row]:
    rows = conn.execute(
        "SELECT * FROM evidence_items WHERE case_id=? ORDER BY id",
        (case_id,),
    ).fetchall()
    return list(rows)


def fetch_anomalies(conn: sqlite3.Connection, case_id: int) -> List[sqlite3.Row]:
    rows = conn.execute(
        "SELECT * FROM anomalies WHERE case_id=? ORDER BY id",
        (case_id,),
    ).fetchall()
    return list(rows)


def fetch_timeline(conn: sqlite3.Connection, case_id: int) -> List[sqlite3.Row]:
    rows = conn.execute(
        "SELECT * FROM timeline_events WHERE case_id=? ORDER BY event_time_utc",
        (case_id,),
    ).fetchall()
    return list(rows)


def fetch_audit_log(conn: sqlite3.Connection, case_id: int) -> List[sqlite3.Row]:
    rows = conn.execute(
        "SELECT * FROM audit_log WHERE case_id=? ORDER BY id",
        (case_id,),
    ).fetchall()
    return list(rows)


def get_case(conn: sqlite3.Connection, case_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()


def iter_rows(rows: Iterable[sqlite3.Row]) -> List[Dict[str, Any]]:
    return [dict(row) for row in rows]


class CaseDatabase:
    def __init__(self, path: Path, case_id: Optional[int] = None) -> None:
        self.path = path
        self.conn = connect_db(self.path)
        init_schema(self.conn)
        self.case_id = case_id or self._discover_case_id()
        LOGGER.info(
            "Case database initialized",
            extra={"extra_data": {"path": str(self.path), "case_id": self.case_id}},
        )

    def _discover_case_id(self) -> Optional[int]:
        row = self.conn.execute("SELECT id FROM cases LIMIT 1").fetchone()
        return int(row[0]) if row else None

    def close(self) -> None:
        self.conn.close()
