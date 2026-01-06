from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from aegismeta.infra import db


def ingest_file_events(conn, case_id: int, evidence_id: int, path: Path) -> None:
    stat = path.stat()
    events = [
        (stat.st_ctime, "created"),
        (stat.st_mtime, "modified"),
    ]
    for ts, label in events:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        db.add_timeline_event(
            conn,
            case_id=case_id,
            evidence_id=evidence_id,
            event_time_utc=dt.isoformat().replace("+00:00", "Z"),
            event_type=label,
            source="filesystem",
            detail={"path": str(path)},
            confidence=0.6,
        )


def ingest_metadata_event(
    conn, case_id: int, evidence_id: Optional[int], event_time: str, event_type: str, source: str, detail
) -> None:
    db.add_timeline_event(
        conn,
        case_id=case_id,
        evidence_id=evidence_id,
        event_time_utc=event_time,
        event_type=event_type,
        source=source,
        detail=detail,
        confidence=0.5,
    )
