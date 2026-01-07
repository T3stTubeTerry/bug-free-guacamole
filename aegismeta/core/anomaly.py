from __future__ import annotations

import json
import statistics
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from aegismeta.infra import db
from aegismeta.infra.filesystem import detect_magic_extension

try:
    from sklearn.ensemble import IsolationForest  # type: ignore
    import numpy as np  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    IsolationForest = None
    np = None


class TimestampInconsistencyRule:
    name = "timestamp_inconsistency"

    def apply(self, conn, evidence_items: Iterable[db.sqlite3.Row]) -> None:  # type: ignore[attr-defined]
        for item in evidence_items:
            created = item["acquired_at"]
            if created:
                try:
                    dt = datetime.fromisoformat(created.rstrip("Z"))
                    if dt > datetime.utcnow():
                        db.add_anomaly(
                            conn,
                            case_id=item["case_id"],
                            evidence_id=item["id"],
                            category=self.name,
                            severity="medium",
                            description="Evidence acquisition time is in the future",
                            evidence_json={"acquired_at": created},
                        )
                except ValueError:
                    db.add_anomaly(
                        conn,
                        case_id=item["case_id"],
                        evidence_id=item["id"],
                        category=self.name,
                        severity="low",
                        description="Invalid acquisition timestamp format",
                        evidence_json={"acquired_at": created},
                    )


class ExtensionMagicMismatchRule:
    name = "extension_magic_mismatch"

    def apply(self, conn, evidence_items: Iterable[db.sqlite3.Row]) -> None:  # type: ignore[attr-defined]
        for item in evidence_items:
            path = Path(item["path"])
            magic = detect_magic_extension(str(path))
            ext = path.suffix.lower().lstrip(".")
            if magic and magic != ext:
                db.add_anomaly(
                    conn,
                    case_id=item["case_id"],
                    evidence_id=item["id"],
                    category=self.name,
                    severity="high",
                    description=f"Extension {ext} mismatches magic {magic}",
                    evidence_json={"magic": magic, "extension": ext},
                )


class ZScoreOutlierRule:
    name = "zscore_outlier"

    def __init__(self, field: str, threshold: float = 2.5) -> None:
        self.field = field
        self.threshold = threshold

    def apply(self, conn, evidence_items: Iterable[db.sqlite3.Row]) -> None:  # type: ignore[attr-defined]
        items = list(evidence_items)
        values: List[float] = []
        evidences: List[int] = []
        for item in items:
            meta_rows = conn.execute(
                "SELECT value_json FROM metadata_records WHERE evidence_id=? AND key=?",
                (item["id"], self.field),
            ).fetchall()
            for row in meta_rows:
                try:
                    payload_raw = row[0]
                    payload = json.loads(payload_raw) if isinstance(payload_raw, str) else payload_raw
                    value = float(payload.get("value", 0.0))
                    values.append(value)
                    evidences.append(item["id"])
                except Exception:
                    continue
        if len(values) < 3:
            return
        mean = statistics.mean(values)
        stdev = statistics.stdev(values)
        for val, evidence_id in zip(values, evidences):
            if stdev and abs(val - mean) / stdev > self.threshold:
                db.add_anomaly(
                    conn,
                    case_id=items[0]["case_id"] if items else 1,
                    evidence_id=evidence_id,
                    category=self.name,
                    severity="medium",
                    description=f"Value {val} for {self.field} is an outlier",
                    evidence_json={"value": val, "mean": mean, "stdev": stdev},
                )


class IsolationForestRule:
    name = "isolation_forest"

    def __init__(self, field: str) -> None:
        self.field = field

    def apply(self, conn, evidence_items: Iterable[db.sqlite3.Row]) -> None:  # type: ignore[attr-defined]
        if IsolationForest is None or np is None:
            # gracefully fallback using z-score
            fallback = ZScoreOutlierRule(self.field)
            fallback.apply(conn, evidence_items)
            return
        items = list(evidence_items)
        values: List[float] = []
        mapping: List[int] = []
        for item in items:
            rows = conn.execute(
                "SELECT value_json FROM metadata_records WHERE evidence_id=? AND key=?",
                (item["id"], self.field),
            ).fetchall()
            for row in rows:
                payload_raw = row[0]
                payload = json.loads(payload_raw) if isinstance(payload_raw, str) else payload_raw
                try:
                    val = float(payload.get("value", 0.0))
                except Exception:
                    continue
                values.append(val)
                mapping.append(item["id"])
        if len(values) < 5:
            return
        model = IsolationForest(contamination=0.15, random_state=42)
        preds = model.fit_predict(np.array(values).reshape(-1, 1))
        for score, evidence_id in zip(preds, mapping):
            if score == -1:
                db.add_anomaly(
                    conn,
                    case_id=items[0]["case_id"] if items else 1,
                    evidence_id=evidence_id,
                    category=self.name,
                    severity="medium",
                    description=f"IsolationForest flagged {self.field}",
                    evidence_json={"value": values[mapping.index(evidence_id)]},
                )
