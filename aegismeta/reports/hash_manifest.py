from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from aegismeta.infra import db
from aegismeta.infra.logging_utils import LOGGER


def generate_hash_manifest(case_db: db.CaseDatabase, output_path: Path) -> Path:
    conn = case_db.conn
    case_id = case_db.case_id or 1
    evidence_rows = db.iter_rows(db.fetch_evidence_items(conn, case_id))
    payload: Dict[str, Any] = {
        "case_id": case_id,
        "evidence": [
            {
                "id": row["id"],
                "logical_name": row["logical_name"],
                "path": row["path"],
                "size": row["size"],
                "sha256": row["sha256"],
                "blake3": row["blake3"],
                "acquired_at": row["acquired_at"],
                "source": row["source"],
                "notes": row["notes"],
            }
            for row in evidence_rows
        ],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    LOGGER.info("Hash manifest generated", extra={"extra_data": {"output": str(output_path)}})
    return output_path
