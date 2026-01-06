from pathlib import Path

from aegismeta.core.anomaly import ExtensionMagicMismatchRule
from aegismeta.infra import db


def test_extension_magic_mismatch(tmp_path: Path) -> None:
    db_path = tmp_path / "case.db"
    case_db = db.CaseDatabase(db_path)
    case_id = db.insert_case(case_db.conn, "Case", "tester", "")
    evidence_path = tmp_path / "sample.fake"
    evidence_path.write_bytes(b"%PDF-1.4 test")
    evidence_id = db.add_evidence_item(
        case_db.conn,
        case_id=case_id,
        path=str(evidence_path),
        logical_name="sample",
        size=evidence_path.stat().st_size,
        sha256="",
        blake3_hash="",
        source="unit",
        notes="",
    )
    rule = ExtensionMagicMismatchRule()
    rule.apply(case_db.conn, db.fetch_evidence_items(case_db.conn, case_id))
    anomalies = db.fetch_anomalies(case_db.conn, case_id)
    assert any(a["category"] == rule.name for a in anomalies)
