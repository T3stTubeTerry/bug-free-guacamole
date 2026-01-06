from pathlib import Path

from aegismeta.infra import db


def test_audit_log_chain(tmp_path: Path) -> None:
    db_path = tmp_path / "case.db"
    case_db = db.CaseDatabase(db_path)
    case_id = db.insert_case(case_db.conn, name="Test", investigator="unit", notes="")
    first = db.append_audit_log(case_db.conn, case_id, actor="tester", action="step1", details={})
    second = db.append_audit_log(case_db.conn, case_id, actor="tester", action="step2", details={})
    assert second.prev_hash == first.entry_hash
    rows = db.fetch_audit_log(case_db.conn, case_id)
    assert len(rows) >= 3  # includes create_case
