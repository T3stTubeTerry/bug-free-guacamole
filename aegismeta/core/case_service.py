from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

from aegismeta import __version__
from aegismeta.infra import db
from aegismeta.infra.crypto import derive_key, encrypt_file
from aegismeta.infra.filesystem import hash_file
from aegismeta.infra.logging_utils import LOGGER


@dataclass
class CaseBundle:
    case_id: int
    path: Path
    db_path: Path
    artifacts_path: Path
    encrypted: bool


class CaseService:
    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.current: Optional[CaseBundle] = None

    def create_case(self, name: str, investigator: str, notes: str, password: Optional[str] = None) -> CaseBundle:
        case_dir = self.base_dir / name.replace(" ", "_")
        case_dir.mkdir(parents=True, exist_ok=True)
        db_path = case_dir / "case.db"
        conn = db.connect_db(db_path)
        db.init_schema(conn)
        case_id = db.insert_case(conn, name=name, investigator=investigator, notes=notes)
        conn.close()
        bundle = CaseBundle(case_id=case_id, path=case_dir, db_path=db_path, artifacts_path=case_dir / "artifacts", encrypted=False)
        bundle.artifacts_path.mkdir(exist_ok=True)
        if password:
            salt = (case_dir / "salt.bin")
            salt.write_bytes(b"aegismeta-salt")
            key = derive_key(password, salt.read_bytes())
            encrypt_file(str(db_path), str(case_dir / "case.db.enc"), key)
            db_path.unlink()
            bundle.encrypted = True
        self.current = bundle
        LOGGER.info("Created case bundle", extra={"extra_data": {"case": name, "version": __version__}})
        return bundle

    def open_case(self, bundle_path: Path, password: Optional[str] = None) -> CaseBundle:
        db_path = bundle_path / "case.db"
        if not db_path.exists() and (bundle_path / "case.db.enc").exists():
            if not password:
                raise ValueError("Password required for encrypted case")
            salt = (bundle_path / "salt.bin").read_bytes()
            key = derive_key(password, salt)
            decrypt_target = bundle_path / "case.db"
            from aegismeta.infra.crypto import decrypt_file

            decrypt_file(str(bundle_path / "case.db.enc"), str(decrypt_target), key)
            db_path = decrypt_target
        conn = db.connect_db(db_path)
        case_row = conn.execute("SELECT id FROM cases LIMIT 1").fetchone()
        case_id = int(case_row[0]) if case_row else 1
        conn.close()
        bundle = CaseBundle(
            case_id=case_id,
            path=bundle_path,
            db_path=db_path,
            artifacts_path=bundle_path / "artifacts",
            encrypted=(bundle_path / "case.db.enc").exists(),
        )
        bundle.artifacts_path.mkdir(exist_ok=True)
        self.current = bundle
        return bundle

    def add_evidence(self, path: Path, logical_name: str, source: str = "user", notes: str = "") -> int:
        if not self.current:
            raise RuntimeError("No case opened")
        conn = db.connect_db(self.current.db_path)
        stats = path.stat()
        hashes = hash_file(str(path))
        evidence_id = db.add_evidence_item(
            conn,
            case_id=self.current.case_id,
            path=str(path),
            logical_name=logical_name,
            size=stats.st_size,
            sha256=hashes.sha256,
            blake3_hash=hashes.blake3,
            source=source,
            notes=notes,
        )
        conn.close()
        return evidence_id

    def get_db(self) -> db.CaseDatabase:
        if not self.current:
            raise RuntimeError("No case opened")
        return db.CaseDatabase(self.current.db_path, case_id=self.current.case_id)

    def close_case(self) -> None:
        self.current = None

    def delete_case(self, bundle: CaseBundle) -> None:
        shutil.rmtree(bundle.path, ignore_errors=True)
