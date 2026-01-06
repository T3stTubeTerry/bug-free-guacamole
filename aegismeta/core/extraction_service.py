from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from aegismeta import __version__
from aegismeta.core import models
from aegismeta.core.rule_engine import YaraLiteEngine
from aegismeta.infra import db
from aegismeta.infra.logging_utils import LOGGER
from aegismeta.plugins.base import Extractor, PluginRegistry


class ExtractionService:
    def __init__(self, registry: PluginRegistry) -> None:
        self.registry = registry
        self.rule_engine = YaraLiteEngine()

    def run(self, case_db: db.CaseDatabase, evidence_id: int, evidence_path: Path) -> List[models.DerivedField]:
        available = [p for p in self.registry.plugins if p.supports(evidence_path)]
        LOGGER.info("Running extractors", extra={"extra_data": {"count": len(available)}})
        conn = case_db.conn
        case_id = case_db.case_id or 1
        run_id = db.start_extraction_run(conn, case_id, __version__, config={"plugins": [p.name for p in available]})
        derived: List[models.DerivedField] = []
        for plugin in available:
            try:
                results = plugin.extract(evidence_path)
                for field in results.metadata:
                    derived.append(field)
                    db.add_metadata_record(
                        conn,
                        evidence_id,
                        extractor=plugin.name,
                        key=field.key,
                        value={"value": field.value, "method": field.method},
                        raw_value=str(field.value),
                        confidence=field.confidence,
                        evidence_json=field.evidence,
                    )
            except Exception as exc:  # pragma: no cover - defensive
                LOGGER.error("Extractor failed", extra={"extra_data": {"plugin": plugin.name, "error": str(exc)}})
        # Run rule engine
        for hit in self.rule_engine.scan(evidence_path):
            df = models.DerivedField(
                key="rule_match",
                value=hit.name,
                confidence=0.6,
                evidence={"description": hit.description, "path": str(evidence_path)},
                method="yara-lite",
            )
            derived.append(df)
            db.add_metadata_record(
                conn,
                evidence_id,
                extractor="yara-lite",
                key=df.key,
                value={"value": df.value, "method": df.method},
                raw_value=df.value,
                confidence=df.confidence,
                evidence_json=df.evidence,
            )
        db.finish_extraction_run(conn, run_id)
        conn.commit()
        return derived


class AnomalyService:
    def __init__(self, rule_engines: List) -> None:
        self.rule_engines = rule_engines

    def evaluate(self, case_db: db.CaseDatabase, case_id: int) -> None:
        conn = case_db.conn
        evidence_items = db.fetch_evidence_items(conn, case_id)
        for rule in self.rule_engines:
            rule.apply(conn, evidence_items)
