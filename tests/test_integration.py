from pathlib import Path

import pytest

pytest.importorskip("PyPDF2")
from PyPDF2 import PdfWriter

from aegismeta.core.anomaly import ExtensionMagicMismatchRule, IsolationForestRule, TimestampInconsistencyRule, ZScoreOutlierRule
from aegismeta.core.case_service import CaseService
from aegismeta.core.extraction_service import AnomalyService, ExtractionService
from aegismeta.core.timeline import ingest_file_events
from aegismeta.infra import db
from aegismeta.plugins.base import PluginRegistry
from aegismeta.plugins.generic_signature_checker import GenericSignatureChecker
from aegismeta.plugins.image_exif_extractor import ImageExifExtractor
from aegismeta.plugins.pdf_metadata_extractor import PdfMetadataExtractor
from aegismeta.reports.html_report import generate_html_report


def test_full_flow(tmp_path: Path) -> None:
    service = CaseService(tmp_path / "cases")
    bundle = service.create_case("Case1", "investigator", "notes")
    evidence_path = tmp_path / "cases" / "sample.pdf"
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    with evidence_path.open("wb") as f:
        writer.write(f)
    evidence_id = service.add_evidence(evidence_path, logical_name="sample.pdf")

    registry = PluginRegistry()
    registry.register(ImageExifExtractor())
    registry.register(PdfMetadataExtractor())
    registry.register(GenericSignatureChecker())

    case_db = service.get_db()
    extraction = ExtractionService(registry)
    derived = extraction.run(case_db, evidence_id, evidence_path)
    ingest_file_events(case_db.conn, case_db.case_id or 1, evidence_id, evidence_path)

    anomaly_service = AnomalyService(
        [
            TimestampInconsistencyRule(),
            ExtensionMagicMismatchRule(),
            ZScoreOutlierRule("magic_extension"),
            IsolationForestRule("entropy"),
        ]
    )
    anomaly_service.evaluate(case_db, case_db.case_id or 1)

    report_path = tmp_path / "report.html"
    generate_html_report(case_db, report_path)

    assert derived is not None
    assert report_path.exists()
    anomalies = db.fetch_anomalies(case_db.conn, case_db.case_id or 1)
    assert anomalies is not None
