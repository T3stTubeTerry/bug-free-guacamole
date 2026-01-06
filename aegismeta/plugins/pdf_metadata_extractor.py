from __future__ import annotations

from pathlib import Path
from typing import List

from aegismeta.core.models import DerivedField, ExtractionResult


class PdfMetadataExtractor:
    name = "pdf_metadata_extractor"

    def supports(self, path: Path) -> bool:
        return path.suffix.lower() == ".pdf"

    def extract(self, path: Path) -> ExtractionResult:
        metadata: List[DerivedField] = []
        try:
            from PyPDF2 import PdfReader  # type: ignore
            reader = PdfReader(str(path))
            info = reader.metadata or {}
            for key, value in info.items():
                metadata.append(
                    DerivedField(
                        key=str(key),
                        value=str(value),
                        confidence=0.7,
                        evidence={"source": "PDF", "path": str(path)},
                        method="PyPDF2",
                    )
                )
        except Exception:
            # best-effort extraction
            metadata.append(
                DerivedField(
                    key="pdf_parse_error",
                    value="unreadable PDF",
                    confidence=0.2,
                    evidence={"path": str(path)},
                    method="PyPDF2",
                )
            )
        return ExtractionResult(metadata=metadata)
