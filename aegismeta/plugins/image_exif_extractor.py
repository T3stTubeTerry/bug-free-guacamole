from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from aegismeta.core.models import DerivedField, ExtractionResult
from aegismeta.infra.filesystem import detect_mime_type


class ImageExifExtractor:
    name = "image_exif_extractor"

    def supports(self, path: Path) -> bool:
        mime = detect_mime_type(str(path)) or ""
        return mime.startswith("image/")

    def extract(self, path: Path) -> ExtractionResult:
        metadata: List[DerivedField] = []
        try:
            from PIL import Image, ExifTags  # type: ignore
        except Exception:
            # fallback: no EXIF extraction available
            metadata.append(
                DerivedField(
                    key="exif_unavailable",
                    value="Pillow not installed",
                    confidence=0.2,
                    evidence={"path": str(path)},
                    method="fallback",
                )
            )
            return ExtractionResult(metadata=metadata)
        with Image.open(path) as img:
            raw_exif = img.getexif() or {}
            readable: Dict[str, str] = {}
            for key, value in raw_exif.items():
                label = ExifTags.TAGS.get(key, str(key))
                readable[label] = str(value)
            for key, value in readable.items():
                metadata.append(
                    DerivedField(
                        key=key,
                        value=value,
                        confidence=0.8,
                        evidence={"source": "EXIF", "path": str(path)},
                        method="Pillow-EXIF",
                    )
                )
        return ExtractionResult(metadata=metadata)
