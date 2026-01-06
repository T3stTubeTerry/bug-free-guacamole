from __future__ import annotations

from pathlib import Path
from typing import List
import re

from aegismeta.core.models import DerivedField, ExtractionResult
from aegismeta.infra.filesystem import calculate_entropy, detect_magic_extension


class GenericSignatureChecker:
    name = "generic_signature_checker"

    def supports(self, path: Path) -> bool:
        return True

    def extract(self, path: Path) -> ExtractionResult:
        metadata: List[DerivedField] = []
        magic_ext = detect_magic_extension(str(path))
        if magic_ext:
            metadata.append(
                DerivedField(
                    key="magic_extension",
                    value=magic_ext,
                    confidence=0.9,
                    evidence={"source": "magic", "path": str(path)},
                    method="magic-signature",
                )
            )
        entropy = calculate_entropy(path)
        metadata.append(
            DerivedField(
                key="entropy",
                value=round(entropy, 3),
                confidence=0.7,
                evidence={"source": "entropy", "path": str(path)},
                method="shannon-entropy",
            )
        )
        if entropy > 7.5:
            metadata.append(
                DerivedField(
                    key="high_entropy_flag",
                    value=True,
                    confidence=0.6,
                    evidence={"entropy": entropy, "path": str(path)},
                    method="entropy-threshold",
                )
            )
        with open(path, "rb") as f:
            data = f.read()
        strings = re.findall(rb"[\\x20-\\x7E]{6,}", data[:4096])
        if strings:
            metadata.append(
                DerivedField(
                    key="strings_sample",
                    value=strings[:3],
                    confidence=0.5,
                    evidence={"count": len(strings), "path": str(path)},
                    method="ascii-scan",
                )
            )
        return ExtractionResult(metadata=metadata)
