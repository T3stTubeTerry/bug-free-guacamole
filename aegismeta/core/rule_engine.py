from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List


@dataclass
class Rule:
    name: str
    pattern: bytes
    description: str


class YaraLiteEngine:
    def __init__(self, rules: List[Rule] | None = None) -> None:
        self.rules = rules or self._default_rules()

    def _default_rules(self) -> List[Rule]:
        return [
            Rule(name="high_entropy_hint", pattern=b"\x00\xFF\x00\xFF", description="Possible packed data marker"),
            Rule(name="pdf_signature", pattern=b"%PDF", description="PDF header present"),
            Rule(name="jpeg_signature", pattern=b"\xFF\xD8\xFF", description="JPEG header present"),
        ]

    def scan(self, path: Path) -> List[Rule]:
        data = path.read_bytes()
        hits: List[Rule] = []
        for rule in self.rules:
            if rule.pattern in data:
                hits.append(rule)
        return hits
