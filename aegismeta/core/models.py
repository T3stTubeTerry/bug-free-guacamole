from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class DerivedField:
    key: str
    value: Any
    confidence: float
    evidence: Dict[str, Any]
    method: str


@dataclass
class Case:
    id: int
    name: str
    created_at: datetime
    investigator: str
    notes: str


@dataclass
class EvidenceItem:
    id: int
    case_id: int
    path: str
    logical_name: str
    size: int
    sha256: str
    blake3: str
    acquired_at: datetime
    source: str
    notes: str


@dataclass
class ExtractionResult:
    metadata: List[DerivedField] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)
