from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

from aegismeta.core.models import ExtractionResult


class Extractor(ABC):
    name: str

    @abstractmethod
    def supports(self, path: Path) -> bool:
        raise NotImplementedError

    @abstractmethod
    def extract(self, path: Path) -> ExtractionResult:
        raise NotImplementedError


class PluginRegistry:
    def __init__(self) -> None:
        self.plugins: List[Extractor] = []

    def register(self, plugin: Extractor) -> None:
        self.plugins.append(plugin)

    def supported_for(self, path: Path) -> List[Extractor]:
        return [p for p in self.plugins if p.supports(path)]
