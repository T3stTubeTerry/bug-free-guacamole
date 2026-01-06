from __future__ import annotations

from typing import Dict, Set


class AccessController:
    def __init__(self, role: str = "Investigator") -> None:
        self.role = role
        self.permissions: Dict[str, Set[str]] = {
            "Investigator": {"create_case", "open_case", "add_evidence", "run_extraction", "generate_report"},
            "Analyst": {"open_case", "run_extraction", "generate_report"},
            "Admin": {"create_case", "open_case", "add_evidence", "run_extraction", "generate_report", "settings"},
        }

    def set_role(self, role: str) -> None:
        self.role = role

    def check(self, action: str) -> bool:
        return action in self.permissions.get(self.role, set())
