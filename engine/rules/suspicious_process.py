"""
Suspicious Process Detector
============================
Flags shell/command-interpreter spawns from unauthorized parent processes.
MITRE ATT&CK: T1059 (Command and Scripting Interpreter) under Execution.
"""

import threading
from datetime import datetime
from typing import Optional

from config import HIGH_RISK_PARENTS, PARENT_WHITELIST, SHELL_BLACKLIST, Severity
from engine.rules.base_rule import Alert, BaseRule


class SuspiciousProcessDetector(BaseRule):
    """Detects unauthorized shell spawning from suspicious parent processes."""

    def __init__(self) -> None:
        self._count: int = 0
        self._lock = threading.Lock()

    @property
    def name(self) -> str:
        return "SuspiciousProcessDetector"

    @property
    def description(self) -> str:
        return (
            "Flags shell commands spawned from unauthorized parent processes. "
            "CRITICAL when the parent is a web server."
        )

    @property
    def mitre_tactic(self) -> str:
        return "Execution"

    @property
    def mitre_technique(self) -> str:
        return "T1059"

    def evaluate(self, log_event: dict) -> Optional[Alert]:
        if log_event.get("event_type") != "process_start":
            return None

        proc = (log_event.get("process_name") or "").lower()
        parent = (log_event.get("parent_process") or "").lower()

        if not any(s.lower() in proc for s in SHELL_BLACKLIST):
            return None

        if any(w.lower() in parent for w in PARENT_WHITELIST):
            return None

        is_high_risk = any(r.lower() in parent for r in HIGH_RISK_PARENTS)
        severity = Severity.CRITICAL if is_high_risk else Severity.HIGH

        with self._lock:
            self._count += 1

        return Alert(
            timestamp=log_event.get("timestamp", datetime.utcnow().isoformat()),
            severity=severity,
            severity_score=Severity.SCORE.get(severity, 0),
            alert_type="Suspicious Process",
            rule_name=self.name,
            description=(
                f"'{proc}' spawned by unauthorized parent '{parent}'."
                + (" HIGH RISK: web-server parent!" if is_high_risk else "")
            ),
            source_ip=log_event.get("source_ip"),
            username=log_event.get("username"),
            mitre_tactic=self.mitre_tactic,
            mitre_technique=self.mitre_technique,
            metadata={
                "process_name": proc,
                "parent_process": parent,
                "is_high_risk_parent": is_high_risk,
            },
        )

    def reset_state(self) -> None:
        with self._lock:
            self._count = 0
