"""
Brute Force Detector
====================
Tracks failed login attempts per (username, source_ip) over a sliding
time window.  Fires HIGH at 5+ failures, CRITICAL at 10+.
MITRE ATT&CK: T1110 (Brute Force) under Credential Access.
"""

import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Optional

from config import (
    BRUTE_FORCE_CRITICAL_THRESHOLD,
    BRUTE_FORCE_MAX_ATTEMPTS,
    BRUTE_FORCE_TIME_WINDOW,
    Severity,
)
from engine.rules.base_rule import Alert, BaseRule


class BruteForceDetector(BaseRule):
    """Detects brute-force login attempts via sliding-window analysis."""

    def __init__(self) -> None:
        self._attempts: dict[tuple[str, str], deque] = defaultdict(
            lambda: deque(maxlen=100)
        )
        self._lock = threading.Lock()

    # ── BaseRule contract ────────────────────────────────────────────────

    @property
    def name(self) -> str:
        return "BruteForceDetector"

    @property
    def description(self) -> str:
        return (
            f"Fires when a user exceeds {BRUTE_FORCE_MAX_ATTEMPTS} failed "
            f"logins within {BRUTE_FORCE_TIME_WINDOW}s from the same IP."
        )

    @property
    def mitre_tactic(self) -> str:
        return "Credential Access"

    @property
    def mitre_technique(self) -> str:
        return "T1110"

    def evaluate(self, log_event: dict) -> Optional[Alert]:
        if log_event.get("event_type") != "authentication_failure":
            return None

        username = log_event.get("username", "unknown")
        source_ip = log_event.get("source_ip", "unknown")
        ts_raw = log_event.get("timestamp", datetime.utcnow().isoformat())

        try:
            event_time = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            event_time = datetime.utcnow()

        key = (username, source_ip)
        with self._lock:
            self._attempts[key].append(event_time)
            cutoff = event_time - timedelta(seconds=BRUTE_FORCE_TIME_WINDOW)
            while self._attempts[key] and self._attempts[key][0] < cutoff:
                self._attempts[key].popleft()
            count = len(self._attempts[key])

        if count < BRUTE_FORCE_MAX_ATTEMPTS:
            return None

        severity = (
            Severity.CRITICAL
            if count >= BRUTE_FORCE_CRITICAL_THRESHOLD
            else Severity.HIGH
        )

        return Alert(
            timestamp=ts_raw,
            severity=severity,
            severity_score=Severity.SCORE.get(severity, 0),
            alert_type="Brute Force Attack",
            rule_name=self.name,
            description=(
                f"{count} failed logins for '{username}' from {source_ip} "
                f"within {BRUTE_FORCE_TIME_WINDOW}s."
            ),
            source_ip=source_ip,
            username=username,
            mitre_tactic=self.mitre_tactic,
            mitre_technique=self.mitre_technique,
            metadata={"attempt_count": count, "process_name": "sshd"},
        )

    def reset_state(self) -> None:
        with self._lock:
            self._attempts.clear()
