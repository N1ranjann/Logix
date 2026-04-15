"""
Correlation Engine
==================
Stateful correlation rules that detect patterns across multiple events
within time windows — the core of what makes a SIEM more than a log parser.
"""

import logging
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Optional

from config import CORRELATION_WINDOW, Severity
from engine.rules.base_rule import Alert

logger = logging.getLogger("logix.correlation")


class CorrelationRule:
    """A correlation rule definition."""

    def __init__(
        self,
        name: str,
        description: str,
        sequence: list[dict],
        window_seconds: int,
        alert_type: str,
        severity: str,
        mitre_tactic: str = "",
        mitre_technique: str = "",
        group_by: str = "source_ip",
    ):
        self.name = name
        self.description = description
        self.sequence = sequence  # list of {event_type, field_match}
        self.window_seconds = window_seconds
        self.alert_type = alert_type
        self.severity = severity
        self.mitre_tactic = mitre_tactic
        self.mitre_technique = mitre_technique
        self.group_by = group_by


class CorrelationEngine:
    """
    Tracks event sequences per entity across time windows.
    Fires alerts when a full sequence is matched within the window.
    """

    def __init__(self, window: int = CORRELATION_WINDOW) -> None:
        self._rules: list[CorrelationRule] = []
        self._state: dict[str, dict[str, deque]] = defaultdict(
            lambda: defaultdict(lambda: deque(maxlen=500))
        )
        self._lock = threading.Lock()
        self._default_window = window
        self._alert_count = 0

        # Register built-in correlation rules
        self._register_defaults()

    def register_rule(self, rule: CorrelationRule) -> None:
        self._rules.append(rule)
        logger.info("Correlation rule registered: %s", rule.name)

    def evaluate(self, log_event: dict) -> list[Alert]:
        """Check if this event completes any correlation sequence."""
        alerts = []
        for rule in self._rules:
            alert = self._check_rule(rule, log_event)
            if alert:
                alerts.append(alert)
        return alerts

    def get_stats(self) -> dict:
        return {
            "correlation_rules": len(self._rules),
            "correlation_alerts": self._alert_count,
        }

    # ── Internal ─────────────────────────────────────────────────────────

    def _check_rule(self, rule: CorrelationRule, event: dict) -> Optional[Alert]:
        """Check if this event matches any step in the correlation sequence."""
        entity = event.get(rule.group_by, "unknown")
        if entity == "unknown" or entity is None:
            return None

        event_type = event.get("event_type", "")
        ts_raw = event.get("timestamp", datetime.utcnow().isoformat())

        try:
            event_time = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            event_time = datetime.utcnow()

        # Check if event matches any step in the sequence
        matched_step = None
        for i, step in enumerate(rule.sequence):
            if step.get("event_type") == event_type:
                # Check additional field matches
                field_match = step.get("field_match", {})
                if all(event.get(k) == v for k, v in field_match.items()):
                    matched_step = i
                    break

        if matched_step is None:
            return None

        key = f"{rule.name}:{entity}"
        with self._lock:
            self._state[key][matched_step].append(event_time)

            # Clean old entries
            window = timedelta(seconds=rule.window_seconds)
            cutoff = event_time - window
            for step_idx in self._state[key]:
                q = self._state[key][step_idx]
                while q and q[0] < cutoff:
                    q.popleft()

            # Check if all steps in the sequence have been seen
            all_matched = all(
                len(self._state[key].get(i, deque())) > 0
                for i in range(len(rule.sequence))
            )

            if not all_matched:
                return None

            # Full sequence matched — fire alert and clear state
            step_counts = {
                i: len(self._state[key].get(i, deque()))
                for i in range(len(rule.sequence))
            }
            self._state[key].clear()
            self._alert_count += 1

        return Alert(
            timestamp=ts_raw,
            severity=rule.severity,
            severity_score=Severity.SCORE.get(rule.severity, 0),
            alert_type=rule.alert_type,
            rule_name=f"CORR:{rule.name}",
            description=(
                f"{rule.description} Entity: {entity}. "
                f"Steps matched: {step_counts}"
            ),
            source_ip=event.get("source_ip"),
            username=event.get("username"),
            mitre_tactic=rule.mitre_tactic,
            mitre_technique=rule.mitre_technique,
            metadata={
                "correlation_rule": rule.name,
                "entity": entity,
                "window_seconds": rule.window_seconds,
            },
        )

    def _register_defaults(self) -> None:
        """Register built-in correlation rules."""

        # Compromised Account: multiple failures then success from same IP
        self.register_rule(CorrelationRule(
            name="CompromisedAccount",
            description="Multiple login failures followed by successful login",
            sequence=[
                {"event_type": "authentication_failure"},
                {"event_type": "authentication_success"},
            ],
            window_seconds=600,
            alert_type="Compromised Account",
            severity=Severity.CRITICAL,
            mitre_tactic="Credential Access",
            mitre_technique="T1110",
            group_by="source_ip",
        ))

        # Lateral Movement: auth success then suspicious process on same host
        self.register_rule(CorrelationRule(
            name="LateralMovement",
            description="Successful auth followed by suspicious process execution",
            sequence=[
                {"event_type": "authentication_success"},
                {"event_type": "process_start"},
            ],
            window_seconds=300,
            alert_type="Lateral Movement",
            severity=Severity.HIGH,
            mitre_tactic="Lateral Movement",
            mitre_technique="T1021",
            group_by="source_ip",
        ))

        # Persistence: scheduled task or cron manipulation
        self.register_rule(CorrelationRule(
            name="PersistenceAttempt",
            description="Process start followed by scheduled task creation",
            sequence=[
                {"event_type": "process_start"},
                {"event_type": "scheduled_task"},
            ],
            window_seconds=900,
            alert_type="Persistence Attempt",
            severity=Severity.HIGH,
            mitre_tactic="Persistence",
            mitre_technique="T1053",
            group_by="username",
        ))
