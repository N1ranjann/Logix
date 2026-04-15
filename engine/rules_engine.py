"""
Rules Engine
============
Central dispatcher that evaluates every log event against all registered
detection rules and collects the resulting alerts.
"""

import logging
import threading
from typing import Optional

from engine.rules.base_rule import Alert, BaseRule

logger = logging.getLogger("logix.rules_engine")


class RulesEngine:
    """Registry and dispatcher for detection rules."""

    def __init__(self) -> None:
        self._rules: list[BaseRule] = []
        self._lock = threading.Lock()
        self._total_evaluated: int = 0
        self._total_alerts: int = 0

    def register_rule(self, rule: BaseRule) -> None:
        """Add a rule to the active rule-set."""
        with self._lock:
            self._rules.append(rule)
        logger.info("Registered rule: %s", rule.name)

    def evaluate(self, log_event: dict) -> list[Alert]:
        """Run *all* registered rules against a single log event."""
        alerts: list[Alert] = []
        with self._lock:
            self._total_evaluated += 1

        for rule in self._rules:
            try:
                alert = rule.evaluate(log_event)
                if alert is not None:
                    alerts.append(alert)
                    with self._lock:
                        self._total_alerts += 1
                    logger.warning(
                        "[%s] %s: %s",
                        alert.severity.upper(),
                        rule.name,
                        alert.description,
                    )
            except Exception as exc:
                logger.error("Rule '%s' raised: %s", rule.name, exc)

        return alerts

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "rules_registered": len(self._rules),
                "total_events_evaluated": self._total_evaluated,
                "total_alerts_generated": self._total_alerts,
            }
