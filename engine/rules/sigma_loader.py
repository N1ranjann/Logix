"""
SIGMA Rule Loader
=================
Loads SIGMA-format YAML detection rules and converts them into
Logix BaseRule instances for the rules engine.

SIGMA is the open standard for sharing security detection rules.
See: https://github.com/SigmaHQ/sigma
"""

import logging
import re
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional

from config import SIGMA_RULES_DIR, Severity
from engine.rules.base_rule import Alert, BaseRule

logger = logging.getLogger("logix.sigma")

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False
    logger.warning("PyYAML not installed — SIGMA rules disabled")


class SigmaRule(BaseRule):
    """A detection rule loaded from a SIGMA YAML definition."""

    def __init__(self, sigma: dict, filepath: str = "") -> None:
        self._sigma = sigma
        self._filepath = filepath
        self._name = sigma.get("title", "UnnamedSigmaRule")
        self._desc = sigma.get("description", "")
        self._level = sigma.get("level", "medium")
        self._count = 0
        self._lock = threading.Lock()

        # MITRE extraction
        tags = sigma.get("tags", [])
        self._mitre_tactic = ""
        self._mitre_technique = ""
        for tag in tags:
            if tag.startswith("attack.t"):
                self._mitre_technique = tag.replace("attack.", "").upper()
            elif tag.startswith("attack."):
                self._mitre_tactic = tag.replace("attack.", "").replace("_", " ").title()

        # Parse detection logic
        self._detection = sigma.get("detection", {})
        self._logsource = sigma.get("logsource", {})

    @property
    def name(self) -> str:
        return f"SIGMA:{self._name}"

    @property
    def description(self) -> str:
        return self._desc

    @property
    def mitre_tactic(self) -> Optional[str]:
        return self._mitre_tactic or None

    @property
    def mitre_technique(self) -> Optional[str]:
        return self._mitre_technique or None

    def evaluate(self, log_event: dict) -> Optional[Alert]:
        # Check logsource match first
        if not self._match_logsource(log_event):
            return None

        # Evaluate detection logic
        if not self._match_detection(log_event):
            return None

        with self._lock:
            self._count += 1

        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "informational": Severity.LOW,
        }
        sev = severity_map.get(self._level, Severity.MEDIUM)

        return Alert(
            timestamp=log_event.get("timestamp", datetime.utcnow().isoformat()),
            severity=sev,
            severity_score=Severity.SCORE.get(sev, 0),
            alert_type=f"SIGMA: {self._name}",
            rule_name=self.name,
            description=self._desc or f"SIGMA rule '{self._name}' matched.",
            source_ip=log_event.get("source_ip"),
            username=log_event.get("username"),
            mitre_tactic=self._mitre_tactic or None,
            mitre_technique=self._mitre_technique or None,
            metadata={
                "sigma_rule": self._name,
                "sigma_level": self._level,
                "process_name": log_event.get("process_name"),
            },
        )

    def reset_state(self) -> None:
        with self._lock:
            self._count = 0

    # ── SIGMA Detection Logic ────────────────────────────────────────────

    def _match_logsource(self, event: dict) -> bool:
        """Check if the event matches the SIGMA logsource definition."""
        category = self._logsource.get("category", "")
        product = self._logsource.get("product", "")

        if category == "authentication":
            return event.get("event_type", "").startswith("authentication")
        if category == "process_creation":
            return event.get("event_type") == "process_start"
        if category == "firewall":
            return event.get("event_type") == "firewall_event"
        if category == "network_connection":
            return event.get("event_type") == "network_connection"

        # If no specific category, allow all events
        return True

    def _match_detection(self, event: dict) -> bool:
        """Evaluate the SIGMA detection block against an event."""
        condition = self._detection.get("condition", "selection")
        selection = self._detection.get("selection", {})
        filter_block = self._detection.get("filter", {})

        selection_match = self._match_block(selection, event)

        if "not" in condition and "filter" in condition:
            filter_match = self._match_block(filter_block, event)
            return selection_match and not filter_match

        return selection_match

    def _match_block(self, block: dict, event: dict) -> bool:
        """Match a single detection block (selection or filter)."""
        if not block:
            return False

        for field_key, expected in block.items():
            # Handle SIGMA field name mapping
            field_name = self._map_field(field_key)
            actual = event.get(field_name, "")
            if actual is None:
                actual = ""

            actual_lower = str(actual).lower()

            if isinstance(expected, list):
                # OR match: any value in the list
                if not any(
                    self._value_match(str(v).lower(), actual_lower)
                    for v in expected
                ):
                    return False
            elif isinstance(expected, str):
                if not self._value_match(expected.lower(), actual_lower):
                    return False
            elif isinstance(expected, (int, float)):
                try:
                    if float(actual) != float(expected):
                        return False
                except (ValueError, TypeError):
                    return False

        return True

    @staticmethod
    def _value_match(pattern: str, actual: str) -> bool:
        """Match a SIGMA value pattern (supports wildcards)."""
        if "*" in pattern:
            regex = re.escape(pattern).replace(r"\*", ".*")
            return bool(re.search(regex, actual))
        return pattern in actual

    @staticmethod
    def _map_field(sigma_field: str) -> str:
        """Map SIGMA field names to Logix schema fields."""
        mapping = {
            "Image": "process_name",
            "ParentImage": "parent_process",
            "CommandLine": "message",
            "User": "username",
            "SourceIp": "source_ip",
            "DestinationIp": "dest_ip",
            "DestinationPort": "dest_port",
            "EventType": "event_type",
            "TargetUserName": "username",
            "IpAddress": "source_ip",
            "ProcessName": "process_name",
            "Hostname": "hostname",
        }
        return mapping.get(sigma_field, sigma_field.lower())


def load_sigma_rules(directory: Path = SIGMA_RULES_DIR) -> list[SigmaRule]:
    """Load all SIGMA YAML rules from a directory."""
    if not _HAS_YAML:
        logger.warning("PyYAML not available — skipping SIGMA rules")
        return []

    if not directory.exists():
        logger.info("SIGMA rules directory not found: %s", directory)
        return []

    rules = []
    for yml_file in sorted(directory.glob("*.yml")):
        try:
            with open(yml_file, "r", encoding="utf-8") as f:
                sigma = yaml.safe_load(f)
            if sigma and isinstance(sigma, dict) and "detection" in sigma:
                rules.append(SigmaRule(sigma, str(yml_file)))
                logger.info("Loaded SIGMA rule: %s", sigma.get("title", yml_file.name))
        except Exception as exc:
            logger.error("Failed to load SIGMA rule %s: %s", yml_file.name, exc)

    logger.info("Loaded %d SIGMA rules from %s", len(rules), directory)
    return rules
