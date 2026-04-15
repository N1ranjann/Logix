"""
Incident Manager
================
Groups related alerts into Incidents (like QRadar Offenses / Sentinel Incidents).
Handles auto-merge, status workflow, and entity-based grouping.

Status workflow:  new → in_progress → resolved → closed
"""

import logging
import threading
from datetime import datetime
from typing import Optional

from config import INCIDENT_AUTO_MERGE_WINDOW, Severity

logger = logging.getLogger("logix.incidents")


class IncidentManager:
    """Manages the lifecycle of security incidents."""

    def __init__(self, db) -> None:
        self._db = db
        self._lock = threading.Lock()

    def process_alert(self, alert_dict: dict, alert_id: int) -> Optional[int]:
        """
        Process a new alert — either attach it to an existing open incident
        or create a new one. Returns the incident ID.
        """
        entity_type, entity_value = self._extract_entity(alert_dict)
        if not entity_value:
            return None

        with self._lock:
            # Check for an existing open incident for this entity
            existing = self._db.find_open_incident(entity_type, entity_value)

            if existing:
                incident_id = existing["id"]
                self._merge_into_incident(incident_id, alert_dict, alert_id)
                logger.info(
                    "Alert %d merged into incident %d (%s)",
                    alert_id, incident_id, existing["title"],
                )
                return incident_id

            # Create a new incident
            incident_id = self._create_incident(
                alert_dict, alert_id, entity_type, entity_value
            )
            logger.info(
                "New incident %d created for %s=%s",
                incident_id, entity_type, entity_value,
            )
            return incident_id

    def update_status(
        self, incident_id: int, status: str, notes: str = ""
    ) -> bool:
        """Update an incident's status."""
        valid_statuses = {"new", "in_progress", "resolved", "closed"}
        if status not in valid_statuses:
            return False

        updates = {"status": status}
        if notes:
            existing = self._db.get_incident(incident_id)
            if existing:
                prev_notes = existing.get("notes", "") or ""
                ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
                updates["notes"] = (
                    f"{prev_notes}\n[{ts}] Status → {status}: {notes}".strip()
                )

        return self._db.update_incident(incident_id, updates)

    def get_summary(self) -> dict:
        """Get a summary of incident counts by status."""
        return self._db.get_incident_counts()

    # ── Internal ─────────────────────────────────────────────────────────

    def _create_incident(
        self, alert: dict, alert_id: int,
        entity_type: str, entity_value: str,
    ) -> int:
        """Create a new incident from an alert."""
        severity = alert.get("severity", "medium")
        now = alert.get("timestamp", datetime.utcnow().isoformat())

        mitre = ""
        if alert.get("mitre_technique"):
            mitre = f" [{alert['mitre_technique']}]"

        incident = {
            "title": f"{alert.get('alert_type', 'Alert')}: {entity_value}{mitre}",
            "severity": severity,
            "severity_score": alert.get("severity_score", Severity.SCORE.get(severity, 0)),
            "status": "new",
            "entity_type": entity_type,
            "entity_value": entity_value,
            "alert_count": 1,
            "first_seen": now,
            "last_seen": now,
            "notes": f"Auto-created from {alert.get('rule_name', 'unknown')} alert.",
        }
        incident_id = self._db.insert_incident(incident)

        # Link the alert
        self._db.link_alert_to_incident(alert_id, incident_id)

        return incident_id

    def _merge_into_incident(
        self, incident_id: int, alert: dict, alert_id: int
    ) -> None:
        """Merge a new alert into an existing incident."""
        existing = self._db.get_incident(incident_id)
        if not existing:
            return

        new_count = (existing.get("alert_count") or 0) + 1
        now = alert.get("timestamp", datetime.utcnow().isoformat())

        # Escalate severity if new alert is worse
        alert_sev = alert.get("severity", "medium")
        alert_score = alert.get("severity_score", Severity.SCORE.get(alert_sev, 0))
        current_score = existing.get("severity_score", 0)

        updates = {
            "alert_count": new_count,
            "last_seen": now,
        }

        if alert_score > current_score:
            updates["severity"] = alert_sev
            updates["severity_score"] = alert_score

        self._db.update_incident(incident_id, updates)
        self._db.link_alert_to_incident(alert_id, incident_id)

    @staticmethod
    def _extract_entity(alert: dict) -> tuple[str, Optional[str]]:
        """Determine the primary entity (IP or user) from an alert."""
        if alert.get("source_ip") and alert["source_ip"] != "unknown":
            return "ip", alert["source_ip"]
        if alert.get("username") and alert["username"] != "unknown":
            return "user", alert["username"]
        return "unknown", None
