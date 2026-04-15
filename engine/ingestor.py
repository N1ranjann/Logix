"""
Log Ingestor
============
Central ingestion pipeline:
  * HTTP API events
  * Syslog messages (via normalizer)
  * Webhook payloads
  * File batch import

Every event is normalised, persisted, run through the Rules Engine
and Correlation Engine, and resulting alerts are dispatched.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from engine.alert_manager import AlertManager
from engine.correlation import CorrelationEngine
from engine.normalizer import LogNormalizer
from engine.rules_engine import RulesEngine

logger = logging.getLogger("logix.ingestor")


class LogIngestor:
    """Normalises, persists, and evaluates log events."""

    def __init__(
        self,
        rules_engine: RulesEngine,
        alert_manager: AlertManager,
        correlation: Optional[CorrelationEngine] = None,
        incident_manager=None,
        db=None,
    ) -> None:
        self._rules = rules_engine
        self._alerts = alert_manager
        self._correlation = correlation
        self._incidents = incident_manager
        self._db = db
        self._normalizer = LogNormalizer()
        self._count: int = 0

    # ── Public API ───────────────────────────────────────────────────────

    def ingest_event(self, raw: dict, source: str = "api") -> list[dict]:
        """Ingest one event. Returns list of alert dicts (may be empty)."""
        norm = self._normalizer.normalize(raw, source)
        if norm is None:
            return []

        # Persist log
        log_id = None
        if self._db:
            try:
                log_id = self._db.insert_log(norm)
            except Exception as exc:
                logger.error("DB insert failed: %s", exc)

        self._count += 1
        all_alerts = []

        # Run rules engine
        alerts = self._rules.evaluate(norm)
        all_alerts.extend(alerts)

        # Run correlation engine
        if self._correlation:
            try:
                corr_alerts = self._correlation.evaluate(norm)
                all_alerts.extend(corr_alerts)
            except Exception as exc:
                logger.error("Correlation error: %s", exc)

        # Dispatch alerts and create/merge incidents
        result = []
        for a in all_alerts:
            self._alerts.dispatch(a)
            alert_dict = a.to_dict()

            # Persist alert and get its ID
            alert_id = None
            if self._db:
                try:
                    alert_id = self._db.insert_alert(alert_dict)
                except Exception as exc:
                    logger.error("Alert DB insert failed: %s", exc)

            # Process through incident manager
            if self._incidents and alert_id:
                try:
                    incident_id = self._incidents.process_alert(alert_dict, alert_id)
                    if incident_id:
                        alert_dict["incident_id"] = incident_id
                except Exception as exc:
                    logger.error("Incident processing failed: %s", exc)

            result.append(alert_dict)

        return result

    def ingest_syslog(self, raw_line: str, sender_ip: str = "") -> list[dict]:
        """Ingest a raw syslog line."""
        norm = self._normalizer.normalize_syslog(raw_line)
        if norm is None:
            return []
        if sender_ip and not norm.get("source_ip"):
            norm["source_ip"] = sender_ip
        norm["log_source"] = "syslog"
        return self.ingest_event(norm, source="syslog")

    def ingest_webhook(self, payload: dict, source_name: str = "webhook") -> list[dict]:
        """Ingest a webhook payload from external services."""
        payload["log_source"] = source_name
        return self.ingest_event(payload, source=source_name)

    def ingest_from_file(self, filepath: str | Path) -> int:
        """Ingest all events from a JSON array or NDJSON file."""
        filepath = Path(filepath)
        if not filepath.exists():
            logger.error("File not found: %s", filepath)
            return 0

        text = filepath.read_text(encoding="utf-8").strip()
        count = 0

        # Try JSON array first
        try:
            data = json.loads(text)
            if isinstance(data, list):
                for ev in data:
                    self.ingest_event(ev)
                    count += 1
                return count
        except json.JSONDecodeError:
            pass

        # Fall back to NDJSON
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                self.ingest_event(json.loads(line))
                count += 1
            except json.JSONDecodeError:
                pass
        return count

    @property
    def ingested_count(self) -> int:
        return self._count
