"""
Alert Manager
=============
Fan-out dispatcher that routes every alert to three outputs:
  1. Console  — coloured severity logging
  2. JSON file — NDJSON append to data/alerts.json
  3. SQLite    — persists to the alerts table
"""

import json
import logging
import threading
from typing import Callable

from config import ALERTS_JSON_PATH, DATA_DIR
from engine.rules.base_rule import Alert

logger = logging.getLogger("logix.alert_manager")

_COLORS = {
    "critical": "\033[91m",
    "high": "\033[93m",
    "medium": "\033[94m",
    "low": "\033[90m",
}
_RESET = "\033[0m"


class AlertManager:
    """Multi-output alert dispatcher."""

    def __init__(self, db=None) -> None:
        self._handlers: list[Callable[[dict], None]] = []
        self._db = db
        self._lock = threading.Lock()
        self._count: int = 0

        DATA_DIR.mkdir(parents=True, exist_ok=True)

        # Default handlers
        self._handlers.append(self._console)
        self._handlers.append(self._file)
        if db:
            self._handlers.append(self._database)

    def dispatch(self, alert: Alert) -> None:
        """Send an alert to every registered handler."""
        d = alert.to_dict()
        with self._lock:
            self._count += 1
        for h in self._handlers:
            try:
                h(d)
            except Exception as exc:
                logger.error("Handler failed: %s", exc)

    # ── Built-in handlers ────────────────────────────────────────────────

    @staticmethod
    def _console(a: dict) -> None:
        sev = a.get("severity", "low")
        c = _COLORS.get(sev, "")
        logger.info(
            "%s[%s]%s %s - %s",
            c, sev.upper(), _RESET,
            a.get("alert_type", "?"),
            a.get("description", ""),
        )

    @staticmethod
    def _file(a: dict) -> None:
        with open(ALERTS_JSON_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(a, default=str) + "\n")

    def _database(self, a: dict) -> None:
        if self._db:
            self._db.insert_alert(a)

    @property
    def alert_count(self) -> int:
        with self._lock:
            return self._count
