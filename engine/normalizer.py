"""
Log Normalizer
==============
Maps raw log events from different sources (syslog, webhooks, API)
into the unified Logix internal schema.
"""

import re
import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger("logix.normalizer")

# Unified schema fields
_SCHEMA_FIELDS = {
    "timestamp", "event_type", "source_ip", "dest_ip", "dest_port",
    "username", "hostname", "process_name", "parent_process",
    "message", "log_source",
}

# ── Syslog RFC 3164 parser ───────────────────────────────────────────────
_SYSLOG_RE = re.compile(
    r"^<(\d{1,3})>"                          # priority
    r"(\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})" # timestamp
    r"\s+(\S+)"                              # hostname
    r"\s+(\S+?)(?:\[(\d+)\])?:"              # process[pid]
    r"\s*(.*)",                               # message
    re.DOTALL,
)

# Facility/severity from syslog priority
_FACILITIES = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
    "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
]
_SEVERITIES = [
    "emergency", "alert", "critical", "error", "warning", "notice", "info", "debug",
]

# Patterns for event-type classification
_AUTH_FAIL_PATTERNS = [
    r"failed password",
    r"authentication failure",
    r"invalid user",
    r"failed login",
    r"access denied",
    r"login failed",
]

_AUTH_OK_PATTERNS = [
    r"accepted password",
    r"session opened",
    r"successful login",
    r"authenticated",
]

_PROCESS_PATTERNS = [
    r"process started",
    r"exec\(",
    r"spawned",
    r"new process",
    r"command=",
]

_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_USER_RE = re.compile(r"(?:user|for)\s+(\w[\w.-]{0,30})", re.IGNORECASE)


class LogNormalizer:
    """Normalizes raw log data from various sources into the Logix schema."""

    def normalize(self, raw: dict, source: str = "api") -> Optional[dict]:
        """Normalize a raw event dict. Returns None if invalid."""
        if not isinstance(raw, dict):
            return None

        # Already has event_type? Light normalization only.
        if "event_type" in raw:
            return self._normalize_structured(raw, source)

        # Has a raw syslog line?
        if "raw" in raw or "message" in raw:
            msg = raw.get("raw") or raw.get("message", "")
            return self._normalize_message(msg, source, raw)

        return None

    def normalize_syslog(self, raw_line: str) -> Optional[dict]:
        """Parse a raw syslog line (RFC 3164) into the Logix schema."""
        match = _SYSLOG_RE.match(raw_line.strip())
        if not match:
            return self._normalize_message(raw_line, "syslog", {})

        priority = int(match.group(1))
        ts_str = match.group(2)
        hostname = match.group(3)
        process = match.group(4)
        pid = match.group(5)
        message = match.group(6).strip()

        facility = _FACILITIES[priority >> 3] if (priority >> 3) < len(_FACILITIES) else "unknown"
        sev_idx = priority & 0x07
        syslog_severity = _SEVERITIES[sev_idx] if sev_idx < len(_SEVERITIES) else "info"

        # Parse timestamp (add current year)
        try:
            now = datetime.utcnow()
            ts = datetime.strptime(f"{now.year} {ts_str}", "%Y %b %d %H:%M:%S")
            timestamp = ts.isoformat() + "Z"
        except ValueError:
            timestamp = datetime.utcnow().isoformat() + "Z"

        event_type = self._classify_message(message, process)
        source_ip = self._extract_ip(message)
        username = self._extract_username(message)

        return {
            "timestamp": timestamp,
            "event_type": event_type,
            "source_ip": source_ip,
            "dest_ip": None,
            "dest_port": None,
            "username": username,
            "hostname": hostname,
            "process_name": process,
            "parent_process": None,
            "message": message,
            "log_source": "syslog",
            "syslog_facility": facility,
            "syslog_severity": syslog_severity,
            "pid": pid,
        }

    def _normalize_structured(self, raw: dict, source: str) -> dict:
        """Normalize a pre-structured event dict."""
        if "timestamp" not in raw:
            raw["timestamp"] = datetime.utcnow().isoformat() + "Z"
        return {
            "timestamp": raw.get("timestamp"),
            "event_type": raw.get("event_type"),
            "source_ip": raw.get("source_ip"),
            "dest_ip": raw.get("dest_ip"),
            "dest_port": raw.get("dest_port"),
            "username": raw.get("username"),
            "hostname": raw.get("hostname"),
            "process_name": raw.get("process_name"),
            "parent_process": raw.get("parent_process"),
            "message": raw.get("message", ""),
            "log_source": source,
        }

    def _normalize_message(self, message: str, source: str, extra: dict) -> Optional[dict]:
        """Normalize a raw text message into the schema by extracting fields."""
        if not message or not message.strip():
            return None

        event_type = self._classify_message(message, extra.get("process_name", ""))

        return {
            "timestamp": extra.get("timestamp", datetime.utcnow().isoformat() + "Z"),
            "event_type": event_type,
            "source_ip": extra.get("source_ip") or self._extract_ip(message),
            "dest_ip": extra.get("dest_ip"),
            "dest_port": extra.get("dest_port"),
            "username": extra.get("username") or self._extract_username(message),
            "hostname": extra.get("hostname"),
            "process_name": extra.get("process_name"),
            "parent_process": extra.get("parent_process"),
            "message": message.strip(),
            "log_source": source,
        }

    @staticmethod
    def _classify_message(message: str, process: str = "") -> str:
        """Classify a log message into an event_type."""
        msg_lower = message.lower()
        proc_lower = process.lower() if process else ""

        for pattern in _AUTH_FAIL_PATTERNS:
            if re.search(pattern, msg_lower):
                return "authentication_failure"

        for pattern in _AUTH_OK_PATTERNS:
            if re.search(pattern, msg_lower):
                return "authentication_success"

        for pattern in _PROCESS_PATTERNS:
            if re.search(pattern, msg_lower):
                return "process_start"

        if any(kw in proc_lower for kw in ("sshd", "login", "pam", "sudo")):
            return "authentication_event"

        if any(kw in proc_lower for kw in ("cron", "at")):
            return "scheduled_task"

        if any(kw in msg_lower for kw in ("firewall", "iptables", "nftables", "ufw")):
            return "firewall_event"

        if any(kw in msg_lower for kw in ("connection", "connect", "listen", "bind")):
            return "network_connection"

        return "system_event"

    @staticmethod
    def _extract_ip(message: str) -> Optional[str]:
        """Extract the first IP address from a message."""
        match = _IP_RE.search(message)
        return match.group(1) if match else None

    @staticmethod
    def _extract_username(message: str) -> Optional[str]:
        """Extract a username from a message."""
        match = _USER_RE.search(message)
        return match.group(1) if match else None
