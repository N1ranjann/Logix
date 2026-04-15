"""
Database Layer
==============
Thread-safe SQLite persistence with WAL mode, FTS5 full-text search,
and support for logs, alerts, incidents, and log retention.
"""

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional

from config import DATABASE_PATH, DATA_DIR, LOG_RETENTION_DAYS


class Database:
    """Thread-safe singleton SQLite database manager."""

    _instance: Optional["Database"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "Database":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self._db_path = str(DATABASE_PATH)
        self._local = threading.local()
        self._init_schema()
        self._initialized = True

    # ── Connection Management ────────────────────────────────────────────

    def _get_conn(self) -> sqlite3.Connection:
        """Get a thread-local database connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self._db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return self._local.conn

    def _init_schema(self) -> None:
        """Create tables and indices if they don't exist."""
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source_ip TEXT,
                dest_ip TEXT,
                dest_port INTEGER,
                username TEXT,
                hostname TEXT,
                process_name TEXT,
                parent_process TEXT,
                message TEXT,
                log_source TEXT DEFAULT 'api',
                raw_json TEXT,
                ingested_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                severity_score INTEGER DEFAULT 0,
                alert_type TEXT NOT NULL,
                source_ip TEXT,
                username TEXT,
                description TEXT,
                rule_name TEXT,
                mitre_tactic TEXT,
                mitre_technique TEXT,
                incident_id INTEGER,
                metadata_json TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (incident_id) REFERENCES incidents(id)
            );

            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'medium',
                severity_score INTEGER DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'new',
                assignee TEXT,
                entity_type TEXT,
                entity_value TEXT,
                alert_count INTEGER DEFAULT 0,
                first_seen TEXT,
                last_seen TEXT,
                notes TEXT DEFAULT '',
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS engine_state (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                value_json TEXT,
                updated_at TEXT DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_logs_type ON logs(event_type);
            CREATE INDEX IF NOT EXISTS idx_logs_src ON logs(source_ip);
            CREATE INDEX IF NOT EXISTS idx_logs_user ON logs(username);
            CREATE INDEX IF NOT EXISTS idx_logs_source ON logs(log_source);
            CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_id);
            CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
            CREATE INDEX IF NOT EXISTS idx_incidents_entity ON incidents(entity_type, entity_value);
        """)

        # FTS5 virtual table for full-text log search
        try:
            conn.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS logs_fts USING fts5(
                    message, event_type, username, source_ip,
                    content='logs',
                    content_rowid='id'
                )
            """)
        except sqlite3.OperationalError:
            pass  # FTS5 not available in this SQLite build

        conn.commit()

    # ── Write Operations ─────────────────────────────────────────────────

    def insert_log(self, log_event: dict) -> int:
        """Insert a normalized log event. Returns the new row id."""
        conn = self._get_conn()
        cur = conn.execute(
            """INSERT INTO logs
               (timestamp, event_type, source_ip, dest_ip, dest_port,
                username, hostname, process_name, parent_process,
                message, log_source, raw_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                log_event.get("timestamp", datetime.utcnow().isoformat()),
                log_event.get("event_type", "unknown"),
                log_event.get("source_ip"),
                log_event.get("dest_ip"),
                log_event.get("dest_port"),
                log_event.get("username"),
                log_event.get("hostname"),
                log_event.get("process_name"),
                log_event.get("parent_process"),
                log_event.get("message"),
                log_event.get("log_source", "api"),
                json.dumps(log_event),
            ),
        )
        row_id = cur.lastrowid

        # Update FTS index
        try:
            conn.execute(
                """INSERT INTO logs_fts(rowid, message, event_type, username, source_ip)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    row_id,
                    log_event.get("message", ""),
                    log_event.get("event_type", ""),
                    log_event.get("username", ""),
                    log_event.get("source_ip", ""),
                ),
            )
        except sqlite3.OperationalError:
            pass  # FTS5 not available

        conn.commit()
        return row_id

    def insert_alert(self, alert: dict) -> int:
        """Insert a generated alert. Returns the new row id."""
        conn = self._get_conn()
        core_keys = {
            "timestamp", "severity", "severity_score", "alert_type",
            "source_ip", "username", "description", "rule_name",
            "mitre_tactic", "mitre_technique", "incident_id",
        }
        metadata = {k: v for k, v in alert.items() if k not in core_keys}
        cur = conn.execute(
            """INSERT INTO alerts
               (timestamp, severity, severity_score, alert_type, source_ip,
                username, description, rule_name, mitre_tactic,
                mitre_technique, incident_id, metadata_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                alert.get("timestamp", datetime.utcnow().isoformat()),
                alert.get("severity", "medium"),
                alert.get("severity_score", 0),
                alert.get("alert_type", "unknown"),
                alert.get("source_ip"),
                alert.get("username"),
                alert.get("description"),
                alert.get("rule_name"),
                alert.get("mitre_tactic"),
                alert.get("mitre_technique"),
                alert.get("incident_id"),
                json.dumps(metadata),
            ),
        )
        conn.commit()
        return cur.lastrowid

    def insert_incident(self, incident: dict) -> int:
        """Insert a new incident. Returns the new row id."""
        conn = self._get_conn()
        cur = conn.execute(
            """INSERT INTO incidents
               (title, severity, severity_score, status, entity_type,
                entity_value, alert_count, first_seen, last_seen, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                incident.get("title"),
                incident.get("severity", "medium"),
                incident.get("severity_score", 0),
                incident.get("status", "new"),
                incident.get("entity_type"),
                incident.get("entity_value"),
                incident.get("alert_count", 1),
                incident.get("first_seen"),
                incident.get("last_seen"),
                incident.get("notes", ""),
            ),
        )
        conn.commit()
        return cur.lastrowid

    def update_incident(self, incident_id: int, updates: dict) -> bool:
        """Update an existing incident's fields."""
        conn = self._get_conn()
        allowed = {
            "title", "severity", "severity_score", "status",
            "assignee", "alert_count", "last_seen", "notes",
        }
        fields = {k: v for k, v in updates.items() if k in allowed}
        if not fields:
            return False
        fields["updated_at"] = datetime.utcnow().isoformat()
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values()) + [incident_id]
        conn.execute(
            f"UPDATE incidents SET {set_clause} WHERE id = ?", values
        )
        conn.commit()
        return True

    def link_alert_to_incident(self, alert_id: int, incident_id: int) -> None:
        """Link an alert to an incident by updating its incident_id."""
        conn = self._get_conn()
        conn.execute(
            "UPDATE alerts SET incident_id = ? WHERE id = ?",
            (incident_id, alert_id),
        )
        conn.commit()

    # ── Read Operations ──────────────────────────────────────────────────

    def get_alerts(
        self, limit: int = 50, severity: Optional[str] = None, offset: int = 0
    ) -> list[dict]:
        """Fetch recent alerts, optionally filtered by severity."""
        conn = self._get_conn()
        query = "SELECT * FROM alerts"
        params: list = []
        if severity:
            query += " WHERE severity = ?"
            params.append(severity)
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        return [dict(r) for r in conn.execute(query, params).fetchall()]

    def get_alert_counts(self) -> dict[str, int]:
        """Count alerts grouped by severity."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity"
        ).fetchall()
        return {r["severity"]: r["count"] for r in rows}

    def get_login_failures(self, hours: int = 24) -> list[dict]:
        """Get failed login counts bucketed by hour over the last N hours."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT strftime('%%Y-%%m-%%d %%H:00:00', timestamp) AS hour,
                      COUNT(*) AS count
               FROM logs
               WHERE event_type = 'authentication_failure'
                 AND timestamp >= datetime('now', ? || ' hours')
               GROUP BY hour ORDER BY hour""",
            (f"-{hours}",),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_malicious_processes(self, limit: int = 10) -> list[dict]:
        """Get top flagged process names from suspicious-process alerts."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT json_extract(metadata_json, '$.process_name') AS process_name,
                      COUNT(*) AS count
               FROM alerts
               WHERE rule_name = 'SuspiciousProcessDetector'
                 AND json_extract(metadata_json, '$.process_name') IS NOT NULL
               GROUP BY process_name
               ORDER BY count DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_log_count(self) -> int:
        conn = self._get_conn()
        return conn.execute("SELECT COUNT(*) AS c FROM logs").fetchone()["c"]

    def get_alert_count(self) -> int:
        conn = self._get_conn()
        return conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]

    # ── Incident Queries ─────────────────────────────────────────────────

    def get_incidents(
        self,
        limit: int = 50,
        status: Optional[str] = None,
        offset: int = 0,
    ) -> list[dict]:
        """Fetch incidents, optionally filtered by status."""
        conn = self._get_conn()
        query = "SELECT * FROM incidents"
        params: list = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY updated_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        return [dict(r) for r in conn.execute(query, params).fetchall()]

    def get_incident(self, incident_id: int) -> Optional[dict]:
        """Fetch a single incident by ID."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_incident_alerts(self, incident_id: int) -> list[dict]:
        """Fetch all alerts linked to a specific incident."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM alerts WHERE incident_id = ? ORDER BY created_at DESC",
            (incident_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_incident_counts(self) -> dict[str, int]:
        """Count incidents grouped by status."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT status, COUNT(*) as count FROM incidents GROUP BY status"
        ).fetchall()
        return {r["status"]: r["count"] for r in rows}

    def find_open_incident(self, entity_type: str, entity_value: str) -> Optional[dict]:
        """Find an open incident for a given entity."""
        conn = self._get_conn()
        row = conn.execute(
            """SELECT * FROM incidents
               WHERE entity_type = ? AND entity_value = ?
                 AND status IN ('new', 'in_progress')
               ORDER BY updated_at DESC LIMIT 1""",
            (entity_type, entity_value),
        ).fetchone()
        return dict(row) if row else None

    # ── Log Search ───────────────────────────────────────────────────────

    def search_logs(self, query: str, limit: int = 100) -> list[dict]:
        """Full-text search on log messages using FTS5."""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                """SELECT logs.* FROM logs_fts
                   JOIN logs ON logs.id = logs_fts.rowid
                   WHERE logs_fts MATCH ?
                   ORDER BY logs.timestamp DESC LIMIT ?""",
                (query, limit),
            ).fetchall()
            return [dict(r) for r in rows]
        except sqlite3.OperationalError:
            # Fallback to LIKE if FTS5 not available
            rows = conn.execute(
                """SELECT * FROM logs
                   WHERE message LIKE ? OR event_type LIKE ?
                   ORDER BY timestamp DESC LIMIT ?""",
                (f"%{query}%", f"%{query}%", limit),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_entity_timeline(
        self, entity_type: str, entity_value: str, limit: int = 200
    ) -> dict:
        """Get a combined timeline of logs and alerts for a specific entity."""
        conn = self._get_conn()
        col = "source_ip" if entity_type == "ip" else "username"

        logs = conn.execute(
            f"SELECT * FROM logs WHERE {col} = ? ORDER BY timestamp DESC LIMIT ?",
            (entity_value, limit),
        ).fetchall()

        alerts = conn.execute(
            f"SELECT * FROM alerts WHERE {col} = ? ORDER BY timestamp DESC LIMIT ?",
            (entity_value, limit),
        ).fetchall()

        incidents = conn.execute(
            """SELECT * FROM incidents
               WHERE entity_type = ? AND entity_value = ?
               ORDER BY updated_at DESC""",
            (entity_type, entity_value),
        ).fetchall()

        return {
            "entity_type": entity_type,
            "entity_value": entity_value,
            "logs": [dict(r) for r in logs],
            "alerts": [dict(r) for r in alerts],
            "incidents": [dict(r) for r in incidents],
        }

    def get_recent_logs(self, limit: int = 100, offset: int = 0, event_type: Optional[str] = None) -> list[dict]:
        """Fetch recent logs with optional event_type filter."""
        conn = self._get_conn()
        query = "SELECT * FROM logs"
        params: list = []
        if event_type:
            query += " WHERE event_type = ?"
            params.append(event_type)
        query += " ORDER BY ingested_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        return [dict(r) for r in conn.execute(query, params).fetchall()]

    def get_log_source_stats(self) -> list[dict]:
        """Get log counts grouped by source."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT log_source, event_type, COUNT(*) as count
               FROM logs GROUP BY log_source, event_type
               ORDER BY count DESC"""
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Maintenance ──────────────────────────────────────────────────────

    def run_retention(self, days: Optional[int] = None) -> int:
        """Delete logs older than the retention period. Returns rows removed."""
        days = days or LOG_RETENTION_DAYS
        conn = self._get_conn()
        cur = conn.execute(
            "DELETE FROM logs WHERE ingested_at < datetime('now', ? || ' days')",
            (f"-{days}",),
        )
        conn.commit()
        return cur.rowcount
