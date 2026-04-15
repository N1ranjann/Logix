"""
REST API Routes
===============
Dashboard data endpoints served under ``/api``.
Covers: log ingestion, alerts, incidents, log search, entity timelines.
"""

import time
from flask import Blueprint, jsonify, request

api_bp = Blueprint("api", __name__, url_prefix="/api")

# Injected at startup by init_api()
_ingestor = None
_db = None
_rules_engine = None
_alert_manager = None
_correlation = None
_incident_manager = None
_syslog_server = None
_start_time: float = 0.0


def init_api(
    ingestor, db, rules_engine, alert_manager,
    correlation, incident_manager, start_time: float,
    syslog_server=None,
):
    """Wire dependencies — called once from create_app()."""
    global _ingestor, _db, _rules_engine, _alert_manager
    global _correlation, _incident_manager, _syslog_server, _start_time
    _ingestor = ingestor
    _db = db
    _rules_engine = rules_engine
    _alert_manager = alert_manager
    _correlation = correlation
    _incident_manager = incident_manager
    _syslog_server = syslog_server
    _start_time = start_time


# ── Health Check ─────────────────────────────────────────────────────────

@api_bp.route("/health", methods=["GET"])
def health_check():
    return jsonify(status="ok", service="logix-siem"), 200


# ── Log Ingestion ────────────────────────────────────────────────────────

@api_bp.route("/logs", methods=["POST"])
def ingest_log():
    data = request.get_json(silent=True)
    if not data:
        return jsonify(error="JSON body required"), 400
    alerts = _ingestor.ingest_event(data)
    return jsonify(status="ingested", alerts_generated=len(alerts), alerts=alerts), 201


@api_bp.route("/webhook/<source_name>", methods=["POST"])
def ingest_webhook(source_name):
    """Generic webhook endpoint for external services."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify(error="JSON body required"), 400
    alerts = _ingestor.ingest_webhook(data, source_name=source_name)
    return jsonify(status="ingested", source=source_name, alerts_generated=len(alerts)), 201


# ── Log Explorer ─────────────────────────────────────────────────────────

@api_bp.route("/logs/recent", methods=["GET"])
def get_recent_logs():
    limit = request.args.get("limit", 100, type=int)
    offset = request.args.get("offset", 0, type=int)
    event_type = request.args.get("event_type") or None
    logs = _db.get_recent_logs(limit=limit, offset=offset, event_type=event_type)
    return jsonify(logs=logs, count=len(logs))


@api_bp.route("/logs/search", methods=["GET"])
def search_logs():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify(error="Query parameter 'q' is required"), 400
    limit = request.args.get("limit", 100, type=int)
    results = _db.search_logs(q, limit=limit)
    return jsonify(results=results, count=len(results), query=q)


@api_bp.route("/logs/sources", methods=["GET"])
def log_sources():
    stats = _db.get_log_source_stats()
    return jsonify(sources=stats)


# ── Alert Feed ───────────────────────────────────────────────────────────

@api_bp.route("/alerts", methods=["GET"])
def get_alerts():
    limit = request.args.get("limit", 50, type=int)
    severity = request.args.get("severity") or None
    offset = request.args.get("offset", 0, type=int)
    alerts = _db.get_alerts(limit=limit, severity=severity, offset=offset)
    return jsonify(alerts=alerts, count=len(alerts))


@api_bp.route("/alerts/count", methods=["GET"])
def alert_counts():
    counts = _db.get_alert_counts()
    return jsonify(counts=counts, total=sum(counts.values()))


# ── Incidents ────────────────────────────────────────────────────────────

@api_bp.route("/incidents", methods=["GET"])
def get_incidents():
    limit = request.args.get("limit", 50, type=int)
    status = request.args.get("status") or None
    offset = request.args.get("offset", 0, type=int)
    incidents = _db.get_incidents(limit=limit, status=status, offset=offset)
    return jsonify(incidents=incidents, count=len(incidents))


@api_bp.route("/incidents/<int:incident_id>", methods=["GET"])
def get_incident(incident_id):
    incident = _db.get_incident(incident_id)
    if not incident:
        return jsonify(error="Incident not found"), 404
    alerts = _db.get_incident_alerts(incident_id)
    return jsonify(incident=incident, alerts=alerts)


@api_bp.route("/incidents/<int:incident_id>", methods=["PATCH"])
def update_incident(incident_id):
    data = request.get_json(silent=True)
    if not data:
        return jsonify(error="JSON body required"), 400

    status_val = data.get("status")
    notes = data.get("notes", "")

    if status_val:
        success = _incident_manager.update_status(incident_id, status_val, notes)
    else:
        success = _db.update_incident(incident_id, data)

    if not success:
        return jsonify(error="Update failed"), 400
    return jsonify(status="updated", incident_id=incident_id)


@api_bp.route("/incidents/summary", methods=["GET"])
def incident_summary():
    counts = _incident_manager.get_summary()
    total = sum(counts.values())
    return jsonify(counts=counts, total=total)


# ── Entity Timeline ─────────────────────────────────────────────────────

@api_bp.route("/entity/<entity_type>/<entity_value>/timeline", methods=["GET"])
def entity_timeline(entity_type, entity_value):
    if entity_type not in ("ip", "user"):
        return jsonify(error="entity_type must be 'ip' or 'user'"), 400
    limit = request.args.get("limit", 200, type=int)
    timeline = _db.get_entity_timeline(entity_type, entity_value, limit=limit)
    return jsonify(**timeline)


# ── Statistics ───────────────────────────────────────────────────────────

@api_bp.route("/stats/login-failures", methods=["GET"])
def login_failures():
    hours = request.args.get("hours", 24, type=int)
    return jsonify(data=_db.get_login_failures(hours=hours))


@api_bp.route("/stats/malicious-processes", methods=["GET"])
def malicious_processes():
    limit = request.args.get("limit", 10, type=int)
    return jsonify(data=_db.get_malicious_processes(limit=limit))


@api_bp.route("/stats/system-health", methods=["GET"])
def system_health():
    elapsed = time.time() - _start_time
    h, rem = divmod(int(elapsed), 3600)
    m, s = divmod(rem, 60)

    syslog_status = "operational" if (_syslog_server and _syslog_server.is_running) else "disabled"

    return jsonify(
        status="operational",
        uptime=f"{h}h {m}m {s}s",
        total_logs=_db.get_log_count(),
        total_alerts=_db.get_alert_count(),
        alert_counts=_db.get_alert_counts(),
        incident_counts=_incident_manager.get_summary() if _incident_manager else {},
        engine=_rules_engine.get_stats(),
        correlation=_correlation.get_stats() if _correlation else {},
        components=dict(
            ingestor="operational",
            rules_engine="operational",
            correlation_engine="operational",
            alert_manager="operational",
            incident_manager="operational",
            syslog_server=syslog_status,
            simulator="operational",
        ),
    )
