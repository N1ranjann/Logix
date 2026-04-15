"""
Logix — SIEM Engine
=====================
Entry point.  Run with:  python app.py
Dashboard:  http://localhost:5000
"""

import logging
import time

from flask import Flask, render_template

from api.routes import api_bp, init_api
from config import (
    FLASK_HOST, FLASK_PORT, FLASK_DEBUG,
    SIMULATOR_ENABLED, SIMULATOR_INTERVAL,
    SYSLOG_ENABLED, SYSLOG_UDP_PORT, SYSLOG_TCP_PORT,
)
from engine.alert_manager import AlertManager
from engine.correlation import CorrelationEngine
from engine.incident_manager import IncidentManager
from engine.ingestor import LogIngestor
from engine.rules.brute_force import BruteForceDetector
from engine.rules.sigma_loader import load_sigma_rules
from engine.rules.suspicious_process import SuspiciousProcessDetector
from engine.rules_engine import RulesEngine
from models.database import Database


def create_app() -> Flask:
    """Application factory."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(name)-24s | %(levelname)-7s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    log = logging.getLogger("logix")
    log.info("=" * 60)
    log.info("  LOGIX  —  SIEM Engine")
    log.info("=" * 60)

    # 1. Database
    db = Database()
    log.info("Database ready  (%s)", db._db_path)

    # 2. Rules engine — built-in rules
    engine = RulesEngine()
    engine.register_rule(BruteForceDetector())
    engine.register_rule(SuspiciousProcessDetector())

    # 3. SIGMA rules
    sigma_rules = load_sigma_rules()
    for rule in sigma_rules:
        engine.register_rule(rule)

    # 4. Correlation engine
    correlation = CorrelationEngine()
    log.info("Correlation engine ready (%d rules)", len(correlation._rules))

    # 5. Alert manager
    alerts = AlertManager(db=db)
    log.info("Alert manager ready  (console + file + db)")

    # 6. Incident manager
    incident_mgr = IncidentManager(db=db)
    log.info("Incident manager ready")

    # 7. Ingestor
    ingestor = LogIngestor(
        rules_engine=engine,
        alert_manager=alerts,
        correlation=correlation,
        incident_manager=incident_mgr,
        db=db,
    )
    log.info("Ingestor ready")

    # 8. Syslog server
    syslog_srv = None
    if SYSLOG_ENABLED:
        from engine.sources.syslog_server import SyslogServer
        syslog_srv = SyslogServer(
            callback=ingestor.ingest_syslog,
            udp_port=SYSLOG_UDP_PORT,
            tcp_port=SYSLOG_TCP_PORT,
        )
        syslog_srv.start()

    # 9. Wire API
    start_time = time.time()
    init_api(
        ingestor, db, engine, alerts,
        correlation, incident_mgr, start_time,
        syslog_server=syslog_srv,
    )

    # 10. Flask
    app = Flask(__name__)
    app.register_blueprint(api_bp)

    @app.route("/")
    def dashboard():
        return render_template("dashboard.html")

    @app.route("/health")
    def health():
        return {"status": "ok", "service": "logix-siem"}, 200

    # 11. Simulator (optional — for demo/testing)
    if SIMULATOR_ENABLED:
        from simulator.log_generator import LogSimulator
        sim = LogSimulator(ingestor=ingestor, interval=SIMULATOR_INTERVAL)
        sim.start()
    else:
        log.info("Simulator disabled (set LOGIX_SIMULATOR=true to enable)")

    log.info("Dashboard -> http://%s:%s", FLASK_HOST, FLASK_PORT)
    log.info("=" * 60)
    return app


if __name__ == "__main__":
    application = create_app()
    application.run(
        host=FLASK_HOST, port=FLASK_PORT,
        debug=FLASK_DEBUG, use_reloader=False,
    )
