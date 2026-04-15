"""
Logix Configuration
===================
Central configuration for the SIEM engine.
All settings are overridable via environment variables for deployment flexibility.
"""

import os
from pathlib import Path

# ─── Paths ───────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = DATA_DIR / "logix.db"
ALERTS_JSON_PATH = DATA_DIR / "alerts.json"
SAMPLE_LOGS_PATH = DATA_DIR / "sample_logs.json"
SIGMA_RULES_DIR = BASE_DIR / "engine" / "rules" / "sigma"

# ─── Brute Force Detection ──────────────────────────────────────────────────
BRUTE_FORCE_MAX_ATTEMPTS: int = int(os.getenv("LOGIX_BF_MAX", "5"))
BRUTE_FORCE_CRITICAL_THRESHOLD: int = int(os.getenv("LOGIX_BF_CRIT", "10"))
BRUTE_FORCE_TIME_WINDOW: int = int(os.getenv("LOGIX_BF_WINDOW", "300"))

# ─── Suspicious Process Detection ───────────────────────────────────────────
SHELL_BLACKLIST: list[str] = [
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "bash", "sh", "zsh",
    "python.exe", "python3",
    "wscript.exe", "cscript.exe", "mshta.exe",
]

PARENT_WHITELIST: list[str] = [
    "explorer.exe", "svchost.exe", "services.exe",
    "terminal.exe", "windowsterminal.exe", "conhost.exe",
    "code.exe", "devenv.exe",
]

HIGH_RISK_PARENTS: list[str] = [
    "httpd", "nginx", "apache2", "w3wp.exe",
    "tomcat", "node.exe", "java.exe", "iisexpress.exe",
]


# ─── Severity Levels ────────────────────────────────────────────────────────
class Severity:
    """Standardized severity levels for alerts."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    SCORE = {
        "critical": 90,
        "high": 70,
        "medium": 40,
        "low": 10,
    }


# ─── Syslog Ingestion ──────────────────────────────────────────────────────
SYSLOG_ENABLED: bool = os.getenv("LOGIX_SYSLOG", "true").lower() == "true"
SYSLOG_UDP_PORT: int = int(os.getenv("LOGIX_SYSLOG_UDP", "1514"))
SYSLOG_TCP_PORT: int = int(os.getenv("LOGIX_SYSLOG_TCP", "1514"))

# ─── Correlation ────────────────────────────────────────────────────────────
CORRELATION_WINDOW: int = int(os.getenv("LOGIX_CORR_WINDOW", "600"))
INCIDENT_AUTO_MERGE_WINDOW: int = int(os.getenv("LOGIX_MERGE_WINDOW", "3600"))

# ─── Log Retention ──────────────────────────────────────────────────────────
LOG_RETENTION_DAYS: int = int(os.getenv("LOGIX_RETENTION_DAYS", "30"))

# ─── Simulator ──────────────────────────────────────────────────────────────
SIMULATOR_ENABLED: bool = os.getenv("LOGIX_SIMULATOR", "true").lower() == "true"
SIMULATOR_INTERVAL: float = float(os.getenv("LOGIX_SIM_INTERVAL", "2.0"))

# ─── Flask ──────────────────────────────────────────────────────────────────
FLASK_HOST: str = os.getenv("LOGIX_HOST", "0.0.0.0")
FLASK_PORT: int = int(os.getenv("LOGIX_PORT", "5000"))
FLASK_DEBUG: bool = os.getenv("LOGIX_DEBUG", "true").lower() == "true"

# ─── Dashboard ──────────────────────────────────────────────────────────────
DASHBOARD_POLL_INTERVAL: int = int(os.getenv("LOGIX_POLL_MS", "5000"))
