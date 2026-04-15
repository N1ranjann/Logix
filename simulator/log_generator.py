"""
Log Simulator
=============
Background thread that generates realistic log events:
  60 % normal traffic  |  25 % brute-force  |  15 % suspicious process
"""

import logging
import random
import threading
import time
from datetime import datetime

logger = logging.getLogger("logix.simulator")

_USERS = ["admin", "root", "jsmith", "deploy", "backup", "www-data"]
_NORMAL_USERS = ["jsmith", "agarcia", "lchen", "mwilson", "kpatel"]
_IPS = [
    "192.168.1.100", "192.168.1.105", "10.0.0.50",
    "10.0.0.88", "172.16.0.12", "172.16.0.45",
]
_ATTACKER_IPS = [
    "45.33.32.156", "185.220.101.1", "23.129.64.100",
    "198.51.100.42", "203.0.113.77", "91.219.237.15",
]
_NORMAL_PROCS = [
    ("chrome.exe", "explorer.exe"),
    ("notepad.exe", "explorer.exe"),
    ("code.exe", "explorer.exe"),
    ("svchost.exe", "services.exe"),
]
_SUS_CHAINS = [
    ("cmd.exe", "nginx"), ("powershell.exe", "httpd"),
    ("bash", "apache2"), ("cmd.exe", "w3wp.exe"),
    ("powershell.exe", "tomcat"), ("sh", "nginx"),
    ("cmd.exe", "java.exe"), ("powershell.exe", "node.exe"),
]


class LogSimulator:
    """Generates mixed normal/attack log events in a daemon thread."""

    def __init__(self, ingestor, interval: float = 2.0) -> None:
        self._ingestor = ingestor
        self._interval = interval
        self._running = False

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()
        logger.info("Simulator started (%.1fs interval)", self._interval)

    def stop(self) -> None:
        self._running = False

    def _loop(self) -> None:
        while self._running:
            try:
                for ev in self._batch():
                    self._ingestor.ingest_event(ev)
                time.sleep(self._interval)
            except Exception as exc:
                logger.error("Simulator: %s", exc)
                time.sleep(1)

    def _batch(self) -> list[dict]:
        events = []
        for _ in range(random.randint(1, 3)):
            r = random.random()
            if r < 0.60:
                events.append(self._normal())
            elif r < 0.85:
                events.append(self._brute())
            else:
                events.append(self._suspicious())
        return events

    @staticmethod
    def _ts() -> str:
        return datetime.utcnow().isoformat() + "Z"

    def _normal(self) -> dict:
        kind = random.choice(["auth_ok", "proc", "other"])
        if kind == "auth_ok":
            u = random.choice(_NORMAL_USERS)
            return dict(
                timestamp=self._ts(), event_type="authentication_success",
                source_ip=random.choice(_IPS), username=u,
                process_name="sshd", parent_process="systemd",
                message=f"Accepted password for {u}",
            )
        if kind == "proc":
            p, pp = random.choice(_NORMAL_PROCS)
            return dict(
                timestamp=self._ts(), event_type="process_start",
                source_ip=random.choice(_IPS), process_name=p,
                parent_process=pp, message=f"{p} started by {pp}",
            )
        return dict(
            timestamp=self._ts(),
            event_type=random.choice(["network_connection", "file_access"]),
            source_ip=random.choice(_IPS),
            username=random.choice(_NORMAL_USERS),
            message="Normal activity",
        )

    def _brute(self) -> dict:
        u = random.choice(_USERS[:3])
        return dict(
            timestamp=self._ts(), event_type="authentication_failure",
            source_ip=random.choice(_ATTACKER_IPS), username=u,
            process_name="sshd", parent_process="systemd",
            message=f"Failed password for {u}",
        )

    def _suspicious(self) -> dict:
        p, pp = random.choice(_SUS_CHAINS)
        return dict(
            timestamp=self._ts(), event_type="process_start",
            source_ip=random.choice(_ATTACKER_IPS),
            process_name=p, parent_process=pp, username="www-data",
            message=f"Suspicious: {p} spawned by {pp}",
        )
