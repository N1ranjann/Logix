"""
Syslog Server
=============
Lightweight UDP/TCP syslog receiver that feeds into the Logix ingestor.
Listens on configurable ports (default 1514 to avoid root requirement).
"""

import logging
import socketserver
import threading
from typing import Callable, Optional

logger = logging.getLogger("logix.syslog")


class _UDPHandler(socketserver.BaseRequestHandler):
    """Handler for incoming UDP syslog messages."""

    def handle(self):
        data = self.request[0].strip()
        try:
            message = data.decode("utf-8", errors="replace")
            if self.server.callback:
                self.server.callback(message, self.client_address[0])
        except Exception as exc:
            logger.error("Syslog UDP handler error: %s", exc)


class _TCPHandler(socketserver.StreamRequestHandler):
    """Handler for incoming TCP syslog messages."""

    def handle(self):
        try:
            for line in self.rfile:
                message = line.strip().decode("utf-8", errors="replace")
                if message and self.server.callback:
                    self.server.callback(message, self.client_address[0])
        except Exception as exc:
            logger.error("Syslog TCP handler error: %s", exc)


class _ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    callback: Optional[Callable] = None


class _ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    callback: Optional[Callable] = None


class SyslogServer:
    """
    Dual UDP/TCP syslog receiver.
    Passes every received line to a callback for normalization and ingestion.
    """

    def __init__(
        self,
        callback: Callable[[str, str], None],
        udp_port: int = 1514,
        tcp_port: int = 1514,
    ) -> None:
        self._callback = callback
        self._udp_port = udp_port
        self._tcp_port = tcp_port
        self._udp_server: Optional[_ThreadedUDPServer] = None
        self._tcp_server: Optional[_ThreadedTCPServer] = None
        self._running = False

    def start(self) -> None:
        """Start both UDP and TCP listeners in daemon threads."""
        if self._running:
            return
        self._running = True

        # UDP
        try:
            self._udp_server = _ThreadedUDPServer(
                ("0.0.0.0", self._udp_port), _UDPHandler
            )
            self._udp_server.callback = self._callback
            t = threading.Thread(
                target=self._udp_server.serve_forever, daemon=True
            )
            t.start()
            logger.info("Syslog UDP listening on :%d", self._udp_port)
        except OSError as exc:
            logger.warning("Syslog UDP failed to bind :%d — %s", self._udp_port, exc)

        # TCP
        try:
            self._tcp_server = _ThreadedTCPServer(
                ("0.0.0.0", self._tcp_port), _TCPHandler
            )
            self._tcp_server.callback = self._callback
            t = threading.Thread(
                target=self._tcp_server.serve_forever, daemon=True
            )
            t.start()
            logger.info("Syslog TCP listening on :%d", self._tcp_port)
        except OSError as exc:
            logger.warning("Syslog TCP failed to bind :%d — %s", self._tcp_port, exc)

    def stop(self) -> None:
        self._running = False
        if self._udp_server:
            self._udp_server.shutdown()
        if self._tcp_server:
            self._tcp_server.shutdown()
        logger.info("Syslog server stopped")

    @property
    def is_running(self) -> bool:
        return self._running
