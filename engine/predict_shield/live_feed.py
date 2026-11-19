"""Read-only live state for the operations dashboard.

The running chain, the intake server and the change executor publish
what is happening into a `LiveState`. `LiveFeedServer` serves it:

    GET /api/state   the current state as JSON, with a server timestamp
    GET /            the dashboard page (demo/live.html)
    GET /live.js     its script (demo/live.js)

GET only; every other method is refused. It binds to loopback unless a
caller explicitly allows otherwise, and it never accepts input that could
change the state. The page shows NO LIVE DATA whenever a fetch fails or
the server timestamp stops advancing, so a stale view is never presented
as live.
"""
from __future__ import annotations

import ipaddress
import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MAX_EVENTS = 500


class LiveState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sequence = 0
        self._events: list[dict] = []
        self._incidents: dict[str, dict] = {}
        self._panels: dict[str, object] = {}

    def event(self, kind: str, **fields) -> None:
        with self._lock:
            self._sequence += 1
            self._events.append(dict(fields, kind=kind, sequence=self._sequence,
                                     at=datetime.now(timezone.utc).isoformat()))
            del self._events[:-MAX_EVENTS]

    def incident(self, case_id: str, **fields) -> None:
        with self._lock:
            self._sequence += 1
            current = self._incidents.setdefault(case_id, {"case_id": case_id})
            current.update(fields)
            current["updated_at"] = datetime.now(timezone.utc).isoformat()

    def panel(self, name: str, value) -> None:
        with self._lock:
            self._sequence += 1
            self._panels[name] = value

    def snapshot(self) -> dict:
        with self._lock:
            return {"schema": "predict-shield/live-state/1",
                    "served_at": datetime.now(timezone.utc).isoformat(),
                    "sequence": self._sequence,
                    "incidents": [dict(v) for v in self._incidents.values()],
                    "events": list(self._events[-100:]),
                    "panels": json.loads(json.dumps(self._panels, default=str))}


class LiveFeedServer:
    def __init__(self, state: LiveState, *, host: str = "127.0.0.1", port: int = 0,
                 page: Path | None = None, script: Path | None = None,
                 allow_non_loopback: bool = False):
        if not allow_non_loopback and not ipaddress.ip_address(host).is_loopback:
            raise ValueError("the live feed binds to loopback unless explicitly allowed")
        page_bytes = Path(page).read_bytes() if page else b"<!doctype html><title>PREDICT-SHIELD live</title>"
        script_bytes = Path(script).read_bytes() if script else b""

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                return

            def _send(self, status, content_type, body: bytes):
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Security-Policy",
                                 "default-src 'none'; script-src 'self'; "
                                 "style-src 'unsafe-inline'; connect-src 'self'")
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path == "/api/state":
                    return self._send(200, "application/json", json.dumps(state.snapshot()).encode())
                if self.path == "/live.js" and script_bytes:
                    return self._send(200, "application/javascript", script_bytes)
                if self.path in ("/", "/index.html", "/live.html"):
                    return self._send(200, "text/html; charset=utf-8", page_bytes)
                return self._send(404, "text/plain", b"not found")

            def _refuse(self):
                self._send(405, "text/plain", b"read-only")

            do_POST = do_PUT = do_DELETE = do_PATCH = _refuse

        self.httpd = ThreadingHTTPServer((host, port), Handler)
        self.port = self.httpd.server_address[1]
        self.url = f"http://{host}:{self.port}/"

    def start(self) -> "LiveFeedServer":
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
