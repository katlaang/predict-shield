"""Actual HTTP gateway routing to independently running Java enforcement processes.

The process is intentionally small and disposable. Routing rotates through
three upstream services and preserves actual HTTP response codes. An explicit,
credential-protected restriction changes the gateway's real forwarding rule.
An unavailable upstream produces HTTP 502, which the external load generator
records as disruption. This is not a hardened reverse proxy.
"""
from __future__ import annotations
import itertools
import json
import os
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAMS = tuple(os.environ.get("ENFORCERS", "").split(","))
CONTROL = os.environ.get("LAB_CONTROL_TOKEN", "")
counter = itertools.count()
state_lock = threading.Lock()
restricted = False


class Gateway(BaseHTTPRequestHandler):
    """Expose only bounded synthetic protected, legitimate and control paths."""

    def _send(self, status: int, payload: dict) -> None:
        """Write a JSON response, preserving observed upstream HTTP status."""
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        """Route actual workload traffic through round-robin enforcement nodes."""
        if self.path == "/healthz":
            self._send(200, {"gateway": "ready"})
            return
        if self.path not in ("/protected", "/legitimate"):
            self._send(404, {"error": "unsupported route"})
            return
        with state_lock:
            is_restricted = restricted
        if is_restricted:
            if self.path == "/protected":
                self._send(403, {"source": "gateway", "decision": "DENY"})
            else:
                self._send(503, {"source": "gateway", "error": "gateway restriction"})
            return
        node = UPSTREAMS[next(counter) % len(UPSTREAMS)]
        try:
            with urllib.request.urlopen(node + self.path, timeout=1.0) as resp:
                status = resp.status
                body = resp.read(4096)
        except urllib.error.HTTPError as err:
            status = err.code
            body = err.read(4096)
        except (OSError, TimeoutError):
            self._send(502, {"source": "gateway", "upstream": node, "error": "unreachable"})
            return
        try:
            payload = json.loads(body)
        except (ValueError, UnicodeError):
            payload = {"body_unparseable": True}
        payload["gateway_upstream"] = node
        self._send(status, payload)

    def do_POST(self) -> None:
        """Change only the disposable gateway restriction with an authorized token."""
        global restricted
        if self.headers.get("X-Lab-Control", "") != CONTROL or not CONTROL:
            self._send(403, {"error": "gateway token rejected"})
            return
        if self.path not in ("/admin/restrict", "/admin/restore"):
            self._send(404, {"error": "unknown gateway control"})
            return
        with state_lock:
            restricted = self.path == "/admin/restrict"
            new_state = restricted
        self._send(200, {"restricted": new_state, "acknowledged": True})

    def log_message(self, format: str, *args: object) -> None:
        """Suppress request-body logging and avoid leaking synthetic credentials."""
        return


def main() -> None:
    """Serve the isolated gateway exclusively within its Docker network."""
    if not UPSTREAMS or any(not node.startswith("http://enforcer-") for node in UPSTREAMS):
        raise RuntimeError("Expected explicit laboratory enforcement upstreams")
    ThreadingHTTPServer(("0.0.0.0", 8080), Gateway).serve_forever()


if __name__ == "__main__":
    main()
