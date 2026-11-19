"""HTTPS intake for detections, with source identity checked at the edge.

Two routes, both over TLS:

    POST /v1/detections        body: a signed envelope {"payload", "signature"}
                               checked with `authenticate_signed()`.
    POST /v1/detections/mtls   body: a bare payload. The client must present a
                               certificate that chains to the registered client
                               CA, and its fingerprint must be the one registered
                               for the source the payload names
                               (`authenticate_mtls()`).

An admitted detection is passed to `on_admitted(AdmissionResult)`. Nothing
here executes, approves or verifies an action. Responses never echo the
reason for an authentication failure beyond a fixed message, so a caller
cannot probe which sources or keys are registered.

The server binds to the address it is given; the tests and the CI lab use
loopback only.
"""
from __future__ import annotations

import json
import ssl
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

from .detection_intake import (
    AdmissionResult,
    RegisteredDetectionSource,
    ReplayGuard,
    admit,
    authenticate_mtls,
    authenticate_signed,
)

MAX_BODY_BYTES = 64 * 1024


class DetectionIntakeServer:
    def __init__(self, *, host: str, port: int, certfile: str, keyfile: str,
                 client_ca_file: str | None,
                 registry: dict[str, RegisteredDetectionSource],
                 on_admitted: Callable[[AdmissionResult], None],
                 max_age_seconds: float = 900.0,
                 clock: Callable[[], datetime] | None = None):
        self.registry = registry
        self.on_admitted = on_admitted
        self.max_age_seconds = max_age_seconds
        self.replay_guard = ReplayGuard(max_age_seconds)
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.rejections: list[str] = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile, keyfile)
        if client_ca_file:
            context.load_verify_locations(client_ca_file)
            context.verify_mode = ssl.CERT_OPTIONAL
        else:
            context.verify_mode = ssl.CERT_NONE
        intake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                return

            def _reply(self, status: int, body: dict) -> None:
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                if self.path not in ("/v1/detections", "/v1/detections/mtls"):
                    return self._reply(404, {"error": "not found"})
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    return self._reply(400, {"error": "bad length"})
                if length <= 0 or length > MAX_BODY_BYTES:
                    return self._reply(413, {"error": "body size not accepted"})
                try:
                    body = json.loads(self.rfile.read(length))
                except (ValueError, UnicodeDecodeError):
                    return self._reply(400, {"error": "malformed JSON"})
                now = intake.clock()
                try:
                    if self.path == "/v1/detections":
                        authenticated = authenticate_signed(
                            body, intake.registry, intake.replay_guard,
                            now=now, max_age_seconds=intake.max_age_seconds)
                    else:
                        peer = self.connection.getpeercert(binary_form=True)
                        authenticated = authenticate_mtls(
                            body, peer or b"", intake.registry, intake.replay_guard,
                            now=now, max_age_seconds=intake.max_age_seconds)
                    admitted = admit(authenticated, intake.registry, now=now,
                                     max_age_seconds=intake.max_age_seconds)
                except (ValueError, TypeError) as exc:
                    intake.rejections.append(str(exc))
                    return self._reply(401, {"error": "detection not admitted"})
                intake.on_admitted(admitted)
                return self._reply(202, {"admitted": True,
                                         "assertion": admitted.evidence.assertion,
                                         "source": admitted.evidence.source,
                                         "authentication": authenticated.method})

        self.httpd = ThreadingHTTPServer((host, port), Handler)
        self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self._thread: threading.Thread | None = None

    def start(self) -> "DetectionIntakeServer":
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
