"""Serializing, labelling reverse proxy in front of the application under test.

Each listening port carries one traffic source (benign users, attack tools, crawl).
A single lock lets one request reach the application at a time, so every system
call the application makes between forwarding and response belongs to exactly
one recorded exchange. The ZAP active scanner's X-ZAP-Scan-ID header (the scanner
plugin id) is recorded as a label and removed before forwarding, so neither the
application nor the detector sees it.
"""
from __future__ import annotations

import http.client
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOP = {"connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "te", "trailer",
       "proxy-authorization", "proxy-authenticate", "accept-encoding", "content-length", "host"}
LOCK = threading.Lock()
LOG_LOCK = threading.Lock()


def make_handler(source: str, upstream: tuple[str, int], log):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _relay(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else b""
            plugin = self.headers.get("X-ZAP-Scan-ID", "")
            headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP and k.lower() != "x-zap-scan-id"}
            headers["Host"] = f"{upstream[0]}:{upstream[1]}"
            if body:
                headers["Content-Length"] = str(len(body))
            with LOCK:
                t_send = time.time()
                try:
                    conn = http.client.HTTPConnection(*upstream, timeout=60)
                    conn.request(self.command, self.path, body=body, headers=headers)
                    resp = conn.getresponse()
                    data = resp.read()
                    status, rheaders = resp.status, resp.getheaders()
                    conn.close()
                except Exception as e:  # upstream failure is recorded, not hidden
                    status, rheaders, data = 599, [], str(e).encode()
                t_recv = time.time()
            rec = {"source": source, "plugin": plugin, "method": self.command, "path": self.path,
                   "content_type": self.headers.get("Content-Type", ""), "body": body.decode("utf-8", "replace"),
                   "status": status, "response": data[:20000].decode("utf-8", "replace"),
                   "response_bytes": len(data), "t_send": t_send, "t_recv": t_recv,
                   "user_agent": self.headers.get("User-Agent", "")}
            with LOG_LOCK:
                log.write(json.dumps(rec) + "\n")
                log.flush()
            self.send_response(status)
            for k, v in rheaders:
                if k.lower() not in HOP:
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _relay

    return Handler


def main(log_path: str, upstream_port: int, ports: dict[str, int]) -> None:
    log = open(log_path, "a")
    servers = []
    for source, port in ports.items():
        srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(source, ("127.0.0.1", upstream_port), log))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
    print("proxy ready", ports, flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    # serial_proxy.py LOG UPSTREAM_PORT source=port [source=port ...]
    main(sys.argv[1], int(sys.argv[2]), {kv.split("=")[0]: int(kv.split("=")[1]) for kv in sys.argv[3:]})
