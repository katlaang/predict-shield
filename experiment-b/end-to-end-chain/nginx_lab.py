"""A real nginx serving the operator's page on loopback, for the chain lab.

nginx runs from its own prefix directory with its own pid, logs and temp
paths, listening only on 127.0.0.1. PREDICT-SHIELD changes it only through
`change_execution` adapters:

    managed/csp.conf     the page's CSP header, one generated add_header line
                         (NginxCspIncludeAdapter: nginx -t, then reload)
    www/page.html        the page itself, one of the registered renderings
                         (RegisteredRenderingsAdapter)

Everything under www/isolated/ is provisioned once, at registration time,
and served with the frame's own fixed CSP. The chain never edits it.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "real-script-integrity-pilot"))
import lab_servers  # noqa: E402

NGINX_BINARY = shutil.which("nginx") or "/usr/sbin/nginx"


def free_port(host: str = "127.0.0.1") -> int:
    with socket.socket() as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def direct_page(script_url: str) -> str:
    return lab_servers.PAGE_TEMPLATE.format(script_url=script_url, script_attrs="", extra_script_tag="")


def pinned_page(script_url: str, sri: str) -> str:
    return lab_servers.PAGE_TEMPLATE.format(
        script_url=script_url, script_attrs=f' integrity="{sri}" crossorigin="anonymous"', extra_script_tag="")


def isolated_page() -> str:
    return lab_servers.ISOLATED_PAGE_TEMPLATE


class NginxLab:
    def __init__(self, prefix: Path, vendor_origin: str):
        self.prefix = Path(prefix)
        self.vendor_origin = vendor_origin
        self.vendor_source = vendor_origin.split("://", 1)[1]
        self.port = free_port()
        self.origin = f"http://127.0.0.1:{self.port}"
        self.csp_include = self.prefix / "managed" / "csp.conf"
        self.page = self.prefix / "www" / "page.html"
        self.conf = self.prefix / "nginx.conf"

    @property
    def cmd(self) -> list[str]:
        # -e: never touch the system error log, so nginx runs unprivileged.
        return [NGINX_BINARY, "-p", str(self.prefix), "-c", str(self.conf),
                "-e", str(self.prefix / "logs" / "error.log")]

    def provision(self, initial_csp_include: str, initial_page: str) -> None:
        if self.prefix.exists():
            shutil.rmtree(self.prefix)
        for sub in ("managed", "www/isolated", "logs", "tmp"):  # logs must exist before -e
            (self.prefix / sub).mkdir(parents=True, exist_ok=True)
        os.chmod(self.prefix, 0o755)
        self.csp_include.write_text(initial_csp_include)
        self.page.write_text(initial_page)
        www = self.prefix / "www"
        (www / "canary.gif").write_bytes(lab_servers._GIF)
        (www / "isolated" / "vendor-frame.html").write_text(
            lab_servers.FRAME_TEMPLATE.format(script_url=self.vendor_origin + "/widget.js"))
        (www / "isolated" / "frame-bridge.js").write_bytes(lab_servers.FRAME_BRIDGE_JS)
        (www / "isolated" / "host-bridge.js").write_bytes(lab_servers.HOST_BRIDGE_JS)
        user = "user root;\n" if os.geteuid() == 0 else ""
        p = self.prefix
        self.conf.write_text(f"""{user}worker_processes 1;
pid {p}/nginx.pid;
error_log {p}/logs/error.log warn;
events {{ worker_connections 64; }}
http {{
  access_log {p}/logs/access.log;
  client_body_temp_path {p}/tmp/body;
  proxy_temp_path {p}/tmp/proxy;
  fastcgi_temp_path {p}/tmp/fastcgi;
  uwsgi_temp_path {p}/tmp/uwsgi;
  scgi_temp_path {p}/tmp/scgi;
  types {{ text/html html; application/javascript js; image/gif gif; }}
  server {{
    listen 127.0.0.1:{self.port};
    root {p}/www;
    location = /page.html {{
      include {self.csp_include};
      add_header Cache-Control "no-store" always;
    }}
    location /isolated/ {{
      add_header Content-Security-Policy "{lab_servers.frame_csp(self.vendor_source)}" always;
      add_header Cache-Control "no-store" always;
    }}
  }}
}}
""")

    def start(self) -> None:
        result = subprocess.run(self.cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError("nginx failed to start: " + result.stderr)
        for _ in range(50):
            try:
                urllib.request.urlopen(self.origin + "/canary.gif", timeout=1).read()
                return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("nginx did not come up")

    def stop(self) -> None:
        subprocess.run(self.cmd + ["-s", "quit"], capture_output=True)
        pid = self.prefix / "nginx.pid"
        for _ in range(50):
            if not pid.exists():
                return
            time.sleep(0.1)

    def wait_reloaded(self) -> None:
        """nginx reload is asynchronous: old workers finish, new ones start.
        Give it a moment so verification observes the new configuration."""
        time.sleep(0.5)
