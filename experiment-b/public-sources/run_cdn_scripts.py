"""Real public CDN files: two-publisher attestation, the production hash
probe against the live CDN, and real-browser SRI enforcement."""
from __future__ import annotations

import argparse
import http.server
import json
import sys
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "engine"))

from cdn_scripts import CdnFile, attest, monitor, register  # noqa: E402
from predict_shield.script_integrity import RegisteredScript  # noqa: E402

ENTRIES = (
    CdnFile("jquery", "3.7.1", "jquery.min.js", "jquery", "/dist/jquery.min.js", "jQuery"),
    CdnFile("jquery", "3.7.0", "jquery.min.js", "jquery", "/dist/jquery.min.js", "jQuery"),
    CdnFile("lodash.js", "4.17.21", "lodash.min.js", "lodash", "/lodash.min.js", "_"),
)

PAGE = """<!doctype html><html><head><meta charset="utf-8"></head><body>
<script src="{url}" integrity="{sri}" crossorigin="anonymous"></script>
</body></html>"""


def serve_pages(pages: dict[str, str]) -> http.server.ThreadingHTTPServer:
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = pages.get(self.path)
            if body is None:
                self.send_response(404)
                self.end_headers()
                return
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def browser_sri(trials: dict[str, tuple[CdnFile, str]]) -> dict:
    from playwright.sync_api import sync_playwright
    pages = {f"/{name}.html": PAGE.format(url=entry.cdnjs_url, sri=sri) for name, (entry, sri) in trials.items()}
    server = serve_pages(pages)
    origin = "http://127.0.0.1:%d" % server.server_address[1]
    out = {}
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            for name, (entry, sri) in trials.items():
                page = browser.new_page()
                messages = []
                page.on("console", lambda m: messages.append(m.text))
                page.goto(f"{origin}/{name}.html", wait_until="load")
                page.wait_for_timeout(500)
                ran = page.evaluate(f"typeof window[{json.dumps(entry.browser_global)}] !== 'undefined'")
                out[name] = {"url": entry.cdnjs_url, "integrity": sri, "library_ran": ran,
                             "integrity_error_reported": any("integrity" in m.lower() for m in messages)}
                page.close()
            browser.close()
    finally:
        server.shutdown()
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = {"schema": "predict-shield/public-cdn-scripts/1", "attestations": {}, "monitoring": {}}
    attestations = {}
    for entry in ENTRIES:
        a = attest(entry)
        key = f"{entry.library}@{entry.version}"
        attestations[key] = a
        report["attestations"][key] = {
            "cdnjs_url": entry.cdnjs_url, "jsdelivr_url": entry.jsdelivr_url, "cdnjs_sri": a.cdnjs_sri,
            "jsdelivr_sha256": a.jsdelivr_sha256_b64, "cdnjs_bytes_match_cdnjs_sri": a.cdnjs_bytes_match_cdnjs_sri,
            "jsdelivr_bytes_match_jsdelivr_hash": a.jsdelivr_bytes_match_jsdelivr_hash,
            "files_identical": a.files_identical, "accepted": a.accepted, "registered_sha384": a.sha384}
    for key, a in attestations.items():
        report["monitoring"][key] = monitor(register(a))
    # A script registered with one version's trusted hash, served the other
    # version: the probe must report NOT VERIFIED.
    new, old = attestations["jquery@3.7.1"], attestations["jquery@3.7.0"]
    swapped = RegisteredScript(script_id="cdnjs:jquery-registered-3.7.0-served-3.7.1",
                               url=new.entry.cdnjs_url, trusted_sha384=(old.sha384,))
    report["monitoring"]["version_changed_under_registration"] = monitor(swapped)
    report["browser_sri"] = browser_sri({
        "jquery-3.7.1-published-sri": (new.entry, new.cdnjs_sri),
        "jquery-3.7.1-with-3.7.0-sri": (new.entry, old.cdnjs_sri),
        "lodash-4.17.21-published-sri": (attestations["lodash.js@4.17.21"].entry,
                                         attestations["lodash.js@4.17.21"].cdnjs_sri),
    })
    report["summary"] = {
        "all_attested": all(v["accepted"] for v in report["attestations"].values()),
        "monitoring": {k: v["outcome"] for k, v in report["monitoring"].items()},
        "browser": {k: v["library_ran"] for k, v in report["browser_sri"].items()},
    }
    args.output.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print(json.dumps(report["summary"], indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
