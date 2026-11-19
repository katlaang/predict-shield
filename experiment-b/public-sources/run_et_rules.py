"""The Emerging Threats open ruleset in the lab's Suricata.

1. `suricata-update` downloads ET Open for the installed Suricata version
   into a private data directory and merges it into one rules file; the
   file's SHA-256 and rule counts are recorded.
2. Suricata loads that file plus the lab's own rule and captures loopback.
3. Lab traffic reproduces the classic test trigger for a long-standing
   public rule, "GPL ATTACK_RESPONSE id check returned root" (sid
   2100498): an HTTP response containing `uid=0(root)`.
4. The alert is forwarded, signed, to the TLS intake through a registered
   mapping for that signature and host, and must be admitted.
"""
from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import re
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT / "engine" / "tests"))
sys.path.insert(0, str(ROOT / "experiment-b" / "end-to-end-chain"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

from ids_forwarder import AlertMapping, EveForwarder, Suricata  # noqa: E402
from pki_fixture import TestPKI  # noqa: E402
from predict_shield.detection_intake import RegisteredDetectionSource  # noqa: E402
from predict_shield.intake_server import DetectionIntakeServer  # noqa: E402

TEST_SID = 2100498


def update_rules(data_dir: Path) -> dict:
    data_dir.mkdir(parents=True, exist_ok=True)
    out = data_dir / "rules"
    done = subprocess.run(["suricata-update", "--data-dir", str(data_dir), "--output", str(out),
                           "--no-test", "--no-reload", "--suricata-conf", "/etc/suricata/suricata.yaml"],
                          capture_output=True, text=True, timeout=600)
    if done.returncode != 0:
        raise RuntimeError("suricata-update failed: " + done.stderr[-1500:])
    merged = out / "suricata.rules"
    text = merged.read_text(errors="replace")
    enabled = [l for l in text.splitlines() if l.startswith("alert ") or l.startswith("drop ")]
    test_rule = next((l for l in enabled if re.search(rf"\bsid:\s*{TEST_SID}\s*;", l)), None)
    sources = re.findall(r"(https://rules\.emergingthreats\.net/\S+)", done.stderr + done.stdout)
    return {"rules_file": str(merged), "sha256": hashlib.sha256(merged.read_bytes()).hexdigest(),
            "enabled_rules": len(enabled), "test_rule_enabled": test_rule is not None,
            "test_rule": test_rule, "download_urls": sorted(set(sources))}


def response_server(host: str) -> http.server.ThreadingHTTPServer:
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"uid=0(root) gid=0(root) groups=0(root)\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            return

    server = http.server.ThreadingHTTPServer((host, 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--sudo", action="store_true")
    parser.add_argument("--rules-file", type=Path,
                        help="use this rules file instead of downloading ET Open (offline mechanics check only)")
    args = parser.parse_args()
    report = {"schema": "predict-shield/et-open-rules/1"}
    if args.rules_file:
        text = args.rules_file.read_text()
        report["ruleset"] = {"rules_file": str(args.rules_file), "source": "local file, not ET Open",
                             "sha256": hashlib.sha256(args.rules_file.read_bytes()).hexdigest(),
                             "enabled_rules": sum(1 for l in text.splitlines() if l.startswith("alert ")),
                             "test_rule_enabled": f"sid:{TEST_SID};" in text.replace(" ", "")}
    else:
        report["ruleset"] = update_rules(args.workdir / "suricata-update")
        report["ruleset"]["source"] = "ET Open via suricata-update"
    if not report["ruleset"]["test_rule_enabled"]:
        raise RuntimeError(f"sid {TEST_SID} is not enabled in the downloaded ruleset")

    key = Ed25519PrivateKey.generate()
    pki = TestPKI("et-intake")
    cert, keyfile, _ = pki.issue("intake", server=True)
    admitted: list = []
    intake = DetectionIntakeServer(
        host="127.0.0.1", port=0, certfile=cert, keyfile=keyfile, client_ca_file=None,
        registry={"suricata-et": RegisteredDetectionSource(
            "suricata-et", "Suricata with ET Open",
            ed25519_public_key_hex=key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex())},
        on_admitted=admitted.append).start()
    server = response_server("127.0.0.2")
    host, port = server.server_address
    suricata = Suricata(args.workdir / "suricata", command_prefix=["sudo"] if args.sudo else None,
                        extra_rules_file=Path(report["ruleset"]["rules_file"]))
    forwarder = None
    try:
        report["suricata_version"] = suricata.start(timeout=600)
        log = (suricata.logdir / "suricata.log").read_text(errors="replace")
        loaded = re.search(r"(\d+) rules successfully loaded", log)
        report["rules_loaded_by_suricata"] = int(loaded.group(1)) if loaded else None
        forwarder = EveForwarder(
            eve_path=suricata.eve,
            mapping=AlertMapping(asset="lab-host-" + host, page_origin=None, sink_hosts=(host,),
                                 signature_ids=(TEST_SID,), either_direction=True,
                                 technique="T1059"),  # command output returned by a server
            source_id="suricata-et", private_key=key, intake_host="127.0.0.1", intake_port=intake.port,
            ca_file=pki.ca_file).start()
        started = time.monotonic()
        urllib.request.urlopen(f"http://{host}:{port}/id", timeout=10).read()
        while time.monotonic() - started < 60 and not admitted:
            time.sleep(0.5)
        report["seconds_to_admission"] = round(time.monotonic() - started, 2) if admitted else None
    finally:
        if forwarder:
            forwarder.stop()
        suricata.stop()
        server.shutdown()
        intake.stop()
    alerts = []
    if suricata.eve.exists():
        for line in suricata.eve.read_text(errors="replace").splitlines():
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if record.get("event_type") == "alert":
                alerts.append({"sid": record["alert"]["signature_id"], "signature": record["alert"]["signature"],
                               "src": record.get("src_ip"), "dest": record.get("dest_ip")})
    report["alerts"] = alerts
    report["test_rule_fired"] = any(a["sid"] == TEST_SID for a in alerts)
    report["forwarder"] = {"alerts_seen": forwarder.stats.alerts_seen if forwarder else 0,
                           "dropped": forwarder.stats.dropped if forwarder else {},
                           "posted": len(forwarder.stats.posted) if forwarder else 0}
    report["admitted"] = [{"asset": a.asset, "assertion": a.evidence.assertion, "source": a.evidence.source}
                          for a in admitted]
    report["intake_rejections"] = len(intake.rejections)
    args.output.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print(json.dumps({k: report[k] for k in ("test_rule_fired", "rules_loaded_by_suricata", "seconds_to_admission",
                                             "intake_rejections")} | {"enabled_rules": report["ruleset"]["enabled_rules"],
                                                                      "admitted": len(admitted)}, indent=1))


if __name__ == "__main__":
    main()
