"""Run the OTRF replay end to end: pinned public datasets, registered rules,
signed detections, the TLS intake server, the re-verification scheduler."""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import ssl
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT / "engine" / "tests"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

from otrf_replay import replay  # noqa: E402
from pki_fixture import TestPKI  # noqa: E402
from predict_shield.detection_intake import RegisteredDetectionSource  # noqa: E402
from predict_shield.intake_server import DetectionIntakeServer  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((HERE / "sources.json").read_text())
    key = Ed25519PrivateKey.generate()
    pki = TestPKI("otrf-intake")
    cert, keyfile, _ = pki.issue("intake", server=True)
    admitted: list = []
    registry = {"otrf-replay": RegisteredDetectionSource(
        "otrf-replay", "OTRF Security-Datasets replay",
        ed25519_public_key_hex=key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex())}
    server = DetectionIntakeServer(host="127.0.0.1", port=0, certfile=cert, keyfile=keyfile, client_ca_file=None,
                                   registry=registry, on_admitted=admitted.append).start()
    context = ssl.create_default_context(cafile=pki.ca_file)

    sent: list = []

    def post(envelope: dict) -> int:
        sent.append(envelope)
        conn = http.client.HTTPSConnection("127.0.0.1", server.port, context=context, timeout=10)
        conn.request("POST", "/v1/detections", body=json.dumps(envelope).encode(),
                     headers={"Content-Type": "application/json"})
        status = conn.getresponse().status
        conn.close()
        return status

    try:
        report = replay(manifest, post=post, private_key=key, admitted=admitted)
        # Re-sending an envelope already admitted must be refused: the
        # intake's replay guard is part of what this feed exercises.
        before = len(admitted)
        report["resent_envelope_status"] = post(sent[0])
        report["resent_envelope_admitted"] = len(admitted) > before
        report["intake_rejections"] = len(server.rejections)
    finally:
        server.stop()
    report["schema"] = "predict-shield/otrf-replay/1"
    report["sources_json_sha256"] = hashlib.sha256((HERE / "sources.json").read_bytes()).hexdigest()
    args.output.write_text(json.dumps(report, indent=1, sort_keys=True, default=str) + "\n")
    print(json.dumps(report["summary"], indent=1, sort_keys=True))
    for d in report["datasets"]:
        print(d["id"], d["title"], d["labels"], "hits", d["hits_by_rule"], "admitted", d["admitted"],
              "due", d["scheduler_due_after_admission"])


if __name__ == "__main__":
    main()
