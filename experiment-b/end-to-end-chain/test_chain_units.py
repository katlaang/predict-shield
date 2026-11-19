"""Unit tests for the chain lab's IDS forwarding. The full chain runs in CI
against real nginx, Chromium and Suricata (end-to-end-chain.yml)."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "engine"))
sys.path.insert(0, str(HERE.parents[1] / "engine" / "tests"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

from ids_forwarder import AlertMapping, EveForwarder, alert_to_detection  # noqa: E402
from pki_fixture import TestPKI  # noqa: E402
from predict_shield.detection_intake import RegisteredDetectionSource  # noqa: E402
from predict_shield.intake_server import DetectionIntakeServer  # noqa: E402

MAPPING = AlertMapping(asset="lab-checkout-page", page_origin="http://127.0.0.1:8080", sink_hosts=("127.0.0.2",))


def alert(**overrides):
    base = {"timestamp": "2026-11-18T16:52:32.751558-0600", "flow_id": 1, "tx_id": 0, "event_type": "alert",
            "dest_ip": "127.0.0.2", "alert": {"signature_id": 9900001, "severity": 1},
            "http": {"hostname": "127.0.0.2", "http_refer": "http://127.0.0.1:8080/page.html"}}
    base.update(overrides)
    return base


class AlertMappingTests(unittest.TestCase):
    def test_a_registered_alert_maps_to_the_page(self):
        event, why = alert_to_detection(alert(), MAPPING, "suricata-lab")
        self.assertEqual(why, "mapped")
        self.assertEqual((event.asset, event.technique, event.confidence), ("lab-checkout-page", "T1041", 0.9))
        self.assertEqual(event.observed_at.utcoffset().total_seconds(), -6 * 3600)

    def test_alerts_outside_the_registered_mapping_are_dropped(self):
        cases = {
            "signature not registered for forwarding": alert(alert={"signature_id": 1, "severity": 1}),
            "destination is not a registered sink": alert(dest_ip="10.0.0.9", http={"hostname": "x",
                                                         "http_refer": "http://127.0.0.1:8080/"}),
            "referrer is not the registered page": alert(http={"hostname": "127.0.0.2",
                                                               "http_refer": "http://127.0.0.1:9999/"}),
            "not an alert": alert(event_type="flow"),
        }
        for reason, record in cases.items():
            event, why = alert_to_detection(record, MAPPING, "suricata-lab")
            self.assertIsNone(event)
            self.assertEqual(why, reason)


class ForwarderTests(unittest.TestCase):
    def test_forwarded_alerts_are_admitted_once_and_partial_lines_wait(self):
        from datetime import datetime, timezone
        key = Ed25519PrivateKey.generate()
        pki = TestPKI("fwd")
        cert, keyfile, _ = pki.issue("intake", server=True)
        admitted = []
        registry = {"suricata-lab": RegisteredDetectionSource(
            "suricata-lab", "Suricata", ed25519_public_key_hex=key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex())}
        server = DetectionIntakeServer(host="127.0.0.1", port=0, certfile=cert, keyfile=keyfile, client_ca_file=None,
                                       registry=registry, on_admitted=admitted.append).start()
        try:
            eve = Path(tempfile.mkdtemp()) / "eve.json"
            eve.write_text("")
            fwd = EveForwarder(eve_path=eve, mapping=MAPPING, source_id="suricata-lab", private_key=key,
                               intake_host="127.0.0.1", intake_port=server.port, ca_file=pki.ca_file)
            now = datetime.now(timezone.utc).isoformat()
            line = json.dumps(alert(timestamp=now))
            with eve.open("a") as handle:
                handle.write(line[:40])
            fwd.poll_once()
            self.assertEqual(fwd.stats.alerts_seen, 0)
            with eve.open("a") as handle:
                handle.write(line[40:] + "\n" + json.dumps(alert(timestamp=now, flow_id=2, dest_ip="10.9.9.9",
                             http={"hostname": "x", "http_refer": ""})) + "\n")
            fwd.poll_once()
            self.assertEqual(fwd.stats.alerts_seen, 2)
            self.assertEqual([p["status"] for p in fwd.stats.posted], [202])
            self.assertEqual(len(admitted), 1)
            fwd.poll_once()
            self.assertEqual(len(admitted), 1)
        finally:
            server.stop()


if __name__ == "__main__":
    unittest.main()
