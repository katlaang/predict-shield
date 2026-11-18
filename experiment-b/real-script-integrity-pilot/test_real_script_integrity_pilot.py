"""Fast contracts for the lab servers and the pilot's own assertion
wiring, runnable without launching a real browser, so CI can validate
these before paying for the real Playwright run."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab_servers

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "engine"))
from predict_shield.script_integrity import FetchRejected, RegisteredScript, fetch_script_observation


class LabServerTests(unittest.TestCase):
    def test_vendor_server_serves_the_current_script_body(self):
        state = lab_servers.VendorState()
        vendor = lab_servers.start_server("127.0.0.1", lab_servers.make_vendor_handler(state))
        try:
            host, port = vendor.server_address
            script = RegisteredScript(script_id="x", url=f"http://{host}:{port}/widget.js",
                                      trusted_sha384=("a" * 96,))
            observation = fetch_script_observation(script, (host,))
            self.assertEqual(observation.status_code, 200)
        finally:
            vendor.shutdown()

    def test_vendor_server_rejects_an_unregistered_host(self):
        state = lab_servers.VendorState()
        vendor = lab_servers.start_server("127.0.0.1", lab_servers.make_vendor_handler(state))
        try:
            host, port = vendor.server_address
            script = RegisteredScript(script_id="x", url=f"http://{host}:{port}/widget.js",
                                      trusted_sha384=("a" * 96,))
            with self.assertRaises(FetchRejected):
                fetch_script_observation(script, ("some-other-host",))
        finally:
            vendor.shutdown()

    def test_malicious_script_body_differs_from_good_body(self):
        good = lab_servers.GOOD_SCRIPT
        malicious = lab_servers.malicious_script("http://127.0.0.2:9999")
        self.assertNotEqual(good, malicious)
        self.assertIn(b"127.0.0.2:9999", malicious)

    def test_benign_update_differs_from_good_but_keeps_behavior_marker(self):
        self.assertNotEqual(lab_servers.GOOD_SCRIPT, lab_servers.BENIGN_UPDATE_SCRIPT)
        self.assertIn(b"checkout-button", lab_servers.BENIGN_UPDATE_SCRIPT)

    def test_sink_server_records_every_hit(self):
        sink_state = lab_servers.SinkState()
        sink = lab_servers.start_server("127.0.0.2", lab_servers.make_sink_handler(sink_state))
        try:
            import urllib.request
            host, port = sink.server_address
            urllib.request.urlopen(f"http://{host}:{port}/exfil?c=test", timeout=5).read()
            self.assertIn("/exfil?c=test", sink_state.hits)
        finally:
            sink.shutdown()


if __name__ == "__main__":
    unittest.main()
