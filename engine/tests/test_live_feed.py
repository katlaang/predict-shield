import json
import unittest
import urllib.error
import urllib.request

from predict_shield.live_feed import LiveFeedServer, LiveState


class LiveFeedTests(unittest.TestCase):
    def setUp(self):
        self.state = LiveState()
        self.server = LiveFeedServer(self.state).start()

    def tearDown(self):
        self.server.stop()

    def get(self, path):
        with urllib.request.urlopen(self.server.url.rstrip("/") + path, timeout=5) as response:
            return response.status, response.headers, response.read()

    def test_state_reflects_updates_as_they_happen(self):
        self.state.incident("case-1", stage="detected")
        _, headers, body = self.get("/api/state")
        first = json.loads(body)
        self.assertEqual(first["incidents"][0]["stage"], "detected")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.state.incident("case-1", stage="done", final_status="APPLIED_VERIFIED")
        second = json.loads(self.get("/api/state")[2])
        self.assertEqual(second["incidents"][0]["final_status"], "APPLIED_VERIFIED")
        self.assertGreater(second["sequence"], first["sequence"])

    def test_the_feed_is_read_only(self):
        request = urllib.request.Request(self.server.url + "api/state", data=b"{}", method="POST")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(ctx.exception.code, 405)

    def test_the_page_is_served_under_a_csp_without_inline_script(self):
        _, headers, _ = self.get("/")
        self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
        self.assertNotIn("unsafe-inline'; connect", headers["Content-Security-Policy"].split("script-src")[1][:30])

    def test_binding_beyond_loopback_needs_an_explicit_flag(self):
        with self.assertRaises(ValueError):
            LiveFeedServer(LiveState(), host="0.0.0.0")

    def test_event_history_is_bounded(self):
        for i in range(700):
            self.state.event("tick", n=i)
        self.assertEqual(len(self.state.snapshot()["events"]), 100)


if __name__ == "__main__":
    unittest.main()
