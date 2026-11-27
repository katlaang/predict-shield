import json
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
import model_js as m  # noqa: E402


class RowTests(unittest.TestCase):
    def test_norm_path(self):
        self.assertEqual(m.norm_path("/rest/products/12/reviews?x=1"), "/rest/products/N/reviews")
        self.assertEqual(m.norm_path("/rest/track-order/5267-f9cd5882f54c75a3"), "/rest/track-order/X")
        self.assertEqual(m.norm_path("/rest/products/search"), "/rest/products/search")

    def test_fields_query_and_json(self):
        rec = {"path": "/a?q=apple+juice&n=2", "body": json.dumps({"email": "x@y.z", "q": {"id": 3}, "l": [1, 2]}),
               "content_type": "application/json"}
        f = m.fields(rec)
        self.assertEqual(f["q"], "apple juice")
        self.assertEqual(f["body.email"], "x@y.z")
        self.assertEqual(f["body.q.id"], "3")
        self.assertIn("body.l[]", f)

    def test_labels_never_count_unlabelled_as_benign(self):
        recs = [{"source": "benign", "plugin": ""}, {"source": "attack", "plugin": "40018"},
                {"source": "attack", "plugin": "", "user_agent": "sqlmap/1.9"}, {"source": "attack", "plugin": ""}]
        self.assertEqual(m.label(recs, {}), ["benign", "zap:40018", "sqlmap", "unknown"])

    def test_family_rule(self):
        self.assertTrue(m.family("SQL Injection - MySQL").startswith("sqli"))
        self.assertTrue(m.family("Path Traversal").startswith("lfi"))
        self.assertTrue(m.family("Cross Site Scripting (Reflected)").startswith("unseen"))

    def test_confirmed_matching(self):
        recs = [{"path": "/rest/products/search?q=PAYLOADX", "body": ""}, {"path": "/rest/products/search?q=other", "body": ""}]
        labels = ["zap:40018", "zap:40018"]
        alerts = [{"risk": "High", "attack": "PAYLOADX", "pluginId": "40018", "url": "http://h/rest/products/search?q=PAYLOADX"}]
        self.assertEqual(list(m.confirmed(recs, labels, alerts)), [True, False])


class Upstream(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        Upstream.seen.append(dict(self.headers))
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ProxyTests(unittest.TestCase):
    def test_label_recorded_and_header_stripped(self):
        up = HTTPServer(("127.0.0.1", 0), Upstream)
        threading.Thread(target=up.serve_forever, daemon=True).start()
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "p.jsonl"
            p = subprocess.Popen([sys.executable, str(HERE / "serial_proxy.py"), str(log), str(up.server_port),
                                  "benign=19501", "attack=19502"], stdout=subprocess.PIPE, text=True)
            try:
                p.stdout.readline()
                req = urllib.request.Request("http://127.0.0.1:19502/x?q=1", headers={"X-ZAP-Scan-ID": "40018"})
                self.assertEqual(urllib.request.urlopen(req, timeout=10).status, 200)
                urllib.request.urlopen("http://127.0.0.1:19501/y", timeout=10).read()
                time.sleep(0.3)
                recs = [json.loads(l) for l in log.read_text().splitlines()]
                self.assertEqual([(r["source"], r["plugin"]) for r in recs], [("attack", "40018"), ("benign", "")])
                self.assertTrue(all("X-ZAP-Scan-ID" not in h for h in Upstream.seen))
                self.assertTrue(all(r["t_recv"] >= r["t_send"] for r in recs))
            finally:
                p.terminate()
                up.shutdown()


if __name__ == "__main__":
    unittest.main()


class V31Tests(unittest.TestCase):
    def test_cauchy_lets_one_rare_signal_alert(self):
        import numpy as np
        cal = np.column_stack([np.zeros(999), np.random.default_rng(0).random(999), np.random.default_rng(1).random(999),
                               np.random.default_rng(2).random(999)])
        rare = np.array([[5.0, 0.2, 0.2, 0.2]])
        common = np.array([[0.0, 0.2, 0.2, 0.2]])
        self.assertEqual(m.cauchy(common, cal)[0], 0.0)          # nothing unusual: exactly zero
        self.assertGreater(m.cauchy(rare, cal)[0], 50.0)          # one never-seen signal dominates
        mixed = np.array([[5.0, 0.0, 0.0, 0.0]])                  # others at p = 1 do not cancel it
        self.assertAlmostEqual(m.cauchy(mixed, cal)[0], m.cauchy(rare, cal)[0])

    def test_zap_exact_match(self):
        import confirm
        recs = [{"source": "attack", "method": "GET", "path": "/rest/products/search?q=X1", "body": ""},
                {"source": "attack", "method": "GET", "path": "/rest/products/search?q=X2", "body": ""}]
        msgs = [{"pluginId": "40018", "risk": "High", "family": "sqli",
                 "requestHeader": "GET http://127.0.0.1:9002/rest/products/search?q=X2 HTTP/1.1\r\nHost: x", "requestBody": ""}]
        self.assertEqual(confirm.zap_confirmed(recs, msgs, {"40018"}), {1: "sqli"})
        self.assertEqual(confirm.zap_confirmed(recs, msgs, {"10202"}), {})

    def test_challenge_window(self):
        import confirm
        recs = [{"source": "attack", "t_send": 1000.0, "t_recv": 1000.2}, {"source": "benign", "t_send": 1000.3, "t_recv": 1000.4}]
        ch = [{"solved": True, "category": "Injection", "updatedAt": "1970-01-01T00:16:40.100Z"},
              {"solved": True, "category": "XSS", "updatedAt": "1970-01-01T00:16:40.350Z"}]
        self.assertEqual(confirm.challenge_confirmed(recs, ch), {0: "challenge: Injection"})

    def test_sqlmap_payloads(self):
        import confirm
        log = "Parameter: q (GET)\n    Type: boolean-based blind\n    Payload: q=apple' AND 1=1-- abcd\n"
        p = confirm.sqlmap_payloads(log)
        recs = [{"path": "/s?q=apple%27%20AND%201%3D1--%20abcd", "body": ""}]
        self.assertEqual(confirm.sqlmap_confirmed(recs, ["sqlmap"], ["apple' AND 1=1-- abcd"]), {0: "sqli (seen in DVWA)"})
        self.assertEqual(p, ["q=apple' AND 1=1-- abcd"])
