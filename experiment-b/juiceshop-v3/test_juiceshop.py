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
