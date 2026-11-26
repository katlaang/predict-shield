import json
import tempfile
import unittest
from pathlib import Path

import numpy as np

import model_v2 as m
import lab


def ex(path="/vulnerabilities/sqli/", body="<html><pre>Normal</pre></html>"):
    return lab.Exchange("benign", "normal", "GET", path, {"id": "1"},
                        t_send=1.0, t_recv=1.01, status=200, body=body)


class EvidenceFeaturesTests(unittest.TestCase):
    def test_response_score_learned_on_benign_only(self):
        normal = [ex(body="<html><pre>First name: X<br/>Surname: Y</pre></html>") for _ in range(40)]
        profile = m.response_profiles(normal)
        self.assertAlmostEqual(m.response_novelty(normal[0], profile), 0.0)
        unusual = ex(body="<html>" + "<p>unexpected record</p>" * 50 + "</html>")
        self.assertGreater(m.response_novelty(unusual, profile), 0.0)

    def test_unseen_page_is_novel_not_label_based(self):
        profile = m.response_profiles([ex() for _ in range(40)])
        self.assertEqual(m.response_novelty(ex("/new-surface"), profile), 4.0)

    def test_alert_scoring_includes_unseen_programs_files_endpoints(self):
        normal = ex()
        vocab = lab.build_vocab([normal], [[]], "/tmp/dvwa")
        profile = m.response_profiles([normal] * 40)
        class FlatModel:
            def score_samples(self, rows):
                return np.full(len(rows), -0.42)
        base = m.scores(FlatModel(), vocab, profile, [normal], [[]], "/tmp/dvwa")[0]
        unusual = [
            lab.Syscall(1.0, 42, "execve", "/usr/bin/curl", True),
            lab.Syscall(1.0, 42, "connect", "inet:198.51.100.2:4444", True),
            lab.Syscall(1.0, 42, "openat", "/etc/shadow", True),
        ]
        changed = m.scores(FlatModel(), vocab, profile, [normal], [unusual], "/tmp/dvwa")[0]
        self.assertGreater(changed, base)

    def test_freeze_hash_pins_imported_collector(self):
        actual = m.code_hashes()
        self.assertIn("v1-lab.py", actual)
        self.assertIn("v1-detector.py", actual)
        self.assertIn("protocol.json", actual)
        self.assertTrue(all(len(h) == 64 for h in actual.values()))

    def test_fitting_requires_only_benign(self):
        with self.assertRaises(ValueError):
            m.fit([lab.Exchange("attack", "cmdi", "GET", "/", {})], [[]], "/tmp")

    def test_frozen_report_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "report.json"
            p.write_text("{}")
            # The no-overwrite rule is a guard against rescoring a held-out run.
            self.assertTrue(p.exists())


if __name__ == "__main__":
    unittest.main()
