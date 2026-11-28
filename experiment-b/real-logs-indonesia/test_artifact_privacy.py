"""Fail closed if public CI reintroduces publishing real user request targets.

The frozen v3 experiment source must remain byte-identical for reproducibility.
For future scientific datasets, raw values need restricted, separately approved
handling and are not accepted as public GitHub artifact payloads.
"""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/real-logs-indonesia.yml"

class RealLogArtifactPrivacy(unittest.TestCase):
    def test_no_public_raw_review_artifact_upload(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("name: real-logs-review-sample", text)
        self.assertNotIn("path: ${{ runner.temp }}/work/review", text)
        self.assertIn("Remove raw review staging from disposable runner", text)
        self.assertIn("rm -rf \"$RUNNER_TEMP/work/review\"", text)

    def test_original_frozen_experiment_source_not_rewritten(self):
        import hashlib
        f = ROOT / "experiment-b/real-logs-indonesia/model_logs.py"
        digest = hashlib.sha256(f.read_bytes()).hexdigest()
        self.assertEqual(digest, "d1adb00b2313339fc457c19045a2753d25720c2507578a80dad807ad084b47f0")

if __name__ == "__main__":
    unittest.main()
