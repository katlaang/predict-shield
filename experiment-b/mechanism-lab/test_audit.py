"""No-network tests for four-stream audit and conservative resumption."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from audit import audit_campaign, inspect_trial, plan_fingerprint
from plan import create_plan


class CampaignAuditTests(unittest.TestCase):
    """Ensure no incomplete, misattributed, or unexecuted experiment is counted."""

    def setUp(self):
        """Construct a real manifest without generating synthetic outcomes."""
        self.configs, self.trials = create_plan()
        self.trial = self.trials[0]
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name)

    def record(self, kind, changes=None):
        """Create one minimal test-only data record for provenance checking."""
        t = self.trial
        value = {
            "run_id": t["run_id"], "configuration_id": t["configuration_id"],
            "partition": t["partition"], "action_id": t["action_id"],
            "repeat": t["repeat"], "initial_state_seed": t["initial_state_seed"],
            "experiment_type": "real_kafka_multijvm_lab",
            "source_commit": "a" * 40,
        }
        if kind == "pre_action":
            value.update({"oracle_features_excluded": True,
                          "model_prediction_recorded": False})
        if kind == "verification":
            value["outcome"] = "INDETERMINATE"
        if kind == "operations":
            value.update({"observed_requests": 20, "failed_requests": 3})
        if kind == "oracle":
            value.update({"oracle_role": "separate_process_admin_plus_direct_probe",
                          "after": {"inventory_complete": True,
                                    "all_revoked_access_denied": False}})
        value.update(changes or {})
        path = self.output / kind / (t["run_id"] + ".json")
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def test_empty_manifest_not_claimed_complete(self):
        """A configured plan is not measured data."""
        result = audit_campaign(self.configs, self.trials, self.output)
        self.assertEqual(result["complete"], 0)
        self.assertEqual(result["missing"], 1200)
        self.assertFalse(result["ready_for_training"])
        self.assertEqual(len(result["plan_sha256"]), 64)

    def test_complete_trial_not_full_campaign(self):
        """Four valid records establish only one completed trial."""
        for kind in ("pre_action", "verification", "operations", "oracle"):
            self.record(kind)
        self.assertEqual(inspect_trial(self.trial, self.output)[0], "complete")
        result = audit_campaign(self.configs, self.trials, self.output)
        self.assertEqual(result["complete"], 1)
        self.assertEqual(result["missing"], 1199)
        self.assertFalse(result["ready_for_training"])

    def test_partial_writes_fail_audit(self):
        """A process crash between separate record writes cannot be called success."""
        self.record("pre_action")
        self.assertEqual(inspect_trial(self.trial, self.output)[0], "partial")

    def test_wrong_source_commit_invalidates_trial(self):
        """All four observation streams must carry identical source provenance."""
        for kind in ("pre_action", "verification", "operations", "oracle"):
            self.record(kind)
        self.record("operations", {"source_commit": "b" * 40})
        self.assertEqual(inspect_trial(self.trial, self.output)[0], "invalid")

    def test_bad_assurance_verdict_invalidates_trial(self):
        """Gateway-only probes cannot establish verified full scope."""
        for kind in ("pre_action", "verification", "operations", "oracle"):
            self.record(kind)
        self.record("verification", {"outcome": "VERIFIED"})
        self.assertEqual(inspect_trial(self.trial, self.output)[0], "invalid")

    def test_extra_unknown_record_fails_readiness(self):
        """The plan must account for every stored research run ID."""
        (self.output / "oracle").mkdir()
        (self.output / "oracle" / "unregistered.json").write_text("{}")
        result = audit_campaign(self.configs, self.trials, self.output)
        self.assertEqual(result["unexpected_files"], 1)
        self.assertFalse(result["ready_for_training"])

    def test_plan_fingerprint_changes_on_split_modification(self):
        """The protocol digest detects a changed registration, even without results."""
        original = plan_fingerprint(self.configs, self.trials)
        changed = [dict(item) for item in self.configs]
        changed[0]["partition"] = "altered"
        self.assertNotEqual(plan_fingerprint(changed, self.trials), original)


if __name__ == "__main__":
    unittest.main()
