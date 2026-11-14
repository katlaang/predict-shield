"""Synthetic fixture tests for audited exporter, NOT laboratory evidence."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from export_v31_pilot import export, PILOT_SCHEMA
from decision_eval import ACTIONS
from audit import STREAMS

COMMIT = "a" * 40


class AuditedExporterTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for stream in STREAMS:
            (self.root / stream).mkdir()
        self.configs = []
        self.trials = []
        for index in range(3):
            cid = f"v31-pilot-{index:03d}"
            mode = "consumer_paused" if index == 0 else "loss"
            config = {
                "schema": PILOT_SCHEMA, "configuration_id": cid,
                "partition": "pilot", "fault_mode": mode,
                "fault_target": "enforcer-b", "restart_permitted": index != 1,
                "absolute_error_budget_requests": 25,
                "complexity_stratum": "PARTIAL_VISIBILITY" if index == 0 else "SIMPLE",
            }
            self.configs.append(config)
            for repeat in (0, 1):
                for action in ACTIONS:
                    run_id = f"trial-{index}-{repeat}-{action}"
                    trial = {"run_id": run_id, "configuration_id": cid,
                             "partition": "pilot", "repeat": repeat,
                             "action_id": action,
                             "initial_state_seed": 100 + repeat,
                             "execution_status": "PLANNED_NOT_EXECUTED"}
                    self.trials.append(trial)
                    base = dict(run_id=run_id, source_commit=COMMIT)
                    records = {
                        "pre_action": {**base,"oracle_features_excluded": True,
                            "decision_policy_metadata":{
                                "restart_permitted": config["restart_permitted"],
                                "absolute_error_budget_requests":25},
                            "experimental_conditions":{"fault_mode":mode,
                                                       "fault_target":"enforcer-b"},
                            "complexity_stratum":config["complexity_stratum"]},
                        "verification": {**base,"verification_did_not_read_oracle":True,
                            "timed_gateway_exposure":{"valid_probe_count":5,
                                                       "exposure_fraction_upper_bound":0.1}},
                        "operations": {**base,"failed_requests":1,"observed_requests":100},
                        "oracle": {**base,"actual_revoked_access_denied":False,
                            "before":{"all_revoked_access_denied":False},
                            "physical_fault_evidence":{
                                "listener_pause_physically_observed":True,
                                "target_http_status":200} if mode=="consumer_paused" else None},
                    }
                    for stream,payload in records.items():
                        (self.root/stream/(run_id+".json")).write_text(json.dumps(payload))

    @patch("export_v31_pilot.inspect_trial", return_value=("complete", "validated"))
    def test_exports_only_grouped_paired_observed_costs(self, audit):
        rows=export(self.configs,self.trials,self.root)
        self.assertEqual(len(rows),6)
        self.assertEqual(audit.call_count,24)
        self.assertEqual(rows[0]["eligible_actions"],list(ACTIONS))
        self.assertNotIn("restart_enforcer",rows[2]["eligible_actions"])
        self.assertAlmostEqual(rows[0]["action_costs"]["resync_policy"],0.31)
        self.assertNotIn("physical_fault_evidence",rows[0])

    @patch("export_v31_pilot.inspect_trial", return_value=("missing","not executed"))
    def test_missing_physical_replay_fails(self, audit):
        with self.assertRaisesRegex(ValueError,"Unverified physical replay"):
            export(self.configs,self.trials,self.root)

    @patch("export_v31_pilot.inspect_trial", return_value=("complete","validated"))
    def test_consumer_pause_requires_privileged_physical_evidence(self, audit):
        t=self.trials[0]
        path=self.root/"oracle"/(t["run_id"]+".json")
        payload=json.loads(path.read_text())
        payload["physical_fault_evidence"]=None
        path.write_text(json.dumps(payload))
        with self.assertRaisesRegex(ValueError,"physical consumer-pause witness"):
            export(self.configs,self.trials,self.root)

    @patch("export_v31_pilot.inspect_trial", return_value=("complete","validated"))
    def test_unknown_extra_record_rejected(self, audit):
        (self.root/"oracle"/"fake.json").write_text("{}")
        with self.assertRaisesRegex(ValueError,"Unregistered trial"):
            export(self.configs,self.trials,self.root)


if __name__ == "__main__":
    unittest.main()
