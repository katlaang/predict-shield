"""Synthetic contract tests, not evidence of new physical experiments."""
import json
import tempfile
import unittest
from pathlib import Path

from new_configuration_pilot import load_new_paired
from plan import create_plan


def provision(root, *, alter=None):
    cfg, trials = create_plan(seed=20261129, version="v3.1")
    plan = root / "plan"
    plan.mkdir()
    (plan / "configurations.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in cfg))
    (plan / "trials.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in trials))
    chosen = next(x for x in cfg if x["partition"] == "test")
    ids = [t for t in trials if t["configuration_id"] == chosen["configuration_id"]]
    records = root / "records"
    for kind in ("pre_action", "operations", "verification", "oracle"):
        (records / kind).mkdir(parents=True)
    for trial in ids:
        base = {k: trial[k] for k in (
            "run_id", "configuration_id", "action_id", "repeat",
            "partition", "initial_state_seed")}
        base.update(source_commit="a"*40, experiment_type="real_kafka_multijvm_lab")
        pre = dict(base,
            features={"cache_ttl_ms": chosen["cache_ttl_ms"],
                      "requested_rps": chosen["requested_rps"],
                      "visible_enforcement_processes": chosen["visible_enforcement_processes"]},
            experimental_conditions={"fault_mode": chosen["fault_mode"]},
            routing_profile=chosen["routing_profile"],
            model_prediction_recorded=False, oracle_features_excluded=True,
            decision_policy_metadata={"restart_permitted": chosen["restart_permitted"],
                                      "absolute_error_budget_requests": 25},
            external_deny_observations=[{"http_status": 200}, {"http_status": 403}],
            operator_observations=[
                {"node": node, "observed": True,
                 "operator_schema": "operator_pre_action_v2",
                 "applied_revision": 3, "cache_age_ms": 100,
                 "legitimate_service_latency_ms": 15,
                 "handled_events": 4, "refresh_failed": False,
                 "scheduled_callbacks_pending": 0}
                for node in ("enforcer-a", "enforcer-b", "enforcer-c", "enforcer-hidden")])
        ops = dict(base, failed_requests=5, observed_requests=100)
        oracle = dict(base, oracle_role="separate_process_admin_plus_direct_probe",
                      after={"inventory_complete": True, "all_revoked_access_denied": True})
        ver = dict(base, timed_gateway_exposure={
            "method": "monotonic_http_step_integral", "valid_probe_count": 3,
            "exposure_fraction_lower_bound": 0.1, "exposure_fraction_upper_bound": 0.2})
        by_kind = {"pre_action": pre, "operations": ops,
                   "oracle": oracle, "verification": ver}
        if alter and alter[0] in by_kind and trial is ids[0]:
            alter[1](by_kind[alter[0]])
        for name, record in by_kind.items():
            (records / name / (trial["run_id"] + ".json")).write_text(json.dumps(record))
    return plan, records


class NewPhysicalPilotAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_new_config_is_selected_before_outcomes(self):
        plan, records = provision(self.root)
        rows, meta = load_new_paired(plan, records)
        self.assertEqual(len(rows), 12)
        self.assertEqual(len({r["group"] for r in rows}), 1)
        self.assertEqual(len({r["repeat"] for r in rows}), 3)
        self.assertEqual(meta["trial_count"], 12)
        self.assertEqual(meta["pre_registered_seed"], 20261129)
        self.assertEqual(set(r["action"] for r in rows),
                         {"resync_policy", "restart_enforcer", "gateway_restrict", "monitor_only"})
        self.assertTrue(all("fault_mode" not in r["pre_action"] for r in rows))

    def test_incomplete_outcome_refused(self):
        plan, records = provision(self.root)
        victim = next((records/"oracle").glob("*.json"))
        victim.unlink()
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            load_new_paired(plan, records)

    def test_oracle_truth_cannot_be_missing(self):
        plan, records = provision(self.root, alter=("oracle", lambda r:
            r["after"].update(all_revoked_access_denied=None)))
        with self.assertRaisesRegex(ValueError, "independent post-action"):
            load_new_paired(plan, records)

    def test_experiment_never_accepts_wrong_partition(self):
        plan, records = provision(self.root, alter=("pre_action",
            lambda r: r.update(partition="train")))
        with self.assertRaisesRegex(ValueError, "partition"):
            load_new_paired(plan, records)

    def test_preaction_fault_truth_rejected(self):
        plan, records = provision(self.root, alter=("pre_action",
            lambda r: r["features"].update(fault_mode="consumer_paused")))
        with self.assertRaisesRegex(ValueError, "Hidden fault"):
            load_new_paired(plan, records)

    def test_source_commit_mismatch_rejected(self):
        plan, records = provision(self.root, alter=("operations",
            lambda r: r.update(source_commit="b"*40)))
        with self.assertRaisesRegex(ValueError, "source commits"):
            load_new_paired(plan, records)

    def test_no_measured_benign_denominator_refused(self):
        plan, records = provision(self.root, alter=("operations",
            lambda r: r.update(observed_requests=0)))
        with self.assertRaisesRegex(ValueError, "denominator"):
            load_new_paired(plan, records)

    def test_original_historical_seed_is_rejected(self):
        plan, records = provision(self.root)
        configs, trials = create_plan(seed=20261121, version="v3.1")
        (plan / "configurations.jsonl").write_text(
            "".join(json.dumps(row)+"\n" for row in configs))
        (plan / "trials.jsonl").write_text(
            "".join(json.dumps(row)+"\n" for row in trials))
        with self.assertRaisesRegex(ValueError, "differs from newly registered"):
            load_new_paired(plan, records)


    def test_absent_operator_telemetry_fails_admission(self):
        plan, records = provision(self.root, alter=("pre_action",
            lambda r: r.update(operator_observations=[])))
        with self.assertRaisesRegex(ValueError, "Incomplete v2 operator telemetry"):
            load_new_paired(plan, records)

    def test_legacy_schema_fails_admission(self):
        plan, records = provision(self.root, alter=("pre_action",
            lambda r: r["operator_observations"][0].update(
                operator_schema="operator_pre_action")))
        with self.assertRaisesRegex(ValueError, "Incomplete v2 operator telemetry"):
            load_new_paired(plan, records)

if __name__ == "__main__":
    unittest.main()
