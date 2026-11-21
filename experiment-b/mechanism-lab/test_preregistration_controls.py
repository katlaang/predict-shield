"""No-network tests for the preregistration gate, rerun rule, controls and verifier scoring."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import campaign
import controls
import prereg_gate
import verifier_scoring as vs
from plan import create_plan


class GateTests(unittest.TestCase):
    def setUp(self):
        self.state = prereg_gate.current_state()

    def test_unlocked_allows_changes_but_refuses_scored_campaign(self):
        ok, _ = prereg_gate.evaluate({"status": "UNLOCKED"}, self.state, "", scored=False)
        self.assertTrue(ok)
        ok, reason = prereg_gate.evaluate({"status": "UNLOCKED"}, self.state, "", scored=True)
        self.assertFalse(ok)
        self.assertIn("not locked", reason)

    def test_locked_state_must_match_or_be_recorded(self):
        lock = {"status": "LOCKED", **self.state}
        self.assertTrue(prereg_gate.evaluate(lock, self.state, "", scored=True)[0])
        changed = json.loads(json.dumps(self.state))
        changed["files"]["pilot.py"] = "0" * 64
        changed["lock_sha256"] = "1" * 64
        ok, reason = prereg_gate.evaluate(lock, changed, "", scored=True)
        self.assertFalse(ok)
        self.assertIn("pilot.py", reason)
        recorded = "## Entry\nnew_lock_sha256: " + "1" * 64 + "\n"
        self.assertTrue(prereg_gate.evaluate(lock, changed, recorded, scored=True)[0])
        # Only the latest recorded hash counts.
        stale = recorded + "new_lock_sha256: " + "2" * 64 + "\n"
        self.assertFalse(prereg_gate.evaluate(lock, changed, stale, scored=True)[0])

    def test_repository_lock_file_is_consistent(self):
        ok, reason = prereg_gate.check(scored=False)
        self.assertTrue(ok, reason)


class RerunRuleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        _, self.trials = create_plan()
        self.ready_calls = 0

    def ready(self):
        self.ready_calls += 1

    def attempt_sequence(self, outcomes):
        it = iter(outcomes)

        def attempt():
            item = next(it)
            if isinstance(item, Exception):
                raise item
            return item
        return attempt

    def test_one_infrastructure_failure_is_rerun_once(self):
        trial = self.trials[0]
        obs = campaign.execute_with_rerun_rule(
            trial, self.root, self.attempt_sequence([RuntimeError("oracle down"), {"ok": 1}]), self.ready)
        self.assertEqual(obs, {"ok": 1})
        self.assertEqual(self.ready_calls, 1)
        reruns, excluded = campaign.infra_history(self.root)
        self.assertEqual(reruns[trial["run_id"]], 1)
        self.assertFalse(excluded)

    def test_second_failure_excludes_and_budget_spans_invocations(self):
        trial = self.trials[1]
        campaign.append_jsonl(self.root, campaign.RERUNS, {"run_id": trial["run_id"], "rerun": 1})
        obs = campaign.execute_with_rerun_rule(
            trial, self.root, self.attempt_sequence([RuntimeError("again")]), self.ready)
        self.assertIsNone(obs)
        _, excluded = campaign.infra_history(self.root)
        self.assertIn(trial["run_id"], excluded)
        work = campaign.next_trials(self.trials, self.root, start=0, max_trials=4, resume=True)
        self.assertNotIn(trial["run_id"], [t["run_id"] for t in work])

    def test_validation_errors_are_never_rerun(self):
        with self.assertRaises(ValueError):
            campaign.execute_with_rerun_rule(
                self.trials[2], self.root, self.attempt_sequence([ValueError("bad plan")]), self.ready)
        self.assertEqual(campaign.infra_history(self.root)[0][self.trials[2]["run_id"]], 0)

    def test_pilot_and_scored_records_cannot_mix(self):
        campaign.register_kind(self.root, "pilot")
        campaign.register_kind(self.root, "pilot")
        with self.assertRaises(ValueError):
            campaign.register_kind(self.root, "scored:" + "a" * 64)


class ControlTests(unittest.TestCase):
    def run_of(self, kind, denied, end=None):
        return {"kind": kind, "oracle_reads": [{"t": float(i), "denied": d} for i, d in enumerate(denied)],
                "end_of_campaign_window": end or {}}

    def test_positive_outcomes(self):
        self.assertEqual(controls.classify(self.run_of("positive", [True] * 19)), "NOT_EXERCISED")
        self.assertEqual(controls.classify(self.run_of("positive", [False] * 19)), "PERSISTED")
        healed = [False, False, False, True] + [True] * 15
        self.assertEqual(controls.classify(self.run_of("positive", healed)), "SELF_HEALED")
        late = [False] * 10 + [True] * 9
        self.assertEqual(controls.classify(self.run_of("positive", late)), "PERSISTED")
        self.assertEqual(controls.heal_time(self.run_of("positive", late)), 10.0)

    def test_negative_control_flags_any_exposure(self):
        self.assertEqual(controls.classify(self.run_of("negative", [True] * 19,
                                                       {"verifier_scope": "VERIFIED"})), "HEALTHY")
        self.assertEqual(controls.classify(self.run_of("negative", [True, False] + [True] * 17)),
                         "FALSE_FAILURE")
        self.assertEqual(controls.classify(self.run_of("negative", [True] * 19,
                                                       {"gateway_exposure_observed": True})), "FALSE_FAILURE")

    def test_schedule_and_persistence_rule(self):
        runs = controls.schedule()
        self.assertEqual(len(runs), 5 * 8)
        positive = [dict(r, outcome="PERSISTED", oracle_reads=[]) for r in runs if r["fault_mode"] == "loss"]
        positive[0]["outcome"] = positive[1]["outcome"] = "SELF_HEALED"
        summary = controls.summarise(positive)
        self.assertEqual(summary["loss"]["verdict"], "SELF_HEALING_OR_NOT_EXERCISED")
        self.assertAlmostEqual(summary["loss"]["self_heal_rate_when_exercised"], 0.25)


class VerifierScoringTests(unittest.TestCase):
    def telemetry(self, revisions, observed=4):
        return [{"observed": i < observed, "applied_revision": r, "refresh_failed": False,
                 "scheduled_callbacks_pending": 0} for i, r in enumerate(revisions)]

    def test_telemetry_reading(self):
        self.assertEqual(vs.telemetry_reading(self.telemetry([3, 3, 3, 3])), "CONSISTENT")
        self.assertEqual(vs.telemetry_reading(self.telemetry([3, 2, 3, 3])), "DIVERGENT")
        self.assertEqual(vs.telemetry_reading(self.telemetry([3, 3, 3, 3], observed=3)), "UNAVAILABLE")
        self.assertEqual(vs.telemetry_reading(None), "UNAVAILABLE")

    def test_dual_rule_abstains_on_disagreement(self):
        self.assertEqual(vs.dual_verdict("VERIFIED", "CONSISTENT")[0], "VERIFIED")
        self.assertEqual(vs.dual_verdict("VERIFIED", "DIVERGENT")[0], "ABSTAIN")
        self.assertEqual(vs.dual_verdict("VERIFIED", "UNAVAILABLE")[0], "ABSTAIN")
        self.assertEqual(vs.dual_verdict("NOT VERIFIED", "CONSISTENT")[0], "ABSTAIN")
        self.assertEqual(vs.dual_verdict("NOT VERIFIED", "DIVERGENT")[0], "NOT VERIFIED")
        self.assertEqual(vs.dual_verdict("INDETERMINATE", "CONSISTENT")[0], "ABSTAIN")

    def test_tally_counts_false_verified_separately(self):
        t = vs.tally([("VERIFIED", True), ("VERIFIED", False), ("NOT VERIFIED", False),
                      ("NOT VERIFIED", True), ("INDETERMINATE", True)])
        self.assertEqual((t["TP"], t["false_VERIFIED"], t["TN"], t["FN"]), (1, 1, 1, 1))
        self.assertEqual(t["sensitivity_when_answering"], 0.5)
        self.assertEqual(t["specificity_when_answering"], 0.5)
        self.assertEqual(t["abstain_rate"], 0.2)


if __name__ == "__main__":
    unittest.main()
