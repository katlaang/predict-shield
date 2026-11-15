"""Research safety contracts. Artificial fixtures here are not model evidence."""
import unittest

from paired_action_value_training import (
    _grouped_arms, paired_rows, _choose, MARGIN,
    SCHEMA, build_estimator
)
from train import to_features
from decision_eval import observed_utility


def fixture(partition="train",groups=2):
    result=[]
    base={
       "cache_ttl_ms":7000,"requested_rps":40,
       "gateway_visible_enforcer_count":4,
       "initial_gateway_allowed_fraction":0.5,
       "operator_observed_count":4.,"operator_missing_count":0.,
       "operator_revision_spread":1.,"operator_max_cache_age_ms":1000.,
       "operator_refresh_failure_count":1.,"operator_pending_callback_count":0.,
       "operator_handled_event_spread":0.,"operator_max_service_latency_ms":10.,
       "operator_service_latency_spread_ms":0.,"routing_profile":"balanced",
    }
    for g in range(groups):
        for repeat in (0,1,2):
            for action in ("resync_policy","restart_enforcer","gateway_restrict","monitor_only"):
                result.append({
                    "group":f"group-{g}","repeat":repeat,"action":action,
                    "partition":partition,
                    "restart_permitted":bool(g%2),
                    "absolute_error_budget_requests":25,
                    "pre_action":dict(base),
                    "label_path_exposure":0.2 if action=="monitor_only" else 0.1,
                    "label_security_exposure":0.0,
                    "label_absolute_failed_requests":1.0 if action=="monitor_only" else 2.0,
                })
    return result


class Model:
    def __init__(self, pred): self.pred=pred
    def predict(self,x):
        # last feature encodes candidate identity, and no hidden label.
        mapping={0:0.002,1:0.05,2:0.1}
        return [self.pred.get(tuple(int(t) for t in entry[-4:]),0.0)
                for entry in x]


class TrainingSafetyTests(unittest.TestCase):
    def test_all_four_real_action_arms_required(self):
        r=fixture()
        self.assertEqual(len(_grouped_arms(r,"train")),6)
        with self.assertRaisesRegex(ValueError,"Partial"):
            _grouped_arms(r[:-1],"train")

    def test_no_partitions_are_mixed(self):
        with self.assertRaisesRegex(ValueError,"Mixed"):
            _grouped_arms(fixture()+fixture("calibration"),"train")

    def test_replayed_action_budget_must_be_consistent(self):
        r=fixture();r[0]["absolute_error_budget_requests"]=26
        with self.assertRaisesRegex(ValueError,"Inconsistent"):
            paired_rows(r,"train")

    def test_paired_outcome_target_uses_real_matched_action_utility(self):
        r=fixture()
        x=paired_rows(r,"train")
        self.assertEqual(len(x),18)
        ref=r[3]
        expected=observed_utility(ref)-observed_utility(r[0])
        self.assertAlmostEqual(x[0]["actual_benefit"],expected)
        self.assertEqual(x[0]["features"],
                         to_features({"pre_action":ref["pre_action"],
                                      "action":"resync_policy"}))

    def test_action_freeze_rejects_restart_even_if_ai_prefers_it(self):
        r=fixture(groups=1)
        reference=next(row for row in r if row["action"]=="monitor_only")
        model=Model({
            (0,1,0,0):0.9,
            (1,0,0,0):0.02,
            (0,0,1,0):0.001
        })
        selected,_=_choose(model,reference)
        self.assertEqual(selected,"resync_policy")

    def test_monitor_when_no_estimated_gain(self):
        r=fixture(groups=1)
        reference=next(row for row in r if row["action"]=="monitor_only")
        selected,_=_choose(Model({}),reference)
        self.assertEqual(selected,"monitor_only")

    def test_fixed_model_settings_and_margin(self):
        model=build_estimator()
        self.assertEqual(model.max_leaf_nodes,10)
        self.assertEqual(model.max_iter,120)
        self.assertEqual(MARGIN,.01)
        self.assertEqual(SCHEMA,"predict-shield/paired-measured-action-benefit-training/1")

if __name__=="__main__":
    unittest.main()
