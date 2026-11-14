"""Synthetic unit fixtures only. These are NOT published AI performance data."""
import copy
import unittest

from decision_superiority_audit import evaluate, _paired
from decision_eval import ACTIONS


def fixture(calibration_groups=5, test_groups=20, *, model_wins=True):
    rows, predictions = [], {}
    for partition, size in (("calibration", calibration_groups),
                            ("test", test_groups)):
        for i in range(size):
            group=f"{partition}-{i:03d}"
            for repeat in range(3):
                for action in ACTIONS:
                    # Calibration chooses monitor-only on genuinely distinct
                    # groups. The blinded test scenario favors restart, which
                    # the synthetic predictor (not real AI!) forecasts.
                    optimal=("monitor_only" if partition=="calibration"
                             else "restart_enforcer")
                    bad=0.0 if action==optimal else 1.0
                    row={
                        "group":group, "partition":partition, "repeat":repeat,
                        "action":action, "fault":"loss", "target":"enforcer-b",
                        "restart_permitted":True,
                        "absolute_error_budget_requests":25,
                        "complexity_stratum":"PARTIAL_VISIBILITY",
                        "pre_action":{
                            "cache_ttl_ms":3000,
                            "requested_rps":20,
                            "gateway_visible_enforcer_count":4,
                            "initial_gateway_allowed_fraction":0.0,
                            "operator_missing_count":0,
                        },
                        "label_path_exposure":bad,
                        "label_security_exposure":bad,
                        "label_absolute_failed_requests":25*bad,
                    }
                    rows.append(row)
                    if partition=="test":
                        # Predictor input consists only of an action forecast
                        # keyed to group/repeat/action, not post-action data.
                        forecast=(0.0 if action==(
                            optimal if model_wins else "monitor_only") else 1.0)
                        predictions[(group,repeat,action)]={
                            "label_path_exposure":forecast,
                            "label_security_exposure":forecast,
                            "label_absolute_failed_requests":25*forecast,
                        }
    return rows,predictions


PARAMS={"ttl_threshold_ms":6500, "load_threshold_rps":25,
        "revision_spread_threshold":1, "gateway_threshold_rps":40}


class DecisionSuperiorityAuditTests(unittest.TestCase):
    def test_synthetic_positive_requires_20_group_heldout(self):
        rows,pred=fixture()
        result=evaluate(rows,pred,PARAMS,replicates=500)
        self.assertEqual(result["heldout_group_count"],20)
        self.assertEqual(result["locked_non_ai_comparator"] in (
            "fixed_monitor","engineering_rule","observable_telemetry_rule"),True)
        self.assertTrue(result["improvement_target_supported_in_lab"])
        self.assertEqual(result["paired_group_bootstrap_relative_95"],[1.0,1.0])
        self.assertTrue(result["no_external_critical_infrastructure_validation"])

    def test_synthetic_no_advantage_is_not_positive_claim(self):
        rows,pred=fixture(model_wins=False)
        report=evaluate(rows,pred,PARAMS,replicates=500)
        self.assertFalse(report["improvement_target_supported_in_lab"])
        self.assertEqual(report["research_status"],"LAB_SUPERIORITY_NOT_ESTABLISHED")

    def test_insufficient_test_groups_never_prove_superiority(self):
        rows,pred=fixture(test_groups=4)
        report=evaluate(rows,pred,PARAMS,replicates=500)
        self.assertFalse(report["improvement_target_supported_in_lab"])

    def test_missing_forecast_and_incomplete_arm_fail_closed(self):
        rows,pred=fixture()
        del pred[("test-000",0,"resync_policy")]
        with self.assertRaisesRegex(ValueError,"Missing blinded"):
            evaluate(rows,pred,PARAMS,replicates=500)
        rows,pred=fixture()
        rows.pop()
        with self.assertRaisesRegex(ValueError,"Incomplete four-arm"):
            evaluate(rows,pred,PARAMS,replicates=500)

    def test_heldout_and_calibration_group_overlap_rejected(self):
        rows,pred=fixture()
        # Renamed group is present in both calibrator and test partition.
        for row in rows:
            if row["partition"]=="calibration" and row["group"]=="calibration-000":
                row["group"]="test-000"
        with self.assertRaisesRegex(ValueError,"leakage"):
            evaluate(rows,pred,PARAMS,replicates=500)

    def test_unknown_authority_cannot_be_converted_to_point_label(self):
        rows,pred=fixture()
        rows[0]["fault"]="authority_outage"
        with self.assertRaisesRegex(ValueError,"UNKNOWN"):
            evaluate(rows,pred,PARAMS,replicates=500)

    def test_no_zero_denominator_relative_advantage_claim(self):
        rows,pred=fixture()
        # Every physical action scores zero in calibration and test.
        for row in rows:
            row["label_path_exposure"]=0.0
            row["label_security_exposure"]=0.0
            row["label_absolute_failed_requests"]=0.0
        report=evaluate(rows,pred,PARAMS,replicates=500)
        self.assertIsNone(report["paired_group_bootstrap_relative_95"])
        self.assertFalse(report["improvement_target_supported_in_lab"])

    def test_true_outputs_must_not_be_prediction_features(self):
        rows,pred=fixture()
        original=copy.deepcopy(rows)
        for row in rows:
            row["label_security_exposure"]=1-row["label_security_exposure"]
        self.assertEqual(pred,fixture()[1])
        self.assertNotEqual(rows,original)


if __name__=="__main__":
    unittest.main()
