"""Offline safety of pre-registered fresh physical experiment; no made-up wins."""
import json
import tempfile
import unittest
from pathlib import Path

from prospective_action_physical_shard import (
    manifest, SCHEMA, REGISTRATION, ACTIONS_PER_SHARD,
    SOURCE_INDICES,SEED
)
from score_prospective_paired_actions import (
    LOCKED_STRONG_RULE, MODEL_SHA256, OLD_TRAIN_RULE,
    load_physical, _quantile, bootstrap_groups
)


class ProspectiveSafetyTests(unittest.TestCase):
    def test_original_test_groups_and_current_groups_are_disjoint_by_registration(self):
        all_identifiers=set()
        for shard in range(3):
            configs,trials=manifest(shard)
            self.assertEqual(len(configs),8)
            self.assertEqual(len(trials),ACTIONS_PER_SHARD)
            self.assertEqual(len({x["run_id"] for x in trials}),64)
            self.assertEqual({x["partition"] for x in trials},{"test"})
            self.assertEqual(len({x["configuration_id"] for x in configs}),8)
            self.assertEqual(len({x["fault_mode"] for x in configs}),4)
            self.assertTrue(all(x["configuration_id"].startswith("fresh-benefit-") for x in configs))
            ids={x["configuration_id"] for x in configs}
            self.assertFalse(ids&all_identifiers)
            all_identifiers |= ids
        self.assertEqual(len(all_identifiers),24)
        self.assertEqual(len(set(i for group in SOURCE_INDICES for i in group)),24)

    def test_test_manifest_rejects_partial_shards(self):
        with self.assertRaisesRegex(ValueError,"Unknown physical shard"):
            manifest(3)
        with self.assertRaisesRegex(ValueError,"Unknown physical shard"):
            manifest(-1)

    def test_frozen_source_id_and_baseline(self):
        self.assertEqual(SEED,20261115071)
        self.assertEqual(LOCKED_STRONG_RULE,"fixed_monitor")
        self.assertEqual(len(MODEL_SHA256),64)
        self.assertEqual(OLD_TRAIN_RULE["ttl_threshold_ms"],10000)
        self.assertEqual(REGISTRATION,
                         "predict-shield/prospective-action-benefit-physical-plan/1")

    def test_missing_actual_measurements_fail_closed(self):
        with self.assertRaisesRegex(ValueError,"three independent"):
            load_physical([])

    def test_bootstrap_requires_all_group_truth(self):
        d={f"g{i}":{"trained_paired_ai":0.1,"fixed_monitor":0.2} for i in range(12)}
        with self.assertRaisesRegex(ValueError,"24 groups"):
            bootstrap_groups(d,"fixed_monitor")

    def test_quantile_never_invents_a_favorable_metric(self):
        self.assertEqual(_quantile([0,1,2,3,4],.5),2)
        self.assertEqual(_quantile([-3,-2,-1],0),-3)
        self.assertEqual(_quantile([0,1],1),1)


if __name__=="__main__":
    unittest.main()
