"""Unit tests, exclusively planned/synthetic fixtures, not AI trial results."""
import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from full_v3_physical_shard import manifest, SHARDS, TRIALS_PER_SHARD
from full_v3_ai_aggregate import combine
from plan import create_plan


class FullPhysicalAIExperimentContracts(unittest.TestCase):
    def test_disjoint_full_frozen_v3_registration(self):
        configs, trials = create_plan()
        all_config, all_trial = [], []
        for shard in range(SHARDS):
            c, t = manifest(shard)
            self.assertEqual((len(c),len(t)),(20,240))
            self.assertEqual({x["repeat"] for x in t},{0,1,2})
            self.assertEqual(set(x["action_id"] for x in t),
                             {"resync_policy","restart_enforcer",
                              "gateway_restrict","monitor_only"})
            all_config.extend(c)
            all_trial.extend(t)
        self.assertEqual({c["configuration_id"] for c in all_config},
                         {c["configuration_id"] for c in configs})
        self.assertEqual({t["run_id"] for t in all_trial},
                         {t["run_id"] for t in trials})
        self.assertEqual(len(set(t["run_id"] for t in all_trial)),1200)
        self.assertEqual(Counter(c["partition"] for c in all_config),
                         {"train":60,"calibration":20,"test":20})

    def test_no_campaign_from_missing_actual_measured_shards(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError, "Missing required measured physical shard"):
                combine(Path(folder))

    def test_mere_manifest_cannot_fake_a_complete_shard(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for n in range(SHARDS):
                (root/f"shard-{n}.json").write_text(json.dumps({
                    "schema": "predict-shield/full-v3-exploratory-physical-shard/1",
                    "shard_id": n, "physical_replays_completed":240,
                    "all_four_physical_record_streams_audited":True,
                    "sanitized_measured_training_rows": [],
                }))
            with self.assertRaises(ValueError):
                combine(root)

    def test_rejects_unregistered_shard_number(self):
        for i in (-1, 5, 6):
            with self.assertRaises(ValueError):
                manifest(i)


if __name__=="__main__":
    unittest.main()
