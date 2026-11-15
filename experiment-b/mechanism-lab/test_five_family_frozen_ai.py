"""Contract tests, not evidence that an unexecuted physical plan succeeded."""
import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from five_family_frozen_physical import (
    SEED, SCHEMA, REGISTRATION, FAULTS, STRATA,
    SHARDS, REPEATS, CONFIGS_PER_SHARD, ACTIONS_PER_SHARD,
    complete_plan, manifest,
)
from evaluate_five_family_frozen_ai import (
    REPORT_SCHEMA, REGRESSION_RUN, EXPECTED_GROUPS,
    MODEL_SHA256, LOCKED_STRONG_RULE,
    load_shards, bootstrap, quantile,
)


class FrozenFiveFamilyContracts(unittest.TestCase):
    def test_exact_60_fresh_groups_balanced_across_five_faults_and_three_strata(self):
        configurations,trials=complete_plan()
        self.assertEqual(len(configurations),60)
        self.assertEqual(len(trials),480)
        self.assertEqual(len({t["run_id"] for t in trials}),480)
        self.assertEqual({x["partition"] for x in configurations},{"test"})
        self.assertEqual({c["fault_mode"] for c in configurations},set(FAULTS))
        self.assertEqual(Counter((c["fault_mode"],c["complexity_stratum"])
                                 for c in configurations),
                         Counter({(f,s):4 for f in FAULTS for s in STRATA}))
        self.assertFalse(any(x["fault_mode"]=="authority_outage" for x in configurations))
        self.assertTrue(all(c["cache_ttl_ms"]>=6500 for c in configurations))

    def test_separate_physical_runner_per_fault_and_stable_plan(self):
        all_groups=set()
        all_trials=set()
        fingerprints=[]
        for shard in range(SHARDS):
            configs,trials=manifest(shard)
            self.assertEqual(len(configs),CONFIGS_PER_SHARD)
            self.assertEqual(len(trials),ACTIONS_PER_SHARD)
            self.assertEqual({c["fault_mode"] for c in configs},{FAULTS[shard]})
            self.assertEqual(Counter(c["complexity_stratum"] for c in configs),
                             Counter({s:4 for s in STRATA}))
            self.assertFalse({c["configuration_id"] for c in configs}&all_groups)
            all_groups|={c["configuration_id"] for c in configs}
            all_trials|={t["run_id"] for t in trials}
            fingerprints.append(tuple(t["run_id"] for t in trials))
        self.assertEqual(len(all_groups),60)
        self.assertEqual(len(all_trials),480)
        self.assertEqual(fingerprints[4],tuple(t["run_id"] for t in manifest(4)[1]))

    def test_consumer_pause_uses_direct_physical_target(self):
        configs,_=manifest(4)
        self.assertTrue(all(c["fault_target"]!="enforcer-hidden" for c in configs))
        self.assertTrue(all(c["measurement_seconds"]==5 for c in configs))

    def test_untouched_model_and_previously_strongest_rule(self):
        self.assertEqual(SEED,20261115312)
        self.assertEqual(REGRESSION_RUN,43682077804)
        self.assertEqual(LOCKED_STRONG_RULE,"fixed_monitor")
        self.assertEqual(len(MODEL_SHA256),64)
        self.assertEqual(EXPECTED_GROUPS,60)
        self.assertEqual(REGISTRATION,"predict-shield/five-family-frozen-ai-plan/1")
        self.assertEqual(SCHEMA,"predict-shield/five-family-frozen-ai-new-physical-shard/1")
        self.assertEqual(REPORT_SCHEMA,"predict-shield/frozen-five-family-physical-ai-v-seven-rules/1")

    def test_no_missing_or_unverified_shards_score(self):
        with self.assertRaisesRegex(ValueError,"five physical"):
            load_shards([])
        with tempfile.TemporaryDirectory() as temp:
            paths=[]
            for shard in range(5):
                path=Path(temp)/f"shard-{shard}.json"
                path.write_text(json.dumps({
                    "schema":SCHEMA,"shard_id":shard,
                    "prospective_registration":REGISTRATION,
                    "fault_family":FAULTS[shard],
                    "physical_replays_completed":96,
                    "independent_new_configuration_groups":12,
                    "independent_four_stream_audit_passed":False,
                }))
                paths.append(path)
            with self.assertRaisesRegex(ValueError,"Unverified"):
                load_shards(paths)

    def test_no_favorable_bootstrap_with_partial_group_truth(self):
        rows={f"group-{i}":{"trained_paired_ai":0.01,"fixed_monitor":0.02}
              for i in range(30)}
        with self.assertRaisesRegex(ValueError,"missing independent"):
            bootstrap(rows,"fixed_monitor")

    def test_zero_baseline_never_means_superiority(self):
        rows={f"group-{i}":{"trained_paired_ai":0.01,"fixed_monitor":0.0}
              for i in range(60)}
        outcome=bootstrap(rows,"fixed_monitor")
        self.assertFalse(outcome["predeclared_more_than_10pct_supported"])
        self.assertLess(outcome["familywise_one_sided_lower_relative"],0)

    def test_quantile_and_repeated_model_freeze(self):
        self.assertEqual(quantile([0,1,2,3,4],.5),2)
        self.assertEqual(quantile([-2,-1,0],0),-2)
        self.assertEqual(quantile([3,5,7],1),7)


if __name__=="__main__":
    unittest.main()
