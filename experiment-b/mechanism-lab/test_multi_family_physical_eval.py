"""Synthetic admission tests, never interpreted as physical result evidence."""
import copy
import unittest
from multi_family_physical_eval import SEED, select_families, transparent_expert
from plan import create_plan


class FourFamilyAdmissionTests(unittest.TestCase):
    def test_four_distinct_registered_test_families(self):
        configs, trials = create_plan(seed=SEED, version="v3.1")
        chosen = select_families(configs)
        self.assertEqual(len(chosen), 4)
        self.assertEqual(len({c["configuration_id"] for _, c in chosen}), 4)
        self.assertEqual({family for family, _ in chosen},
                         {"persistent_loss", "persistent_paused_consumer",
                          "self_healing_delay", "self_healing_short_ttl"})
        self.assertTrue(all(c["partition"] == "test" for _, c in chosen))
        self.assertTrue(all(sum(t["configuration_id"] == c["configuration_id"]
                                for t in trials) == 12 for _, c in chosen))

    def test_incomplete_test_family_rejected(self):
        configs, _ = create_plan(seed=SEED, version="v3.1")
        filtered = [c for c in configs if not (c["partition"] == "test"
                     and c["fault_mode"] == "consumer_paused")]
        with self.assertRaisesRegex(ValueError, "Missing registered test family"):
            select_families(filtered)

    def test_same_input_rule_does_not_require_oracle(self):
        context = {"pre_action": {
            "operator_missing_count": 0,
            "initial_gateway_allowed_fraction": 1.0,
            "cache_ttl_ms": 11000, "operator_pending_callback_count": 0,
            "requested_rps": 15, "operator_max_service_latency_ms": 20,
        }}
        eligible = ("monitor_only", "resync_policy", "restart_enforcer",
                    "gateway_restrict")
        self.assertEqual(transparent_expert(context, eligible), "restart_enforcer")
        self.assertNotEqual(transparent_expert(context,
                            tuple(a for a in eligible if a != "restart_enforcer")),
                            "restart_enforcer")

    def test_expert_abstains_on_absent_operator_evidence(self):
        context = {"pre_action": {
            "operator_missing_count": 4,
            "initial_gateway_allowed_fraction": 1.0,
            "cache_ttl_ms": 11000, "operator_pending_callback_count": 0,
            "requested_rps": 15, "operator_max_service_latency_ms": 20,
        }}
        self.assertIsNone(transparent_expert(context, ("monitor_only",)))

if __name__ == "__main__":
    unittest.main()
