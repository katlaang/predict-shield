"""Pre-outcome protocol contract tests; synthetic only, no effect-size claims."""
import unittest
from confirmatory_196_plan import (
    REGISTRATION_COMMIT, REGISTERED_SEED, PILOT_INDEXES, make_plan,
    selected, operational_identity, PREVIOUS_SEEDS)
from confirmatory_196_score import expert_ladder, ai_escalation, summarize_pilot
from plan import create_plan


class Confirmatory196Tests(unittest.TestCase):
    def test_seed_is_from_merged_registration_not_picked_after_results(self):
        self.assertEqual(REGISTERED_SEED,int(REGISTRATION_COMMIT[:8],16))

    def test_pilot_has_sixteen_distinct_registered_groups_and_ten_strata(self):
        configurations,trials=make_plan(phase="pilot")
        chosen=selected(configurations,phase="pilot")
        self.assertEqual(len(chosen),16)
        self.assertEqual(len({c["configuration_id"] for c in chosen}),16)
        self.assertEqual(len({(c["confirmatory_family"],c["restart_permitted"])
                              for c in chosen}),10)
        self.assertEqual({c["confirmatory_family"] for c in chosen},
            {"persistent_loss","persistent_paused_consumer","self_healing_delay",
             "self_healing_short_ttl","withheld_publication"})
        self.assertEqual(len(trials),1200)
        for c in chosen:
            self.assertEqual(sum(t["configuration_id"]==c["configuration_id"]
                                 for t in trials),12)

    def test_confirmatory_namespace_does_not_reuse_old_configurations(self):
        configs,_=make_plan(phase="pilot")
        historic={operational_identity(c) for s in PREVIOUS_SEEDS
                  for c in create_plan(seed=s,version="v3.1")[0]}
        self.assertTrue(all(operational_identity(c) not in historic
                            for c in selected(configs,phase="pilot")))

    def test_main_is_separate_from_pilot_and_fixed_across_calls(self):
        pilot,_=make_plan(phase="pilot")
        main,t=make_plan(phase="main",shard=0)
        self.assertEqual((main,t),make_plan(phase="main",shard=0))
        self.assertFalse({c["configuration_id"] for c in pilot}
                         & {c["configuration_id"] for c in main})
        self.assertEqual(len(selected(main,phase="main")),20)
        self.assertTrue(any(c["fault_mode"]=="withheld_publication" for c in main))

    def test_escalation_never_bypasses_restart_authorization(self):
        ctx={"pre_action":{"operator_missing_count":0,"cache_ttl_ms":16000,
                           "operator_pending_callback_count":0,
                           "initial_gateway_allowed_fraction":1.0}}
        self.assertEqual(expert_ladder(ctx,("monitor_only","resync_policy")),"escalate")
        self.assertEqual(expert_ladder(ctx,("restart_enforcer","monitor_only")),"restart_enforcer")
        self.assertEqual(ai_escalation(ctx,("monitor_only","resync_policy"),"monitor_only"),"escalate")

    def test_short_ttl_pending_event_allows_monitoring(self):
        ctx={"pre_action":{"operator_missing_count":0,"cache_ttl_ms":3000,
                           "operator_pending_callback_count":1,
                           "initial_gateway_allowed_fraction":1.0}}
        self.assertEqual(expert_ladder(ctx,("restart_enforcer","monitor_only")),"monitor_only")

    def test_pilot_never_returns_confirmatory_success(self):
        groups=[f"g-{i}" for i in range(16)]
        policies={p:{"per_configuration":{
            g:{"success_fraction":1.0,"verified_successes":3,"failed_legitimate_requests":0}
            for g in groups}} for p in ("ai","expert_E")}
        p=summarize_pilot(policies,{"physical_arms":192,
                                   "four_stream_digest_sha256":"a"*64},
                          {g:True for g in groups})
        self.assertFalse(p["ai_superiority_established"])
        self.assertEqual(p["pilot_discordant_configurations"],0)
        self.assertEqual(p["registered_main_n"],40)

if __name__=="__main__":
    unittest.main()
