"""Synthetic statistical boundary tests only. No physical outcomes here."""
import copy
import unittest
from confirmatory_196_main import check_lock,evaluate
from confirmatory_196_plan import REGISTRATION_COMMIT
from confirmatory_196_score import MODEL_SHA


def lock():
    return {
        "schema":"predict-shield/confirmatory-196-main-lock/1",
        "registration_commit_sha":REGISTRATION_COMMIT,
        "main_n":40,"unbounded_n":23,
        "pilot_groups":16,"pilot_physical_arms":192,
        "pilot_measured_dataset_sha256":"a"*64,
        "model_sha256":MODEL_SHA,"pilot_run_status":"completed_valid_physical",
        "pilot_run_id":12345,"pilot_data_excluded_from_main":True,
    }


def shard(index,ai_success=1.0,exp_success=1.0):
    return {
        "phase":"main","status":"MAIN_SHARD_MEASURED_ANALYSIS_PENDING",
        "provenance":{
            "phase":"main","shard":index,"groups":20,"physical_arms":240,
            "registration_commit_sha":REGISTRATION_COMMIT,
            "four_stream_digest_sha256":("a" if index==0 else "b")*64,
        },
        "policies":{
            policy:{"per_configuration":{
                f"confirm-{index}-{j}":{
                    "success_fraction":score,"verified_successes":int(3*score),
                    "failed_legitimate_requests":0} for j in range(20)}}
            for policy,score in (("ai",ai_success),("expert_E",exp_success))
        },
    }


class MainConfirmatoryTests(unittest.TestCase):
    def test_refuses_missing_pilot_lock(self):
        d=lock();d.pop("pilot_measured_dataset_sha256")
        with self.assertRaisesRegex(ValueError,"No valid"):
            check_lock(d)

    def test_registered_sample_size_formula_cannot_be_shrunk(self):
        d=lock()
        d["unbounded_n"]=300
        d["main_n"]=40
        with self.assertRaisesRegex(ValueError,"No valid"):
            check_lock(d)
        d["main_n"]=150
        self.assertEqual(check_lock(d)["main_n"],150)

    def test_equal_security_and_disruption_never_claims_h2_superiority(self):
        result=evaluate([shard(0),shard(1)],lock())
        self.assertEqual(result["registered_n"],40)
        self.assertTrue(result["security_primary"]["H1_noninferiority_passed"])
        self.assertTrue(result["disruption_secondary"]["H2_superiority_tested"])
        self.assertFalse(result["disruption_secondary"]["H2_superiority_passed"])

    def test_security_deficit_fails_h1_and_blocks_disruption_test(self):
        result=evaluate([shard(0,0.0,1.0),shard(1,0.0,1.0)],lock())
        self.assertFalse(result["security_primary"]["H1_noninferiority_passed"])
        self.assertFalse(result["disruption_secondary"]["H2_superiority_tested"])
        self.assertIsNone(result["disruption_secondary"]["Wilcoxon_one_sided_p_value"])

    def test_missing_configuration_and_duplicate_shard_digest_fail(self):
        first,second=shard(0),shard(1)
        second["provenance"]["four_stream_digest_sha256"]="a"*64
        with self.assertRaisesRegex(ValueError,"Reused"):
            evaluate([first,second],lock())

if __name__=="__main__":
    unittest.main()
