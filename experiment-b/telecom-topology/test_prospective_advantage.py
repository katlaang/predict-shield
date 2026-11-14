import unittest
from prospective_advantage import judge, wilson_lower

def fixture(groups=20, each=500):
    rows=[]
    for g in range(groups):
        for i in range(each):
            y=i%2==0
            rows.append({"group":f"external-site-{g:02d}",
                "source":f"a{i}","target":f"b{i}",
                "verified_link":y,"ai_prediction":y,"baseline_prediction":False,
                "ai_abstained":False,
                "independent_truth_evidence_id":f"synthetic-label-{g}-{i}",
                "model_fingerprint":"locked-ai-v1",
                "baseline_fingerprint":"locked-rule-v1",
                "training_group_member":False})
    return rows,[f"external-site-{g:02d}" for g in range(groups)]

class QualityGateTests(unittest.TestCase):
    def check(self,rows,groups,**kwargs):
        return judge(rows,preregistered_groups=groups,
          locked_model_fingerprint="locked-ai-v1",
          locked_baseline_fingerprint="locked-rule-v1",
          repeats=1000,**kwargs)
    def test_synthetic_perfect_cannot_establish_unattested_superiority(self):
        rows,groups=fixture()
        report=self.check(rows,groups)
        self.assertEqual(report["ai"]["accuracy"],1)
        self.assertFalse(report["ai_advantage_99_9_confirmed"])
        self.assertEqual(report["conclusion"],"NOT_ESTABLISHED")
    def test_deterministic_tie_is_not_advantage(self):
        rows,groups=fixture()
        for r in rows:r["baseline_prediction"]=r["verified_link"]
        report=self.check(rows,groups,external_truth_audit=True)
        self.assertFalse(report["ai_advantage_99_9_confirmed"])
        self.assertEqual(report["paired_group_bootstrap_95_interval"],[0.,0.])
    def test_small_pilot_cannot_claim_99_9(self):
        rows,groups=fixture(4,100)
        report=self.check(rows,groups,external_truth_audit=True)
        self.assertFalse(report["minimum_coverage_met"])
        self.assertFalse(report["ai_advantage_99_9_confirmed"])
    def test_rare_positive_class_can_hide_missed_threats(self):
        rows,groups=fixture()
        for row in rows:
            row["verified_link"]=False
            row["ai_prediction"]=False
        report=self.check(rows,groups,external_truth_audit=True)
        self.assertFalse(report["minimum_coverage_met"])
        self.assertIsNone(report["ai"]["recall"])
    def test_model_leakage_rejected(self):
        rows,groups=fixture()
        rows[0]["training_group_member"]=True
        with self.assertRaisesRegex(ValueError,"leakage"):
            self.check(rows,groups)
    def test_missing_registered_group_rejected(self):
        rows,groups=fixture()
        with self.assertRaisesRegex(ValueError,"omitted"):
            self.check(rows[:-500],groups)
    def test_abstention_is_not_free_success(self):
        rows,groups=fixture()
        rows[0]["ai_abstained"]=True
        with self.assertRaisesRegex(ValueError,"Abstentions"):
            self.check(rows,groups)
    def test_uncertainty_bound_for_10000_zero_misses(self):
        self.assertGreater(wilson_lower(5000,5000),.999)
if __name__=="__main__":
    unittest.main()
