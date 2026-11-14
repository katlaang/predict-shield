import unittest
from independent_discovery_eval import evaluate_locked

def cases(groups=8,ai_correct=True):
    data=[]
    for i in range(groups):
        for j in range(4):
            y=j<2
            data.append({"topology_id":f"top-{i}","source":f"a{j}","target":f"b{j}",
                         "verified_link":y,"model_score":.9 if y==ai_correct else .1,
                         "baseline_score":.9 if j==0 else .1,
                         "truth_evidence_id":f"synthetic-test-label-{i}-{j}"})
    return data
class HeldoutTests(unittest.TestCase):
    def test_positive_synthetic_fixture_not_external_truth(self):
        r=evaluate_locked(cases(),registered_groups=[f"top-{i}" for i in range(8)],
                           independent_provenance_attested=False,bootstrap_repeats=1000)
        self.assertGreater(r["mean_accuracy_delta"],0)
        self.assertFalse(r["ai_superiority_established"])
        self.assertEqual(r["conclusion"],"NOT_ESTABLISHED")
    def test_negative_or_tie_never_report_superior(self):
        r=evaluate_locked(cases(ai_correct=False),
                         registered_groups=[f"top-{i}" for i in range(8)],
                         independent_provenance_attested=True,bootstrap_repeats=1000)
        self.assertFalse(r["ai_superiority_established"])
    def test_missing_groups_refused(self):
        with self.assertRaisesRegex(ValueError,"Missing preregistered"):
            evaluate_locked(cases(7),registered_groups=[f"top-{i}" for i in range(8)],
                            bootstrap_repeats=1000)
    def test_short_experiment_not_superiority(self):
        r=evaluate_locked(cases(3),registered_groups=[f"top-{i}" for i in range(3)],
                          independent_provenance_attested=True,bootstrap_repeats=1000)
        self.assertFalse(r["ai_superiority_established"])
    def test_duplicate_pair_refused(self):
        data=cases()
        with self.assertRaisesRegex(ValueError,"Duplicate"):
            evaluate_locked(data+[dict(data[0])],
                            registered_groups=[f"top-{i}" for i in range(8)],
                            bootstrap_repeats=1000)
    def test_unknown_label_refused(self):
        data=cases();data[0]["verified_link"]=None
        with self.assertRaises(ValueError):
            evaluate_locked(data,registered_groups=[f"top-{i}" for i in range(8)],
                            bootstrap_repeats=1000)
if __name__=="__main__":unittest.main()
