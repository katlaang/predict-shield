"""All observations in this suite are synthetic and not evidence of ISP AI quality."""
import unittest
from link_learning import train_evaluate, infer_pairs, validate_rows, confusion, FEATURES

def row(top,source,target,split,label,**features):
    return {"topology_id":top,"source":source,"target":target,
            "split":split,"verified_link":label,
            "features":{name:features.get(name,False) for name in FEATURES}}

def fixture():
    data=[]
    for i in range(8):
        top=f"train-topology-{i}"
        data.extend([
            row(top,"r1","s1","train",True,lldp_seen=True,same_site=True,interface_type_compatible=True),
            row(top,"r1","s2","train",True,routing_adjacency_seen=True,same_site=True,interface_type_compatible=True),
            row(top,"r1","s3","train",False,same_site=False),
            row(top,"r2","s3","train",False,same_site=False,interface_type_compatible=True),
        ])
    for i in range(3):
        top=f"test-topology-{i}"
        data.extend([
            row(top,"a","b","test",True,lldp_seen=True,same_site=True,interface_type_compatible=True),
            row(top,"a","c","test",True,routing_adjacency_seen=True,same_site=True,interface_type_compatible=True),
            row(top,"a","d","test",False,same_site=False),
            row(top,"b","d","test",False,interface_type_compatible=True),
        ])
    return data

class LinkLearningTests(unittest.TestCase):
    def test_training_and_grouped_heldout_evaluation(self):
        model, report=train_evaluate(fixture())
        self.assertEqual(report["test_records"],12)
        self.assertEqual(len(report["test_topologies"]),3)
        self.assertFalse(report["model_superiority_claim"])
        self.assertEqual(sum(report["model_confusion"][key] for key in ("tp","fp","tn","fn")),12)
        self.assertEqual(sum(report["deterministic_baseline_confusion"][key] for key in ("tp","fp","tn","fn")),12)
        proposals=infer_pairs(model,[{"source":"new-router","target":"new-switch",
                   "features":{key:(key=="lldp_seen") for key in FEATURES}}])
        self.assertEqual(proposals[0]["status"],"INFERRED")
        self.assertFalse(proposals[0]["physically_verified"])
        self.assertFalse(proposals[0]["calibrated_confidence"])

    def test_group_leakage_rejected(self):
        rows=fixture()
        rows[0]["split"]="test"
        with self.assertRaisesRegex(ValueError,"topology"):
            train_evaluate(rows)

    def test_duplicate_edge_with_reversed_direction_rejected(self):
        rows=fixture()
        duplicate=dict(rows[0]);duplicate["source"],duplicate["target"]=duplicate["target"],duplicate["source"]
        rows.append(duplicate)
        with self.assertRaisesRegex(ValueError,"Repeated"):
            validate_rows(rows)

    def test_training_without_negative_class_fails(self):
        rows=fixture()
        for r in rows:
            if r["split"]=="train":
                r["verified_link"]=True
        with self.assertRaisesRegex(ValueError,"both"):
            train_evaluate(rows)

    def test_no_known_labels_in_feature_vector(self):
        rows=fixture()
        rows[0]["features"]["verified_link"]=True
        with self.assertRaisesRegex(ValueError,"pre-verification"):
            train_evaluate(rows)

    def test_confusion_preserves_no_positive_undefined(self):
        a=confusion([False,False],[.1,.2])
        self.assertIsNone(a["precision"])
        self.assertEqual(a["false_positive_rate"],0)

    def test_bad_model_fails_closed(self):
        with self.assertRaises(ValueError):
            infer_pairs({"schema":"fake"},[])

if __name__=="__main__":
    unittest.main()
