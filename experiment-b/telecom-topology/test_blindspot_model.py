import unittest
from blindspot_model import fit_blindspot_model

def record(group,split,idx):
    src,dst="a","b"
    has_observed=(idx%4 in (0,1))
    connected=(idx%2==0)
    nodes=[{"asset_id":name,"type":"router","evidence_sources":[
       {"source_kind":"lldp","source_id":f"collector-{group}"}]} for name in ("a","b","c")]
    edges=[]
    if has_observed and connected:
        edges=[{"source":"a","target":"c","relation":"ROUTES_TO","status":"OBSERVED"},
               {"source":"c","target":"b","relation":"ROUTES_TO","status":"OBSERVED"}]
    elif has_observed:
        edges=[{"source":"a","target":"c","relation":"ROUTES_TO","status":"OBSERVED"}]
    graph={"schema":"predict-shield/asset-evidence-graph/1",
           "nodes":nodes,"edges":edges,"unresolved_links":[]}
    return {"topology_group":group,"split":split,"graph":graph,
            "source":src,"target":dst,"verified_reachable":connected,
            "truth_evidence_id":f"synthetic-label-{group}"}

def fixtures():
    return [record(f"group-{i}", "train" if i<8 else "test",i)
            for i in range(12)]

class BlindspotModelTests(unittest.TestCase):
    def test_trained_model_and_rule_baseline_both_evaluated(self):
        model,report=fit_blindspot_model(fixtures())
        self.assertEqual(report["train_topology_groups"],8)
        self.assertEqual(report["heldout_topology_groups"],4)
        self.assertEqual(report["ai"]["tp"]+report["ai"]["tn"]+
          report["ai"]["fp"]+report["ai"]["fn"],4)
        self.assertFalse(report["ai_superiority_established"])
        self.assertTrue(model["inference_only_no_action_authorization"])
    def test_group_leakage_rejected(self):
        data=fixtures()
        bad=dict(data[0]);bad["split"]="test";bad["source"]="c"
        data.append(bad)
        with self.assertRaisesRegex(ValueError,"leakage"):
            fit_blindspot_model(data)
    def test_unverified_label_rejected(self):
        data=fixtures();data[0]["verified_reachable"]=None
        with self.assertRaisesRegex(ValueError,"verified"):
            fit_blindspot_model(data)
    def test_duplicate_pair_refused(self):
        data=fixtures()
        with self.assertRaisesRegex(ValueError,"Duplicate"):
            fit_blindspot_model(data+[dict(data[0])])
if __name__=="__main__":
    unittest.main()
