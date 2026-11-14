import unittest
from graph_risk_training import fit_and_evaluate
from predict_shield.graph_risk import predict_graph_risk

def graph(i):
    return {"schema":"predict-shield/asset-evidence-graph/1","sha256":str(i),
      "nodes":[{"asset_id":"edge","type":"router"},{"asset_id":"auth","type":"service"}],
      "edges":[{"source":"edge","target":"auth","status":"OBSERVED","relation":"DEPENDS_ON"}],
      "unresolved_links":[]}
def rows():
    out=[]
    for i in range(8):
        for j in range(2):
            out.append({"topology_group":f"topology-{i}","split":"train" if i<6 else "test",
              "asset_id":f"edge-{j}","graph":{**graph(i),"nodes":[
                  {"asset_id":f"edge-{j}","type":"router"},{"asset_id":"auth","type":"service"}],
                  "edges":[{"source":f"edge-{j}","target":"auth","status":"OBSERVED","relation":"DEPENDS_ON"}]},
              "critical_services":["auth"],"confirmed_exposure":float(j),
              "observed_security_incident":bool(j)})
    return out

class GroupedRiskTests(unittest.TestCase):
    def test_grouped_model_fit_and_baseline(self):
        model,report=fit_and_evaluate(rows())
        self.assertEqual(report["test_groups"],2)
        self.assertEqual(report["test_records"],4)
        self.assertFalse(report["superiority_confirmed"])
        score=predict_graph_risk(model,rows()[0]["graph"],"edge-0",
              critical_services=("auth",),confirmed_exposure=0)
        self.assertFalse(score["decision_authorized"])
    def test_group_leakage_fails(self):
        data=rows();data[0]["split"]="test"
        with self.assertRaisesRegex(ValueError,"leakage"):
            fit_and_evaluate(data)
    def test_unknown_incident_label_fails(self):
        data=rows();data[0]["observed_security_incident"]=None
        with self.assertRaisesRegex(ValueError,"label"):
            fit_and_evaluate(data)
if __name__=="__main__":unittest.main()
