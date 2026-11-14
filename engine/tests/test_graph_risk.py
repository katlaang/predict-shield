import unittest
from predict_shield.graph_risk import features_for_asset,predict_graph_risk,FEATURES
def graph():
    return {"schema":"predict-shield/asset-evidence-graph/1","sha256":"synthetic",
      "nodes":[{"asset_id":"edge","type":"router"},{"asset_id":"auth","type":"service"},
               {"asset_id":"core","type":"router"}],
      "edges":[{"source":"edge","target":"core","status":"OBSERVED","relation":"CONNECTED_TO"},
               {"source":"core","target":"auth","status":"DECLARED","relation":"SERVES"}],
      "unresolved_links":[{"source":"edge","target":"unknown"}]}
class GraphRiskTests(unittest.TestCase):
    def test_graph_features_preserve_missing_evidence(self):
        f=features_for_asset(graph(),"edge",critical_services=("auth",),confirmed_exposure=.4)
        self.assertEqual(f["observed_degree"],1)
        self.assertEqual(f["critical_service_reachability"],1)
        self.assertEqual(f["unknown_neighbor_count"],1)
    def test_inferred_edges_not_counted(self):
        g=graph();g["edges"]=[{"source":"edge","target":"auth","status":"INFERRED","relation":"DEPENDS_ON"}]
        f=features_for_asset(g,"edge",critical_services=("auth",),confirmed_exposure=.4)
        self.assertEqual(f["critical_service_reachability"],0)
    def test_missing_real_exposure_rejected(self):
        with self.assertRaises(ValueError):
            features_for_asset(graph(),"edge",critical_services=("auth",),confirmed_exposure=None)
    def test_trained_model_output_not_authority(self):
        bundle={"schema":"predict-shield/telecom-graph-risk-logistic/1",
          "features":list(FEATURES),"coefficients":[.1]*len(FEATURES),
          "intercept":-1.0,"training_fingerprint":"toy"}
        value=predict_graph_risk(bundle,graph(),"edge",critical_services=("auth",),
                                 confirmed_exposure=.4)
        self.assertTrue(0<value["model_score"]<1)
        self.assertFalse(value["decision_authorized"])
        self.assertFalse(value["probability_calibrated"])
if __name__=="__main__":unittest.main()
