import unittest
from predict_shield.telemetry_blindspots import (
 preverification_pair,strong_deterministic_baseline
)
def graph():
    return {"schema":"predict-shield/asset-evidence-graph/1",
      "nodes":[{"asset_id":n,"type":"router","evidence_sources":[
         {"source_kind":"lldp","source_id":"collector"}]} for n in ("a","b","c")],
      "edges":[{"source":"a","target":"c","relation":"NEIGHBOR_OF",
                "status":"OBSERVED","evidence":[{"source_kind":"lldp","source_id":"collector"}]},
               {"source":"c","target":"b","relation":"NEIGHBOR_OF",
                "status":"OBSERVED","evidence":[{"source_kind":"lldp","source_id":"collector"}]}],
      "unresolved_links":[]}
class TelemetryBlindspotTests(unittest.TestCase):
    def test_indirect_observation_not_invented_direct_confirmation(self):
        f=preverification_pair(graph(),"a","b")
        self.assertEqual(f["observed_direct_evidence_count"],0)
        self.assertEqual(f["observed_shared_neighbor_count"],1)
        self.assertEqual(f["shortest_observed_path_inverse"],.5)
        self.assertTrue(strong_deterministic_baseline(f))
    def test_inferred_edges_excluded(self):
        g=graph()
        for edge in g["edges"]:edge["status"]="INFERRED"
        f=preverification_pair(g,"a","b")
        self.assertEqual(f["connected_by_observed_path"],0)
        self.assertFalse(strong_deterministic_baseline(f))
    def test_missing_telemetry_preserved_as_feature(self):
        g=graph()
        g["nodes"][0]["evidence_sources"]=[{"source_kind":"inventory","source_id":"oss"}]
        f=preverification_pair(g,"a","b")
        self.assertEqual(f["endpoint_observation_missing"],1)
    def test_unknown_identity_fails(self):
        with self.assertRaises(ValueError):
            preverification_pair(graph(),"a","ghost")
if __name__=="__main__": unittest.main()
