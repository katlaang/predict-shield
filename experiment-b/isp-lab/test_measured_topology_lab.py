"""Synthetic contract tests for a real-virtual-network experiment."""
import unittest
from measured_topology_lab import partition_protocol,assemble_candidates,NODES,TRAIN_GROUPS,HELDOUT_GROUPS

class ProtocolTests(unittest.TestCase):
    def test_registered_topologies_are_unique_and_reproducible(self):
        x=partition_protocol()
        self.assertEqual(x,partition_protocol())
        self.assertEqual(len(x),TRAIN_GROUPS+HELDOUT_GROUPS)
        self.assertEqual(len(set(x)),len(x))
        self.assertTrue(all(len(x)==len(NODES) for x in x))
    def test_model_feature_source_separate_from_docker_labels(self):
        probes={(a,b):False for a in NODES for b in NODES if a!=b}
        oracle={name:("seg1" if idx<2 else "seg2") for idx,name in enumerate(NODES)}
        result=assemble_candidates("topology-0","test",probes,oracle)
        self.assertEqual(len(result),10)
        a=next(r for r in result if r["source"]==NODES[0] and r["target"]==NODES[1])
        self.assertTrue(a["verified_link"])
        self.assertFalse(a["features"]["bidirectional_flow_seen"])
        self.assertNotIn("verified_link",a["features"])
if __name__=="__main__":unittest.main()
