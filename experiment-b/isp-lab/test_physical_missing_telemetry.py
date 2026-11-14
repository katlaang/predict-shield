import unittest
from physical_missing_telemetry import (
 observation_available,assemble_pretruth_graph,NODES
)
from predict_shield.telemetry_blindspots import preverification_pair

class PhysicalBlindspotContracts(unittest.TestCase):
    def test_mask_is_deterministic_and_not_oracle_driven(self):
        group="blindspot-physical-topology-20"
        self.assertEqual(
          observation_available(group,"edge-a","core-d"),
          observation_available(group,"edge-a","core-d"))
    def test_no_fabricated_link_from_missing_probe(self):
        graph=assemble_pretruth_graph("test",{
          (NODES[0],NODES[1]):None,
          (NODES[1],NODES[0]):None,
        })
        self.assertEqual(graph["edges"],[])
        features=preverification_pair(graph,NODES[0],NODES[1])
        self.assertEqual(features["observed_direct_evidence_count"],0)
    def test_real_positive_probe_generates_observation_only(self):
        graph=assemble_pretruth_graph("test",{(NODES[0],NODES[1]):True})
        self.assertEqual(len(graph["edges"]),1)
        self.assertFalse(graph["physical_link_verified"])
        self.assertFalse(graph["complete_inventory_verified"])

if __name__=="__main__":
    unittest.main()
