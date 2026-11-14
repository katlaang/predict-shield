import unittest

from predict_shield.telecom_graph import build_graph,compare_inventory_observations
from predict_shield.lldp_adapter import lldp_to_source_export

STAMP="2026-11-14T22:00:00Z"

def export(kind, name, assets, links=()):
    return {"schema":"predict-shield/telecom-source-export/1",
            "source_kind":kind,"source_id":name,"collected_at":STAMP,
            "assets":[{"asset_id":id,"type":typ,"attributes":{}} for id,typ in assets],
            "links":[{"source":src,"target":dst,"relation":relation,"evidence_id":ev}
                     for src,dst,relation,ev in links]}

class TelecomGraphTests(unittest.TestCase):
    def test_missing_router_and_link_from_inventory_detected(self):
        inventory=export("inventory","oss", [("router-a","router"),("switch-a","switch")],
                         [("router-a","switch-a","CONNECTED_TO","oss-link-1")])
        observed=export("lldp","probe", [("router-a","router"),("switch-a","switch"),("router-z","router")],
                        [("switch-a","router-z","NEIGHBOR_OF","lldp-link-2")])
        graph=build_graph([inventory,observed])
        self.assertEqual(len(graph["nodes"]),3)
        drift=compare_inventory_observations(graph)
        self.assertEqual(drift["observed_not_registered"],["router-z"])
        edges={(e["source"],e["target"]):e["status"] for e in graph["edges"]}
        self.assertEqual(edges[("switch-a","router-z")],"OBSERVED")
        self.assertEqual(edges[("router-a","switch-a")],"DECLARED")
        self.assertFalse(graph["complete_inventory_verified"])

    def test_lldp_unknown_remote_stays_unresolved(self):
        src=lldp_to_source_export({"schema":"predict-shield/lldp-export/1",
          "devices":[{"device_id":"sw-a","neighbors":[
             {"neighbor_id":"unknown-edge","local_port":"eth1","remote_port":"eth2"}]}]},
             source_id="collector-a",collected_at=STAMP)
        graph=build_graph([src])
        self.assertEqual(len(graph["unresolved_links"]),1)
        self.assertFalse(any(n["asset_id"]=="unknown-edge" for n in graph["nodes"]))

    def test_duplicate_source_identity_rejected(self):
        r=export("inventory","same",[("r1","router")])
        with self.assertRaisesRegex(ValueError,"Duplicate source"):
            build_graph([r,r])

    def test_conflicting_id_type_rejected(self):
        with self.assertRaisesRegex(ValueError,"Conflicting asset"):
            build_graph([export("inventory","one",[("x","switch")]),
                         export("lldp","two",[("x","router")])])

    def test_unverified_unknown_topology_not_assumed_complete(self):
        graph=build_graph([export("inventory","oss",[("x","router")])])
        drift=compare_inventory_observations(graph)
        self.assertEqual(drift["registered_not_observed"],["x"])
        self.assertTrue(drift["no_observation_is_not_proof_of_absence"])

    def test_invalid_time_and_missing_evidence_rejected(self):
        bad=export("lldp","src",[("a","router"),("b","router")],
                   [("a","b","NEIGHBOR_OF","")])
        with self.assertRaisesRegex(ValueError,"evidence"):
            build_graph([bad])
        bad=export("inventory","a",[("a","router")])
        bad["collected_at"]="2026-11-14T22:00:00"
        with self.assertRaisesRegex(ValueError,"timezone"):
            build_graph([bad])

    def test_device_snapshot_does_not_invent_remote_asset(self):
        lldp=lldp_to_source_export({"schema":"predict-shield/lldp-export/1",
          "devices":[{"device_id":"edge","device_type":"router",
                       "neighbors":[{"neighbor_id":"access","local_port":"ge-0/0/1","remote_port":"ge-0/0/2"}]}]},
          source_id="probe",collected_at=STAMP)
        self.assertEqual([a["asset_id"] for a in lldp["assets"]],["edge"])
        self.assertEqual(len(lldp["links"]),1)

if __name__=="__main__":
    unittest.main()
