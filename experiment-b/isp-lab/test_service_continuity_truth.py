import unittest
from isp_defense import execute_and_verify

TOKEN="test-"+"a"*40
P={"lab_only":True,"selected_action":"isolate_access","policy_decision":"ELIGIBLE_LAB_ONLY",
   "scope_complete":True,"approved_lab_asset":"simulated-broadband-access"}

class ServiceContinuityTruthTests(unittest.TestCase):
    def test_unmeasured_other_services_remain_unknown(self):
        def response(base,path,**kwargs):
            if path=="/admin/isolate":return (200,{"acknowledged":True})
            if path=="/healthz":return (200,{"status":"ready"})
            return (403,{"decision":"DENY"})
        r=execute_and_verify(base="http://127.0.0.1:18310",token=TOKEN,
                             proposal=P,requester=response)
        self.assertFalse(r["cross_service_disruption_measured"])
        self.assertEqual(r["cross_service_disruption_outcome"],"UNKNOWN")
        self.assertNotIn("measured_disruption_to_other_services",r)
if __name__=="__main__":unittest.main()
