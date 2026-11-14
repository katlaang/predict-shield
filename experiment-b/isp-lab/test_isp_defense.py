import unittest
from isp_defense import execute_and_verify

TOKEN="lab-token-"+"a"*32
PROPOSAL={"research_lab_only":True,"selected_action":"isolate_access",
          "policy_decision":"ELIGIBLE_LAB_ONLY","scope_complete":True,
          "approved_lab_asset":"simulated-broadband-access"}

class DefenseTests(unittest.TestCase):
    def test_independently_probed_denial(self):
        calls=[]
        def fake(base,path,**kwargs):
            calls.append((path,kwargs.get("method","GET")))
            if path=="/admin/isolate":return 200,{"acknowledged":True}
            if path=="/healthz":return 200,{"status":"ready"}
            return 403,{"decision":"DENY"}
        r=execute_and_verify(base="http://127.0.0.1:18310",token=TOKEN,
                             proposal=PROPOSAL,requester=fake)
        self.assertEqual(r["postcondition"],"VERIFIED_LAB_ONLY")
        self.assertEqual(calls.count(("/protected","GET")),7)
    def test_acknowledgment_without_denial_fails(self):
        def fake(base,path,**kwargs):
            if path=="/admin/isolate":return 200,{"acknowledged":True}
            if path=="/healthz":return 200,{}
            return 200,{"decision":"ALLOW"}
        r=execute_and_verify(base="http://localhost:18310",token=TOKEN,
                             proposal=PROPOSAL,requester=fake)
        self.assertEqual(r["postcondition"],"NOT_VERIFIED_LAB_ONLY")
    def test_model_cannot_bypass_policy(self):
        bad={**PROPOSAL,"policy_decision":"AI_PREFERRED"}
        with self.assertRaises(ValueError):
            execute_and_verify(base="http://127.0.0.1:18310",token=TOKEN,proposal=bad)
    def test_remote_target_denied(self):
        with self.assertRaises(ValueError):
            execute_and_verify(base="http://example.org:18310",token=TOKEN,
                                proposal=PROPOSAL)
if __name__=="__main__":unittest.main()
