import json
import tempfile
import unittest
from pathlib import Path

from predict_shield.run_ai_case import load_catalog


class CliCatalogTests(unittest.TestCase):
    def test_catalog_has_concrete_nonexecuting_policy_action_options(self):
        obj={"schema":"predict-shield/lab-action-catalog/1",
             "actions":[{"action_id":"request_security_review",
                         "tier":"APPROVAL","affected_services":["authorization"],
                         "postcondition":"Analyst checks vulnerability applicability",
                         "reversible":True}],
             "allowed_verification_checks":["recheck_package_version"]}
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/"catalog.json"
            p.write_text(json.dumps(obj))
            actions,checks=load_catalog(p)
        self.assertEqual(actions[0].action_id,"request_security_review")
        self.assertEqual(actions[0].tier.value,"APPROVAL")
        self.assertEqual(checks,("recheck_package_version",))
    def test_duplicate_checks_fail_closed(self):
        obj={"schema":"predict-shield/lab-action-catalog/1",
             "actions":[{"action_id":"review",
                         "tier":"APPROVAL","affected_services":["auth"],
                         "postcondition":"Review","reversible":True}],
             "allowed_verification_checks":["check","check"]}
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/"catalog.json"
            p.write_text(json.dumps(obj))
            with self.assertRaisesRegex(ValueError,"Duplicate"):
                load_catalog(p)

if __name__=="__main__":
    unittest.main()
