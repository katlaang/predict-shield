import unittest
from predict_shield.asset_risk_context import contextualize
I = "sha256:" + "a" * 64

def fixture():
    return {"schema":"predict-shield/asset-discovery-report/1","sha256":"synthetic",
            "assets":[{"asset_id":"docker:one","image_id":I,"service":"enforcer-a"},
                      {"asset_id":"docker:two","image_id":"sha256:other"}],
            "sbom":{I:{"status":"SCANNED","sbom":{"image_id":I,"components":[
                {"purl":"pkg:maven/example@1.0","name":"example"}]}}}}

class TestContext(unittest.TestCase):
    def test_candidate_is_not_confirmed(self):
        x=contextualize(fixture(),[{"purl":"pkg:maven/example@1.0","cve":"CVE-2026-12345","source":"synthetic"}])
        self.assertEqual(len(x["rows"][0]["advisory_candidates"]),1)
        self.assertFalse(x["rows"][0]["confirmed_vulnerability"])
        self.assertFalse(x["ai_prediction"])
        self.assertEqual(x["rows"][1]["sbom_status"],"NOT_SCANNED")
    def test_unmatched_is_not_a_finding(self):
        x=contextualize(fixture(),[{"purl":"pkg:maven/other@1.0","cve":"CVE-2026-12345","source":"synthetic"}])
        self.assertEqual(x["rows"][0]["advisory_candidates"],[])
    def test_mismatched_image_fails(self):
        d=fixture(); d["sbom"][I]["sbom"]["image_id"]="sha256:wrong"
        with self.assertRaises(ValueError): contextualize(d,[])
    def test_missing_source_rejected(self):
        with self.assertRaises(ValueError):
            contextualize(fixture(),[{"purl":"pkg:maven/example@1.0","cve":"CVE-2026-12345"}])
    def test_duplicate_advisory_rejected(self):
        a={"purl":"pkg:maven/example@1.0","cve":"CVE-2026-12345","source":"synthetic"}
        with self.assertRaisesRegex(ValueError,"Duplicate"): contextualize(fixture(),[a,a])
if __name__=="__main__": unittest.main()
