"""Generate an explicit fictional asset/advisory case for local-model smoke tests.

These are NOT real vulnerabilities, network inventories or labels.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from predict_shield.risk_evidence import canonical_digest


def generate_case(directory: Path) -> dict:
    directory.mkdir(parents=True,exist_ok=True)
    asset_id="docker:"+"e"*64
    container_id="e"*64
    image_id="sha256:"+"f"*64
    purl="pkg:maven/com.example/synthetic-demo@1.0"
    cve="CVE-2099-99999"
    discovery={
        "schema":"predict-shield/asset-discovery-report/1",
        "collected_at":datetime.now(timezone.utc).isoformat(),
        "assets":[{"asset_id":asset_id,"container_id":container_id,
                  "image_id":image_id,"service":"fictional-service",
                  "owner":"synthetic-test","criticality":"low"}],
        "reconciliation":{"matched":[container_id],"scope_status":"RECONCILED_SOURCES"},
        "sbom":{image_id:{"status":"SCANNED",
               "sbom":{"image_id":image_id,"components":[{
                   "name":"synthetic-demo","purl":purl,"version":"1.0"}]}}},
        "source_independence_authenticated":False,
        "complete_enterprise_inventory_verified":False,
    }
    discovery["sha256"]=canonical_digest(discovery)
    advisories=[{"cve":cve,"purl":purl,"source":"fictional-test-advisory",
                "text":"Fictional test only: an example package may require a vendor review. "
                       "No verified exploitation, remediation or customer impact exists."}]
    actions={"schema":"predict-shield/lab-action-catalog/1",
             "allowed_verification_checks":["review_version","reconcile_configuration"],
             "actions":[{"action_id":"request_security_review","tier":"APPROVAL",
                         "affected_services":["fictional-service"],
                         "postcondition":"An independent analyst establishes applicability",
                         "reversible":True}]}
    for name,obj in (("discovery.json",discovery),("advisories.json",advisories),
                     ("actions.json",actions)):
        path=directory/name
        if path.exists():
            raise FileExistsError("Refusing to replace evidence: "+str(path))
        path.write_text(json.dumps(obj,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    return {"source_fixture":"SYNTHETIC_NOT_A_REAL_CVE",
            "discovery_sha256":discovery["sha256"],
            "candidate_count":1,
            "action_catalog":["request_security_review"]}


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--output-dir",required=True,type=Path)
    args=parser.parse_args()
    print(json.dumps(generate_case(args.output_dir)))
