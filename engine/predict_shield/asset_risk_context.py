"""Join actual image SBOM evidence to advisory candidates without inventing findings."""
import argparse
import hashlib
import json
from pathlib import Path

def contextualize(discovery, advisories):
    if discovery.get("schema") != "predict-shield/asset-discovery-report/1":
        raise ValueError("Expected discovery report with image SBOMs")
    if not isinstance(discovery.get("assets"), list):
        raise ValueError("Missing assets")
    if not isinstance(advisories, list):
        raise ValueError("Advisories must be a list")
    index = {}
    for a in advisories:
        if not isinstance(a, dict) or not isinstance(a.get("purl"), str) or not a["purl"].startswith("pkg:") or not isinstance(a.get("cve"), str) or not a["cve"].startswith("CVE-") or not a.get("source"):
            raise ValueError("Advisory requires exact purl, CVE and source")
        key = (a["purl"], a["cve"])
        if key in index:
            raise ValueError("Duplicate advisory")
        index[key] = a["source"]
    sboms = discovery.get("sbom", {})
    if not isinstance(sboms, dict):
        sboms = {}
    rows = []
    for asset in discovery["assets"]:
        image, identity = asset.get("image_id"), asset.get("asset_id")
        if not isinstance(image, str) or not identity:
            raise ValueError("Invalid asset identity")
        found = sboms.get(image, {})
        status = found.get("status", "NOT_SCANNED")
        candidates = []
        if status == "SCANNED":
            sbom = found.get("sbom", {})
            if sbom.get("image_id") != image or not isinstance(sbom.get("components"), list):
                raise ValueError("SBOM image identity or components mismatch")
            for component in sbom["components"]:
                if not isinstance(component, dict):
                    raise ValueError("Invalid SBOM component")
                purl = component.get("purl")
                for (advisory_purl, cve), source in index.items():
                    if purl == advisory_purl:
                        candidates.append({"purl": purl, "cve": cve, "source": source, "status": "REQUIRES_APPLICABILITY_VALIDATION"})
        rows.append({"asset_id": identity, "service": asset.get("service"), "image_id": image,
                     "owner": asset.get("owner"), "criticality": asset.get("criticality"),
                     "sbom_status": status, "advisory_candidates": sorted(candidates, key=lambda a:(a["cve"],a["purl"])),
                     "confirmed_vulnerability": False})
    result = {"schema": "predict-shield/asset-risk-context/1",
              "discovery_digest": discovery.get("sha256"), "discovery_scope_verified": False,
              "ai_prediction": False, "rows": sorted(rows, key=lambda a:a["asset_id"])}
    result["sha256"] = hashlib.sha256(json.dumps(result, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return result

def main():
    p = argparse.ArgumentParser(description="Build evidence context; no CVE validation or AI inference")
    p.add_argument("--discovery", type=Path, required=True)
    p.add_argument("--advisories", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    if args.output.exists():
        p.error("Refusing to overwrite evidence")
    result = contextualize(json.loads(args.discovery.read_text()), json.loads(args.advisories.read_text()))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True)+"\n")

if __name__ == "__main__":
    main()
