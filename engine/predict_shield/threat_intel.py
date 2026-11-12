"""Dated threat-context ingestion and transparent prioritization baseline.

This is NOT a trained predictive model or a calibrated probability of loss.
Do not substitute today's EPSS/KEV feeds for historical as-of snapshots.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
from datetime import date
from pathlib import Path


def _date(value: str) -> date:
    return date.fromisoformat(value)


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_epss(path: str | Path, snapshot_date: str, as_of: str) -> tuple[dict, dict]:
    """Read an explicitly dated EPSS CSV. Reject look-ahead snapshots."""
    observed = _date(snapshot_date)
    cutoff = _date(as_of)
    if observed > cutoff:
        raise ValueError("EPSS snapshot is after as_of: look-ahead prohibited")
    raw = Path(path).read_bytes()
    # FIRST EPSS CSV releases may contain a leading '#model_version...' comment.
    lines = [line for line in raw.decode("utf-8-sig").splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    if not {"cve", "epss"}.issubset(set(reader.fieldnames or [])):
        raise ValueError("EPSS CSV requires cve and epss columns")
    scores = {}
    for row in reader:
        cve = row["cve"].strip().upper()
        if not cve.startswith("CVE-") or cve in scores:
            raise ValueError("invalid or duplicate EPSS CVE")
        probability = float(row["epss"])
        if not 0 <= probability <= 1:
            raise ValueError("EPSS probability outside [0,1]")
        scores[cve] = probability
    return scores, {"source": "EPSS", "snapshot_date": observed.isoformat(),
                    "sha256": _hash(raw), "record_count": len(scores)}


def read_kev(path: str | Path, snapshot_date: str, as_of: str) -> tuple[dict, dict]:
    """Read archived CISA KEV JSON; only entries added by as_of are eligible."""
    observed = _date(snapshot_date)
    cutoff = _date(as_of)
    if observed > cutoff:
        raise ValueError("KEV snapshot is after as_of: look-ahead prohibited")
    raw = Path(path).read_bytes()
    payload = json.loads(raw)
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise ValueError("KEV JSON must contain vulnerabilities array")
    entries = {}
    for row in payload["vulnerabilities"]:
        cve = row["cveID"].strip().upper()
        added = _date(row["dateAdded"])
        if cve in entries:
            raise ValueError("duplicate KEV CVE")
        if added <= cutoff:
            entries[cve] = added.isoformat()
    return entries, {"source": "CISA KEV", "snapshot_date": observed.isoformat(),
                     "sha256": _hash(raw), "record_count_as_of": len(entries)}


def prioritize(assets: list[dict], epss: dict, kev: dict, as_of: str) -> list[dict]:
    """Rank asset-vulnerability pairs, retaining missing EPSS as unknown.

    Composite is a transparent, uncalibrated research heuristic. It is not
    exploit probability, monetary loss, CVSS, or a model prediction.
    """
    _date(as_of)
    results = []
    seen = set()
    for asset in assets:
        asset_id = str(asset["asset_id"])
        cve = str(asset["cve"]).upper()
        key = (asset_id, cve)
        if key in seen:
            raise ValueError("duplicate asset-vulnerability pair")
        seen.add(key)
        criticality = float(asset["criticality"])
        exposure = float(asset["exposure"])
        if not 0 <= criticality <= 1 or not 0 <= exposure <= 1:
            raise ValueError("criticality and exposure must be in [0,1]")
        p = epss.get(cve)
        if p is not None and not 0 <= float(p) <= 1:
            raise ValueError("invalid EPSS score")
        known_exploited = cve in kev
        # Unknown EPSS is not treated as zero, and is never silently ranked.
        score = None if p is None else round(
            0.55 * float(p) + 0.20 * float(known_exploited)
            + 0.15 * criticality + 0.10 * exposure, 6)
        results.append({"asset_id": asset_id, "cve": cve, "as_of": as_of,
                        "epss": p, "kev_known_exploited": known_exploited,
                        "kev_date_added": kev.get(cve),
                        "criticality": criticality, "exposure": exposure,
                        "heuristic_score": score,
                        "status": "RANKED" if score is not None else "INSUFFICIENT_EPSS",
                        "calibrated_probability": False})
    return sorted(results, key=lambda x: (x["heuristic_score"] is None,
                                           -(x["heuristic_score"] or 0),
                                           x["asset_id"], x["cve"]))


def build_report(epss_path: str, epss_date: str, kev_path: str,
                 kev_date: str, assets_path: str, as_of: str) -> dict:
    ep, ep_meta = read_epss(epss_path, epss_date, as_of)
    kv, kv_meta = read_kev(kev_path, kev_date, as_of)
    raw = Path(assets_path).read_bytes()
    assets = json.loads(raw)
    if not isinstance(assets, list):
        raise ValueError("assets must be a JSON list")
    return {"schema_version": "threat-baseline-v1", "as_of": as_of,
            "source_provenance": [ep_meta, kv_meta,
                                  {"source": "asset_fixture", "sha256": _hash(raw)}],
            "scoring_method": "uncalibrated_transparent_heuristic",
            "rows": prioritize(assets, ep, kv, as_of)}


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Offline dated EPSS/KEV asset prioritization")
    parser.add_argument("--epss", required=True)
    parser.add_argument("--epss-date", required=True)
    parser.add_argument("--kev", required=True)
    parser.add_argument("--kev-date", required=True)
    parser.add_argument("--assets", required=True)
    parser.add_argument("--as-of", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    report = build_report(args.epss, args.epss_date, args.kev, args.kev_date,
                          args.assets, args.as_of)
    Path(args.output).write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
