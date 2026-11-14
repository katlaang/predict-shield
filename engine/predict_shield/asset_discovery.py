"""Read-only discovery of Docker containers and independent gateway evidence.

This module does not execute remediation or assert complete infrastructure scope.
Only exact runtime container IDs are treated as reconciled identities.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def docker_inspect(*, runner: Callable = subprocess.run) -> list[dict]:
    """Query local Docker using read-only inspect; fail if enumeration fails."""
    ps = runner(["docker", "ps", "--no-trunc", "--quiet"], capture_output=True,
                text=True, check=True, timeout=20)
    ids = [item.strip() for item in ps.stdout.splitlines() if item.strip()]
    if not ids:
        return []
    inspected = runner(["docker", "container", "inspect", *ids],
                       capture_output=True, text=True, check=True, timeout=30)
    data = json.loads(inspected.stdout)
    if not isinstance(data, list) or len(data) != len(ids):
        raise ValueError("Docker inspect enumeration incomplete")
    returned = {str(item.get("Id", "")) for item in data}
    if returned != set(ids):
        raise ValueError("Docker inspect identities differ from docker ps")
    return data


def normalize_runtime(inspected: list[dict]) -> list[dict]:
    assets = []
    seen = set()
    for item in inspected:
        identity = item.get("Id")
        if not isinstance(identity, str) or len(identity) < 12 or identity in seen:
            raise ValueError("Missing or duplicate Docker container identity")
        seen.add(identity)
        labels = item.get("Config", {}).get("Labels") or {}
        if not isinstance(labels, dict):
            raise ValueError("Unexpected container labels")
        assets.append({
            "asset_id": "docker:" + identity,
            "container_id": identity,
            "name": str(item.get("Name", "")).lstrip("/"),
            "image_id": str(item.get("Image") or ""),
            "image_reference": str(item.get("Config", {}).get("Image") or ""),
            "started_at": item.get("State", {}).get("StartedAt"),
            "service": labels.get("com.docker.compose.service"),
            "project": labels.get("com.docker.compose.project"),
            "owner": labels.get("org.predict-shield.owner"),
            "criticality": labels.get("org.predict-shield.criticality"),
        })
    return sorted(assets, key=lambda a: a["asset_id"])


def load_gateway_snapshot(path: Path) -> dict:
    """Import a separately collected snapshot, never represent it as a live probe."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema") != "predict-shield/gateway-observation/1":
        raise ValueError("Unsupported independent gateway snapshot schema")
    if not isinstance(payload.get("collected_at"), str) or not payload["collected_at"]:
        raise ValueError("Missing gateway observation collection time")
    ids = payload.get("observed_container_ids")
    if not isinstance(ids, list) or any(not isinstance(x, str) or len(x) < 12 for x in ids):
        raise ValueError("Gateway observation must enumerate full container IDs")
    if len(set(ids)) != len(ids):
        raise ValueError("Duplicate gateway identity")
    if not isinstance(payload.get("source"), str) or not payload["source"]:
        raise ValueError("Missing gateway provenance")
    return payload


def reconcile(runtime: list[dict], gateway: dict | None) -> dict:
    runtime_ids = {a["container_id"] for a in runtime}
    if gateway is None:
        return {
            "scope_status": "INDETERMINATE",
            "reason": "Independent gateway observation unavailable",
            "runtime_only": sorted(runtime_ids),
            "gateway_only": [],
            "matched": [],
        }
    gateway_ids = set(gateway["observed_container_ids"])
    return {
        "scope_status": "RECONCILED_SOURCES" if runtime_ids == gateway_ids else "DRIFT_DETECTED",
        "reason": "Source membership equality only; not complete infrastructure verification",
        "runtime_only": sorted(runtime_ids - gateway_ids),
        "gateway_only": sorted(gateway_ids - runtime_ids),
        "matched": sorted(runtime_ids & gateway_ids),
    }


def build_report(inspected: list[dict], gateway: dict | None = None) -> dict:
    assets = normalize_runtime(inspected)
    result = reconcile(assets, gateway)
    result["missing_owner"] = sorted(a["asset_id"] for a in assets if not a["owner"])
    result["missing_criticality"] = sorted(a["asset_id"] for a in assets if not a["criticality"])
    result["missing_image_digest"] = sorted(a["asset_id"] for a in assets if not a["image_id"])
    snapshot = {
        "schema": "predict-shield/asset-discovery-report/1",
        "collected_at": utc_now(),
        "runtime_source": "docker-container-inspect",
        "gateway_source": gateway["source"] if gateway else None,
        "gateway_collected_at": gateway["collected_at"] if gateway else None,
        "source_independence_authenticated": False,
        "complete_enterprise_inventory_verified": False,
        "assets": assets,
        "reconciliation": result,
    }
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
    snapshot["sha256"] = hashlib.sha256(canonical).hexdigest()
    return snapshot


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only Docker discovery; no actions taken")
    parser.add_argument("--gateway-snapshot", type=Path, help="Separately captured gateway membership JSON")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Refusing to overwrite an existing evidence report")
    gateway = load_gateway_snapshot(args.gateway_snapshot) if args.gateway_snapshot else None
    report = build_report(docker_inspect(), gateway)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Discovered {len(report['assets'])} containers; scope: {report['reconciliation']['scope_status']}")


if __name__ == "__main__":
    main()
