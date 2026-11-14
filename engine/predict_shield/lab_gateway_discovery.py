"""Read-only reconciliation of running Compose services and live gateway routes.

The gateway exposes configured routes, NOT proof that requests reached every
target. This module never declares security VERIFIED or complete asset scope.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler

from predict_shield.asset_discovery import docker_inspect, normalize_runtime, utc_now

class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def live_gateway_routes(url: str, token: str, *, opener=None) -> dict:
    """Query the lab's actual authenticated gateway inventory, fail closed."""
    parsed = urlsplit(url)
    if (parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or parsed.port is None or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path != "/admin/inventory"):
        raise ValueError("Gateway inventory must use an explicit loopback /admin/inventory URL")
    if not isinstance(token, str) or not token:
        raise ValueError("The lab control token must be present")
    request = Request(url, method="GET", headers={"X-Lab-Control": token, "Accept": "application/json"})
    open_fn = opener if opener is not None else build_opener(_NoRedirect()).open
    with open_fn(request, timeout=5) as response:
        if response.status != 200:
            raise ValueError("Gateway inventory HTTP status was not 200")
        data = response.read(65537)
    if len(data) > 65536:
        raise ValueError("Gateway inventory exceeded size limit")
    payload = json.loads(data)
    if not isinstance(payload, dict) or payload.get("scope") != "gateway-config-only":
        raise ValueError("Unsupported gateway inventory contract")
    routes = payload.get("upstreams")
    if not isinstance(routes, list) or len(routes) > 32 or len(set(routes)) != len(routes):
        raise ValueError("Gateway upstreams missing, duplicated or over limit")
    services = []
    for value in routes:
        if not isinstance(value, str):
            raise ValueError("Invalid gateway route")
        p = urlsplit(value)
        if (p.scheme != "http" or not p.hostname or not p.hostname.startswith("enforcer-")
                or p.port != 8080 or p.path not in ("", "/")
                or p.query or p.fragment or p.username or p.password):
            raise ValueError("Invalid gateway upstream identity")
        services.append(p.hostname)
    if len(services) != len(set(services)):
        raise ValueError("Duplicate gateway service")
    return {"services": sorted(services), "routing_profile": payload.get("traffic_profile"),
            "source": "live-lab-gateway-config", "collected_at": utc_now()}


def reconcile_lab_services(inspected: list[dict], routes: dict, *, project: str) -> dict:
    """Compare service identities without equating routes to active HTTP probes."""
    if not project or not isinstance(project, str):
        raise ValueError("Explicit Compose project is required")
    assets = [a for a in normalize_runtime(inspected) if a["project"] == project]
    if not assets:
        raise ValueError("No running assets for the specified Compose project")
    enforcers = [a for a in assets if isinstance(a["service"], str) and a["service"].startswith("enforcer-")]
    by_service = {}
    for asset in enforcers:
        by_service.setdefault(asset["service"], []).append(asset["asset_id"])
    gateway_services = set(routes["services"])
    running_services = set(by_service)
    duplicate = sorted(k for k, v in by_service.items() if len(v) != 1)
    drift = sorted(running_services ^ gateway_services)
    status = "DRIFT_DETECTED" if drift or duplicate else "RECONCILED_SOURCES"
    report = {
        "schema": "predict-shield/physical-lab-discovery/1",
        "collected_at": utc_now(),
        "project": project,
        "gateway_source": routes["source"],
        "gateway_collected_at": routes["collected_at"],
        "gateway_config_only_not_active_probe": True,
        "authenticated_source_identity_verified": False,
        "complete_enterprise_scope_verified": False,
        "security_verification_outcome": "INDETERMINATE",
        "reconciliation_status": status,
        "running_enforcer_services": sorted(running_services),
        "gateway_routed_services": sorted(gateway_services),
        "runtime_only_services": sorted(running_services - gateway_services),
        "gateway_only_services": sorted(gateway_services - running_services),
        "ambiguous_scaled_services": duplicate,
        "assets": assets,
    }
    digest = hashlib.sha256(json.dumps(report, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    report["sha256"] = digest
    return report


def main():
    parser = argparse.ArgumentParser(description="Read-only physical mechanism-lab gateway discovery")
    parser.add_argument("--project", required=True, help="Exact Docker Compose project label")
    parser.add_argument("--gateway-url", default="http://127.0.0.1:18280/admin/inventory")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Refusing to overwrite prior discovery evidence")
    result = reconcile_lab_services(
        docker_inspect(), live_gateway_routes(args.gateway_url, os.environ.get("LAB_CONTROL_TOKEN", "")),
        project=args.project)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("Lab gateway reconciliation:", result["reconciliation_status"],
          "runtime only:", result["runtime_only_services"],
          "gateway only:", result["gateway_only_services"])


if __name__ == "__main__":
    main()
