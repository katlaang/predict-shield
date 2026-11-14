"""Optional read-only local gateway and SBOM adapters.

The gateway endpoint MUST independently report its own observed full container IDs.
A copied Docker inventory is not independent evidence. No VERIFIED claim is made.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from predict_shield.asset_discovery import build_report, docker_inspect, load_gateway_snapshot

_IMAGE_ID = re.compile(r"^sha256:[a-fA-F0-9]{64}$")
_ALLOWED_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def fetch_local_gateway(url: str, *, opener=urlopen, max_bytes: int = 1024 * 1024) -> dict:
    """Only query explicit localhost HTTP gateway adapters, fail closed."""
    p = urlsplit(url)
    if (p.scheme != "http" or p.hostname not in _ALLOWED_HOSTS or
            p.username or p.password or p.fragment or not p.port):
        raise ValueError("Gateway URL must be explicit local HTTP with a port")
    # Redirects must not escape localhost. Disable them for the default opener.
    from urllib.request import build_opener, HTTPRedirectHandler
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    actual_opener = build_opener(NoRedirect()).open if opener is urlopen else opener
    with actual_opener(Request(url, method="GET", headers={"Accept": "application/json"}),
                       timeout=5) as response:
        if response.status != 200:
            raise ValueError("Gateway response was not HTTP 200")
        body = response.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise ValueError("Oversized gateway response")
    payload = json.loads(body)
    # Reuse the exact schema validation path, without writing an untrusted temp file.
    if (not isinstance(payload, dict) or
            payload.get("schema") != "predict-shield/gateway-observation/1" or
            not isinstance(payload.get("source"), str) or not payload["source"] or
            not isinstance(payload.get("collected_at"), str) or not payload["collected_at"]):
        raise ValueError("Malformed gateway observation")
    identities = payload.get("observed_container_ids")
    if (not isinstance(identities, list) or
            any(not isinstance(v, str) or len(v) < 12 for v in identities) or
            len(set(identities)) != len(identities)):
        raise ValueError("Invalid gateway observed container identities")
    return payload


def scan_running_image(image_id: str, *, runner=subprocess.run) -> dict:
    """Syft reads the exact Docker image ID, not a mutable tag."""
    if not _IMAGE_ID.fullmatch(image_id):
        raise ValueError("A complete immutable Docker image SHA256 ID is required")
    completed = runner(["syft", "docker:" + image_id, "-o", "cyclonedx-json"],
                       capture_output=True, text=True, timeout=90, check=True)
    data = json.loads(completed.stdout)
    if not isinstance(data, dict) or data.get("bomFormat") != "CycloneDX" or not isinstance(data.get("components", []), list):
        raise ValueError("Unexpected Syft CycloneDX output")
    return {
        "image_id": image_id,
        "format": "CycloneDX",
        "component_count": len(data.get("components", [])),
        "components": [
            {"name": str(c.get("name") or ""), "version": str(c.get("version") or ""),
             "purl": c.get("purl")}
            for c in data.get("components", []) if isinstance(c, dict)
        ],
    }


def scan_images(assets: list[dict], *, runner=subprocess.run) -> dict:
    """All scan errors are explicit; no scan failure is treated as clean software."""
    results = {}
    for image_id in sorted({a["image_id"] for a in assets if a["image_id"]}):
        try:
            results[image_id] = {"status": "SCANNED", "sbom": scan_running_image(image_id, runner=runner)}
        except (ValueError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
            results[image_id] = {"status": "UNAVAILABLE", "error_type": type(exc).__name__}
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only discovery with optional local gateway and Syft")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--gateway-url", help="Local independent gateway JSON exporter, explicit port")
    source.add_argument("--gateway-snapshot", type=Path)
    parser.add_argument("--scan-sbom", action="store_true", help="Requires installed Syft and Docker access")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Refusing to overwrite discovery evidence")
    gateway = (fetch_local_gateway(args.gateway_url) if args.gateway_url else
               load_gateway_snapshot(args.gateway_snapshot) if args.gateway_snapshot else None)
    report = build_report(docker_inspect(), gateway)
    report["sbom"] = scan_images(report["assets"]) if args.scan_sbom else {
        "status": "NOT_REQUESTED", "note": "SBOM status is unknown, not clean"}
    report["live_gateway_source_authenticated"] = False
    report["complete_enterprise_inventory_verified"] = False
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("Assets:", len(report["assets"]), "scope:", report["reconciliation"]["scope_status"])


if __name__ == "__main__":
    main()
