"""Live laboratory evidence path for learned, policy-gated defense recommendations.

Unlike the conservative advisory context, this uses two LIVE lab inventories
and independently observed gateway forwards. Trust is bounded to a disposable
localhost lab; it is not a production source attestation.
"""
from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlsplit
import json
import urllib.error
import urllib.request

from .ai_contracts import EvidenceSnapshot
from .asset_discovery import docker_inspect
from .lab_gateway_discovery import live_gateway_routes, reconcile_lab_services


def evaluate_lab_scope(report: dict, observations: list[dict], *, case_id: str,
                       captured_at: datetime | None = None) -> tuple[EvidenceSnapshot, dict]:
    """Establish a bounded testbed scope only when every expected process was forwarded to."""
    if not case_id:
        raise ValueError("Case ID required")
    now = captured_at or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("Timezone-aware timestamp required")
    expected = set(report.get("running_enforcer_services", []))
    routed = set(report.get("gateway_routed_services", []))
    reasons = []
    if (report.get("schema") != "predict-shield/physical-lab-discovery/1" or
            report.get("reconciliation_status") != "RECONCILED_SOURCES" or
            not expected or expected != routed or report.get("ambiguous_scaled_services")):
        reasons.append("INVENTORY_NOT_RECONCILED")
    if report.get("gateway_source") != "live-lab-gateway-config":
        reasons.append("GATEWAY_SOURCE_NOT_LIVE")
    seen = set()
    if not isinstance(observations, list):
        raise ValueError("Probe observations must be a list")
    for observation in observations:
        if not isinstance(observation, dict):
            raise ValueError("Invalid observation")
        # A gateway-generated 403 has no forwarding witness and is not counted.
        upstream = observation.get("gateway_upstream")
        status = observation.get("http_status")
        if not isinstance(upstream, str) or status not in (200, 403):
            continue
        parsed = urlsplit(upstream)
        if (parsed.scheme == "http" and parsed.port == 8080 and
                parsed.hostname in routed and parsed.path in ("", "/")):
            seen.add(parsed.hostname)
    if not expected or not expected.issubset(seen):
        reasons.append("INCOMPLETE_FORWARDED_PROBES")
    # Gateway config is independently requested from the gateway while
    # Docker is interrogated through the host. This is scoped lab trust,
    # not cryptographic provenance or a guarantee about unknown infrastructure.
    supported = not reasons
    evidence = EvidenceSnapshot(
        snapshot_id="lab-scope:" + str(report.get("sha256", "unhashed")),
        case_id=case_id, captured_at=now,
        source_ids=("docker-inspect", "gateway-live-admin", "gateway-forwarded-probes"),
        trusted=supported, scope_complete=supported,
    )
    return evidence, {
        "status": "LAB_SCOPE_SUPPORTED" if supported else "ESCALATE_FOR_EVIDENCE",
        "reasons": sorted(reasons),
        "forwarded_targets": sorted(seen),
        "required_targets": sorted(expected),
        "laboratory_only": True,
        "production_scope_attested": False,
        "vulnerability_applicability_established": False,
    }


def probe_gateway_forwarding(url: str, *, attempts: int = 24,
                             opener=None) -> list[dict]:
    """Read-only requests; preserve real upstream evidence, including allow/deny."""
    parsed = urlsplit(url)
    if (parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost", "::1")
            or not parsed.port or parsed.path != "/protected"
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ValueError("Protected probe must target explicit loopback lab gateway")
    if not 1 <= attempts <= 64:
        raise ValueError("Bounded probe count required")
    # Restrict redirect following, including to off-host addresses.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    transport = opener if opener is not None else urllib.request.build_opener(NoRedirect()).open
    results = []
    for _ in range(attempts):
        request = urllib.request.Request(url, method="GET")
        try:
            with transport(request, timeout=3) as response:
                status, raw = response.status, response.read(8193)
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, exc.read(8193)
        if len(raw) > 8192:
            raise ValueError("Oversize gateway probe response")
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeError):
            body = {}
        results.append({
            "http_status": status,
            "gateway_upstream": body.get("gateway_upstream") if isinstance(body, dict) else None,
        })
    return results


def collect_live_scope(*, project: str, token: str, case_id: str,
                       gateway_base: str = "http://127.0.0.1:18280"):
    """Collect all three sources in one operation, avoiding caller-crafted evidence."""
    if gateway_base != "http://127.0.0.1:18280":
        raise ValueError("Only the fixed isolated laboratory gateway is permitted")
    routes = live_gateway_routes(gateway_base + "/admin/inventory", token)
    runtime = docker_inspect()
    report = reconcile_lab_services(runtime, routes, project=project)
    probes = probe_gateway_forwarding(gateway_base + "/protected")
    snapshot, assessment = evaluate_lab_scope(report, probes, case_id=case_id)
    return snapshot, assessment, report
