"""Independent *laboratory* inventory reconciliation and declared service budgets.

The normal verifier must not query the experimental oracle. Instead, this
module compares the deployment's Docker Compose service inventory against the
gateway's separately credentialed live routing configuration, and checks that
observed authenticated requests actually reached every declared enforcement
process. An HTTP 403 alone never establishes complete inventory coverage.

This checks the bounded experimental deployment, NOT unregistered physical
infrastructure, cloud asset inventories, or production security correctness.
"""
from __future__ import annotations

import json
import math
import subprocess
from urllib.parse import urlsplit

ENFORCER_PREFIX = "enforcer-"


def compose_expected_enforcers() -> set[str]:
    """Enumerate intended enforcement services from Docker Compose config.

    This source is independent of gateway runtime configuration and the
    experimental oracle. Any inability to read deployment metadata fails
    closed rather than falling back to a hard-coded three-node assertion.
    """
    result = subprocess.run(
        ["docker", "compose", "config", "--format", "json"],
        capture_output=True, text=True, timeout=15, check=True,
    )
    config = json.loads(result.stdout)
    names = {name for name in config["services"] if name.startswith(ENFORCER_PREFIX)}
    if not 2 <= len(names) <= 8:
        raise ValueError("Unexpected number of configured lab enforcers")
    return names


def verify_reconciled_scope(
    expected: set[str], gateway_upstreams: list[str], probes: list[dict],
) -> dict:
    """Evaluate denial only after independent deployment and gateway agreement.

    A directly observed successful revoked request immediately refutes the
    control. Complete VERIFIED requires exact inventory agreement, one
    independently forwarded denial from each declared process, and no
    unrecognized, failed or gateway-generated responses. Restriction can
    reduce reachable attack surface while a stale enforcer still exists;
    its 403 responses without an upstream origin cannot prove remediation.
    """
    if not expected or any(not n.startswith(ENFORCER_PREFIX) for n in expected):
        raise ValueError("Invalid independently enumerated service inventory")
    if any(not isinstance(x, str) or not x.startswith("http://enforcer-")
           for x in gateway_upstreams):
        raise ValueError("Unexpected gateway routing entry")
    routed = [urlsplit(item).hostname for item in gateway_upstreams]
    routed_set = set(routed)
    valid_route = len(routed) == len(routed_set) and routed_set == expected
    responses = [p.get("http_status") for p in probes]
    if 200 in responses:
        status, reason = "NOT VERIFIED", "Revoked request allowed by a live route"
    elif not valid_route:
        status, reason = "INDETERMINATE", "Compose and gateway inventory disagree"
    else:
        forwarded = {
            urlsplit(p.get("result", {}).get("gateway_upstream", "")).hostname
            for p in probes if p.get("http_status") == 403
        }
        if (len(probes) >= len(expected) and forwarded == expected
                and all(code == 403 for code in responses)):
            status, reason = "VERIFIED", "All declared routed processes independently denied"
        else:
            status, reason = "INDETERMINATE", "Insufficient direct route coverage"
    return {
        "status": status,
        "reason": reason,
        "independent_compose_inventory": sorted(expected),
        "gateway_runtime_inventory": sorted(routed_set),
        "inventory_reconciled": valid_route,
        "observed_forwarded_targets": sorted({
            p.get("result", {}).get("gateway_upstream", "").rsplit("/", 1)[-1]
            for p in probes if p.get("result", {}).get("gateway_upstream")
        }),
        "testbed_only": True,
    }


def declared_service_budget(
    requested_rps: int, window_seconds: int, *,
    allowed_failure_fraction: float = 0.01,
) -> dict:
    """Provide an explicit laboratory SLO budget, not measured remaining capacity.

    The 1% fraction is an experimental policy assumption and not a known
    real operator SLO. Given a proposed load and measurement window, the
    maximum permitted failed-request fraction can be calculated, but
    *remaining* production error budget cannot be inferred without prior
    measured service consumption. Do not authorize automatic actions with
    this declaration alone.
    """
    if (not isinstance(requested_rps, int) or requested_rps < 1
            or not isinstance(window_seconds, int) or window_seconds < 1
            or not math.isfinite(allowed_failure_fraction)
            or not 0 < allowed_failure_fraction < 1):
        raise ValueError("Invalid declared service budget inputs")
    planned_requests = requested_rps * window_seconds
    return {
        "service": "authorization",
        "experimental_slo_success_fraction": 1 - allowed_failure_fraction,
        "planned_requests": planned_requests,
        "maximum_failed_request_fraction": allowed_failure_fraction,
        "maximum_failed_requests": math.floor(planned_requests * allowed_failure_fraction),
        "remaining_budget_verified": False,
        "requires_measured_consumption": True,
    }
