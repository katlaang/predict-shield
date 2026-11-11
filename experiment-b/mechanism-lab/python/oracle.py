"""Separately deployed oracle observer for the Experiment B mechanism lab.

Unlike the external gateway verifier, this process has an explicit expected
inventory and queries each enforcement node directly over a private admin
path. It also issues a direct active HTTP probe to each target and checks the
authority's current desired revision. Agreement between actual deny probes
and cache state supports a lab ground-truth observation; a missing instance,
contradiction or unavailable authority produces unknown truth rather than a
fabricated pass.

The oracle is operated with an independent credential and never returns its
output to the AI model through the experiment's pre-action feature path.
The admin cache reports are still self-reports, not cryptographic attestations.
"""
from __future__ import annotations
import json
import os
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NODES = tuple(os.environ.get("ENFORCERS", "").split(","))
AUTHORITY = os.environ.get("AUTHORITY_URL", "")
ORACLE_TOKEN = os.environ.get("LAB_ORACLE_TOKEN", "")
INTERNAL_TOKEN = os.environ.get("LAB_INTERNAL_TOKEN", "")


def request_json(url: str, token_header: str | None = None,
                 token: str | None = None) -> tuple[int | None, dict]:
    """Request one internal observation and preserve unreachable states."""
    headers = {token_header: token} if token_header and token else {}
    try:
        with urllib.request.urlopen(
            urllib.request.Request(url, headers=headers), timeout=1.5
        ) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as err:
        try:
            return err.code, json.load(err)
        except (ValueError, OSError):
            return err.code, {"error": "invalid error response"}
    except (OSError, TimeoutError, ValueError):
        return None, {"error": "unreachable"}


def observe() -> dict:
    """Compare an authoritative policy with all known target cache and HTTP states.

    An oracle result can be true, false, or unknown. The observer never infers
    complete coverage from a gateway response, and never silently excludes an
    unavailable node from the declared inventory.
    """
    policy_status, policy = request_json(
        AUTHORITY + "/oracle/policy", "X-Lab-Oracle", INTERNAL_TOKEN
    )
    target_records = []
    for node in NODES:
        admin_status, admin = request_json(
            node + "/admin/state", "X-Lab-Oracle", ORACLE_TOKEN
        )
        probe_status, probe = request_json(node + "/protected")
        target_records.append({
            "node": node,
            "admin_http": admin_status,
            "admin": admin,
            "direct_probe_http": probe_status,
            "direct_probe": probe,
        })
    valid_authority = policy_status == 200 and type(policy.get("revoked")) is bool
    complete = valid_authority and all(
        t["admin_http"] == 200 and t["direct_probe_http"] in (200, 403)
        and type(t["admin"].get("revoked")) is bool for t in target_records
    )
    if not complete:
        truth = None
    else:
        expected_denial = policy["revoked"]
        consistent = all(
            (t["direct_probe_http"] == 403) == t["admin"]["revoked"]
            for t in target_records
        )
        truth = (consistent and all(t["direct_probe_http"] == 403
                for t in target_records)) if expected_denial else None
    return {
        "oracle_type": "separate_process_direct_admin_and_active_probe",
        "authority": policy,
        "authority_http": policy_status,
        "expected_inventory_count": len(NODES),
        "inventory_complete": bool(complete),
        "targets": target_records,
        "all_revoked_access_denied": truth,
        "oracle_limitation": "Known inventory; admin cache state not attested",
    }


class OracleHandler(BaseHTTPRequestHandler):
    """Serve protected ground truth only to the trusted evaluation runner."""

    def do_GET(self) -> None:
        """Return an oracle snapshot or refuse an invalid lab credential."""
        if self.path == "/healthz":
            payload = b'{"oracle":"ready"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path != "/oracle/observe":
            self.send_error(404)
            return
        if not ORACLE_TOKEN or self.headers.get("X-Lab-Oracle") != ORACLE_TOKEN:
            self.send_error(403)
            return
        payload = json.dumps(observe()).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        """Avoid logging credentials or other protected observer metadata."""
        return


def main() -> None:
    """Expose the oracle only through the un-published Docker network port."""
    if not NODES or not ORACLE_TOKEN or not INTERNAL_TOKEN:
        raise RuntimeError("Oracle requires inventory and separate credentials")
    ThreadingHTTPServer(("0.0.0.0", 8080), OracleHandler).serve_forever()


if __name__ == "__main__":
    main()
