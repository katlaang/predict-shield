"""Experiment B: read-only probing and strictly scoped lab-only correction.

Pre-alpha. No arbitrary URL input, no production deployment, no general-purpose
remote command executor. Correction requires an explicit opt-in and disposable
lab token. HTTP status is independently probed after any acknowledgment.
"""
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
import json
import os
import urllib.error
import urllib.request

ALLOWED = frozenset(("http://127.0.0.1:18081", "http://127.0.0.1:18082"))

class Status(str, Enum):
    VERIFIED = "VERIFIED"
    NOT_VERIFIED = "NOT VERIFIED"
    INDETERMINATE = "INDETERMINATE"

@dataclass(frozen=True)
class Observation:
    instance: str
    status_code: int | None
    checked_at: str
    error: str | None = None

@dataclass(frozen=True)
class Result:
    outcome: str
    observations: list[Observation]
    actions: list[dict]
    reason: str

def fetch_status(url: str, token: str | None = None, method: str = "GET") -> int:
    if not any(url == root + path for root in ALLOWED
               for path in ("/api/protected", "/lab/revoke")):
        raise ValueError("URL outside local lab allowlist")
    request = urllib.request.Request(
        url, method=method,
        headers=({"X-Lab-Token": token} if token else {}),
        data=(b"" if method == "POST" else None))
    try:
        with urllib.request.urlopen(request, timeout=3) as resp:
            return resp.status
    except urllib.error.HTTPError as error:
        return error.code

def observe(transport=fetch_status) -> list[Observation]:
    observations = []
    for index, root in enumerate(sorted(ALLOWED), start=1):
        name = "service-a" if root.endswith("18081") else "service-b"
        timestamp = datetime.now(timezone.utc).isoformat()
        try:
            code = transport(root + "/api/protected")
            observations.append(Observation(name, code, timestamp))
        except (OSError, TimeoutError, ValueError) as error:
            observations.append(Observation(name, None, timestamp, type(error).__name__))
    return observations

def classify(observations: list[Observation]) -> tuple[str, str]:
    if len(observations) != 2 or any(o.status_code is None for o in observations):
        return Status.INDETERMINATE.value, "Missing or unreachable service evidence"
    if any(o.status_code not in (200, 403) for o in observations):
        return Status.INDETERMINATE.value, "Unexpected probe response"
    if any(o.status_code == 200 for o in observations):
        return Status.NOT_VERIFIED.value, "At least one instance still allows revoked access"
    return Status.VERIFIED.value, "Both scoped service probes returned HTTP 403"

def run(allow_correction: bool = False, token: str | None = None,
        transport=fetch_status) -> dict:
    before = observe(transport)
    initial, reason = classify(before)
    actions = []
    if allow_correction and initial == Status.NOT_VERIFIED.value:
        if not token:
            raise ValueError("Correction requires a nonempty disposable LAB_TOKEN")
        for item in before:
            if item.status_code != 200:
                continue
            root = "http://127.0.0.1:18081" if item.instance == "service-a" else "http://127.0.0.1:18082"
            try:
                ack = transport(root + "/lab/revoke", token=token, method="POST")
                actions.append({"instance": item.instance, "action": "lab_revoke",
                                "acknowledged": ack == 200})
            except (OSError, TimeoutError, ValueError) as error:
                actions.append({"instance": item.instance, "action": "lab_revoke",
                                "acknowledged": False, "error": type(error).__name__})
    elif allow_correction and initial == Status.INDETERMINATE.value:
        actions.append({"action": "abstain", "reason": "Insufficient evidence"})
    # Independent HTTP probes establish post-action outcome, not the mutation response.
    after = observe(transport)
    final, final_reason = classify(after)
    return {
        "schema_version": "0.1", "scenario": "B-revoked-role-stale-policy",
        "started_outcome": initial, "started_reason": reason,
        "final_outcome": final, "final_reason": final_reason,
        "before": [asdict(o) for o in before],
        "actions": actions, "after": [asdict(o) for o in after],
        "correction_enabled": allow_correction,
        "limitations": ["Lab-local endpoints only", "No cryptographic evidence provenance",
                        "HTTP probes cover only the configured operation"],
    }

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--correct-lab", action="store_true",
                        help="Opt in to local lab revocation; requires LAB_TOKEN")
    parser.add_argument("--output", default="-", help="JSON result path or '-'")
    args = parser.parse_args()
    result = run(args.correct_lab, os.getenv("LAB_TOKEN"))
    payload = json.dumps(result, indent=2)
    if args.output == "-":
        print(payload)
    else:
        with open(args.output, "x", encoding="utf-8") as handle:
            handle.write(payload + "\n")
        print("Recorded run at", args.output)

if __name__ == "__main__":
    main()
