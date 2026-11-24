"""BGP hijack by a customer, detected and contained through the gated change path.

The lab (topology.clab.yml) must already be deployed. Steps:

  baseline        the subscriber reaches the real content host and the customer
  hijack          the customer starts announcing two /25s inside the content
                  provider's /24; traffic for the content goes to the attacker
  detect          pe2's received routes from the customer are compared with the
                  customer's registered prefixes (route_monitor)
  overbroad       a filter that denies everything from the customer is applied
                  with approval; the observer sees the customer's own network
                  cut off, so the change is rolled back
  filter          the registry-derived filter (permit only the customer's own
                  prefix) is refused without approval, then applied with a
                  signed approval and verified by the observer
  withdraw-check  the attack is still being announced; the filter keeps it out

Verification is the independent observer (observer.py): every ISP router's
forwarding table plus pages fetched from the subscriber. The response code is
never asked whether its own change worked.

  python run_lab.py --output reports/isp-hijack.json
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(HERE))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

from predict_shield.assessment import Outcome  # noqa: E402
from predict_shield.change_execution import (  # noqa: E402
    AuditLog, ChangeSpec, RegisteredTarget, Verification, apply_change, sign_approval)

import bgp_filter  # noqa: E402
import observer  # noqa: E402
import route_monitor  # noqa: E402

SCHEMA = "predict-shield/isp-bgp-hijack/1"
CUSTOMER_NEIGHBOR = "10.0.4.2"
ISP_AS = 65100
REGISTRY = {"65200": ["198.51.100.0/24"]}   # what the customer may announce (its IRR/contract entry)
HOSTS = {"content": "content", "custhost": "customer", "attacker": "attacker"}


def start_servers() -> None:
    for node, name in HOSTS.items():
        subprocess.run(["docker", "exec", "-d", f"clab-isp-net-{node}", "sh", "-c",
                        f"mkdir -p /srv && echo {name} > /srv/index.html && cd /srv && exec python -m http.server 80"],
                       check=True)
    time.sleep(2)


def cust(*commands: str) -> None:
    args = ["docker", "exec", "clab-isp-net-cust", "vtysh", "-c", "configure terminal"]
    for c in commands:
        args += ["-c", c]
    subprocess.run(args, check=True, capture_output=True, text=True)


def start_hijack() -> None:
    cust("ip route 203.0.113.128/25 Null0", "router bgp 65200", "address-family ipv4 unicast",
         "network 203.0.113.0/25", "network 203.0.113.128/25", "exit-address-family")


def plan_for(case_id: str, action_id: str) -> dict:
    """The operator's response plan: this action is proposed and needs approval."""
    return {"case_id": case_id, "selection_status": "PROPOSED",
            "policy_screened": {action_id: {"decision": "PROPOSE_FOR_APPROVAL"}}}


def verify_contained() -> Verification:
    seen = observer.observe()
    ok_content = seen["content_answer"] == "content"
    ok_customer = seen["customer_answer"] == "customer"
    clean_routes = not observer.hijacked(seen)
    reasons = [r for good, r in ((ok_content, "content traffic does not reach the real content host"),
                                 (ok_customer, "the customer's own network is not reachable"),
                                 (clean_routes, "an ISP router still routes the content prefix to the customer"),
                                 (seen["stable"], "observations did not settle")) if not good]
    passed = not reasons
    return Verification(Outcome.VERIFIED if passed else Outcome.NOT_VERIFIED, "; ".join(reasons) or "verified", seen)


def run_change(name: str, content: str, log: AuditLog, key, pub: str) -> dict:
    adapter = bgp_filter.FrrInboundFilterAdapter(bgp_filter.docker_runner("clab-isp-net-pe2"), CUSTOMER_NEIGHBOR, ISP_AS)
    action = "bgp_inbound_prefix_filter"
    spec = ChangeSpec(f"{name}:filter", "isp-cust-hijack", "pe2-cust-inbound", action, content)
    target = RegisteredTarget("pe2-cust-inbound", "frr_prefix_filter", "lab", auto_apply_allowed=False,
                              approver_keys={"noc-approver": pub})
    plan = plan_for("isp-cust-hijack", action)
    without = apply_change(plan=plan, spec=spec, target=target, adapter=adapter, verify=verify_contained,
                           audit_log=log, dry_run=False)
    approval = sign_approval(spec, "noc-approver", datetime.now(timezone.utc) + timedelta(minutes=10), key)
    record = apply_change(plan=plan, spec=spec, target=target, adapter=adapter, verify=verify_contained,
                          audit_log=log, approval=approval, dry_run=False)
    return {"filter": content.splitlines(), "without_approval": without["status"], "final_status": record["status"],
            "verification_reason": record.get("verification_reason"),
            "filter_on_router_after": adapter.read().splitlines(), "observed_after": observer.observe()}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    log = AuditLog(Path(tempfile.mkdtemp(prefix="ps-isp-")) / "audit.jsonl")
    start_servers()
    report = {"schema": SCHEMA, "registry": REGISTRY, "steps": {}}

    report["steps"]["baseline"] = base = observer.observe()
    if observer.hijacked(base) or base["content_answer"] != "content" or base["customer_answer"] != "customer":
        raise SystemExit(f"baseline is not healthy: {base}")

    start_hijack()
    report["steps"]["hijack"] = hj = observer.observe()
    report["steps"]["hijack"]["hijack_effective"] = observer.hijacked(hj)

    run = bgp_filter.docker_runner("clab-isp-net-pe2")
    received = bgp_filter.received_routes(run, CUSTOMER_NEIGHBOR)
    findings = route_monitor.unauthorized(received, REGISTRY["65200"], own_as=ISP_AS)
    report["steps"]["detect"] = {"received_from_customer": received, "unauthorized": findings}
    if not findings:
        raise SystemExit("the hijack was not detected; nothing to respond to")

    deny_all = "ip prefix-list CUST-IN seq 5 deny 0.0.0.0/0 le 32\n"
    report["steps"]["overbroad"] = run_change("overbroad", deny_all, log, key, pub)
    proper = route_monitor.filter_for(REGISTRY["65200"])
    report["steps"]["filter"] = run_change("filter", proper, log, key, pub)
    report["steps"]["withdraw_check"] = {
        "still_announced_by_customer": bgp_filter.received_routes(run, CUSTOMER_NEIGHBOR),
        "observed": observer.observe()}

    report["audit_log_chain_intact"] = log.verify_chain()
    report["audit_log"] = log.records()
    report["summary"] = {
        "baseline_content_answer": base["content_answer"],
        "hijack_effective": report["steps"]["hijack"]["hijack_effective"],
        "hijack_content_answer": hj["content_answer"],
        "unauthorized_detected": findings,
        "overbroad": {k: report["steps"]["overbroad"][k] for k in ("without_approval", "final_status", "verification_reason")},
        "filter": {k: report["steps"]["filter"][k] for k in ("without_approval", "final_status", "verification_reason")},
        "after_content_answer": report["steps"]["filter"]["observed_after"]["content_answer"],
        "after_customer_answer": report["steps"]["filter"]["observed_after"]["customer_answer"],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=1, sort_keys=True, default=str) + "\n")
    print(json.dumps(report["summary"], indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
