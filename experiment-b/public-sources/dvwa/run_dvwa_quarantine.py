"""Quarantine a vulnerable route that has no fix, through the same gated
change path as a fix, against a real DVWA behind a real nginx.

DVWA (pinned commit) runs on PHP's built-in server; nginx on loopback proxies
to it and loads one managed include, quarantine.conf. The SQL injection route
is the finding. For this lab it is declared to have no fix and no
configuration mitigation, with an exploitation likelihood supplied as an input
(the learned model scores CVEs; DVWA's lab weakness has no CVE). decide()
picks the action; change_execution applies it with a signed approval;
verification is independent of the executor.

Incidents:
  quarantine-sqli       block /vulnerabilities/sqli/ only. Verified when every
                        injection payload is refused through nginx AND the
                        other DVWA pages still work through nginx.
  overbroad-quarantine  block /vulnerabilities/ (also cuts off unrelated
                        pages). The same verification fails on the regression
                        check and the change is rolled back.
  lift-after-fix        the prepared-statement fix is applied to the source,
                        then the quarantine is lifted; verified when the route
                        is reachable again and every payload still fails.
"""
from __future__ import annotations

import argparse
import hashlib
import http.cookiejar
import json
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(HERE))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

from predict_shield.assessment import Outcome  # noqa: E402
from predict_shield.change_execution import (  # noqa: E402
    AuditLog, ChangeSpec, RegisteredTarget, Verification, apply_change, sign_approval)
from predict_shield.vulnerability_response import (  # noqa: E402
    QUARANTINE, Finding, NginxQuarantineIncludeAdapter, Decision, decide, quarantine_plan, quarantined_paths,
    render_nginx_quarantine)
import run_dvwa_sast_chain as chain  # noqa: E402

SCHEMA = "predict-shield/dvwa-quarantine/1"
ROUTE = "/vulnerabilities/sqli/"
# Pages that must keep working while the SQL injection route is quarantined.
OTHER_PAGES = ("/index.php", "/about.php", "/instructions.php", "/vulnerabilities/xss_r/?name=ps",
               "/vulnerabilities/exec/")
NGINX = shutil.which("nginx") or "/usr/sbin/nginx"
STABLE_READS = 6


class Front:
    """nginx on loopback in front of DVWA, from its own prefix."""

    def __init__(self, prefix: Path, upstream_port: int, port: int):
        self.prefix, self.port = prefix, port
        self.include = prefix / "managed" / "quarantine.conf"
        for sub in ("managed", "logs", "tmp"):
            (prefix / sub).mkdir(parents=True, exist_ok=True)
        self.include.write_text(render_nginx_quarantine([]))
        (prefix / "nginx.conf").write_text(f"""
worker_processes 1;
pid {prefix}/nginx.pid;
error_log {prefix}/logs/error.log;
events {{ worker_connections 64; }}
http {{
  access_log off;
  client_body_temp_path {prefix}/tmp/body; proxy_temp_path {prefix}/tmp/proxy;
  fastcgi_temp_path {prefix}/tmp/fcgi; uwsgi_temp_path {prefix}/tmp/uwsgi; scgi_temp_path {prefix}/tmp/scgi;
  server {{
    listen 127.0.0.1:{port};
    include {self.include};
    location / {{ proxy_pass http://127.0.0.1:{upstream_port}; proxy_set_header Host $host:$server_port; }}
  }}
}}
""")
        self.cmd = [NGINX, "-p", str(prefix), "-c", str(prefix / "nginx.conf"), "-e", str(prefix / "logs" / "error.log")]
        subprocess.run(self.cmd, check=True)
        self.base = f"http://127.0.0.1:{port}"
        jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        for _ in range(50):
            try:
                self.opener.open(self.base + "/index.php", timeout=2).read()
                return
            except OSError:
                time.sleep(0.2)
        raise RuntimeError("nginx front did not start")

    def status(self, path: str) -> int:
        try:
            with self.opener.open(self.base + path, timeout=10) as r:
                r.read()
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    def stop(self) -> None:
        subprocess.run(self.cmd + ["-s", "quit"], capture_output=True)


class ThroughFront(chain.DvwaServer):
    """DVWA lookups sent through the nginx front instead of directly."""

    def __init__(self, front: Front):  # noqa: D401 - no process of its own
        self.base, self.opener = front.base, front.opener

    def stop(self) -> None:
        pass


def observe(front: Front, client: ThroughFront, baseline: dict) -> dict:
    """Read STABLE_READS times so an old nginx worker cannot answer the check."""
    reads = []
    for _ in range(STABLE_READS):
        reads.append({"route_status": front.status(ROUTE + "?id=1&Submit=Submit"),
                      "other_pages": {p: front.status(p) for p in OTHER_PAGES},
                      "injection": chain.injection_results(client, baseline)})
        time.sleep(0.3)
    last = reads[-1]
    stable = all(json.dumps(r, sort_keys=True) == json.dumps(last, sort_keys=True) for r in reads)
    return dict(last, stable_over_reads=stable)


def run_change(*, name, decision: Decision, paths, front, client, baseline, log, approver, expect_route_blocked):
    adapter = NginxQuarantineIncludeAdapter(front.include, front.cmd)
    plan = quarantine_plan(decision, name)
    spec = ChangeSpec(f"{name}:quarantine", name, "dvwa-front-quarantine", plan["action_id"],
                      render_nginx_quarantine(paths))
    target = RegisteredTarget("dvwa-front-quarantine", "nginx_include", "lab", auto_apply_allowed=False,
                              approver_keys={"lab-approver": approver[1]})

    def verify() -> Verification:
        seen = observe(front, client, baseline)
        payloads_fail = not any(r["injection_succeeded"] for r in seen["injection"].values())
        others_ok = all(s == 200 for s in seen["other_pages"].values())
        route_ok = (seen["route_status"] == 403) if expect_route_blocked else (seen["route_status"] == 200)
        passed = payloads_fail and others_ok and route_ok and seen["stable_over_reads"]
        reasons = [r for ok, r in ((payloads_fail, "an injection payload still succeeds"),
                                   (others_ok, "a page outside the quarantine stopped working"),
                                   (route_ok, "the route status is not the expected one"),
                                   (seen["stable_over_reads"], "reads disagreed after reload")) if not ok]
        return Verification(Outcome.VERIFIED if passed else Outcome.NOT_VERIFIED,
                            "; ".join(reasons) or "verified", seen)

    without = apply_change(plan=plan, spec=spec, target=target, adapter=adapter, verify=verify, audit_log=log)
    approval = sign_approval(spec, "lab-approver", datetime.now(timezone.utc) + timedelta(minutes=10), approver[0])
    record = apply_change(plan=plan, spec=spec, target=target, adapter=adapter, verify=verify, audit_log=log,
                          approval=approval, dry_run=False)
    return {"decision": {"action": decision.action, "reasons": decision.reasons}, "paths": list(paths),
            "without_approval": without["status"], "final_status": record["status"],
            "verification_reason": record.get("verification_reason"),
            "verification_detail": record.get("verification_detail"),
            "include_after": quarantined_paths(front.include.read_text()),
            "live_after": observe(front, client, baseline)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--db-host", default="127.0.0.1")
    ap.add_argument("--db-port", type=int, default=3306)
    ap.add_argument("--exploit-top-share", type=float, default=0.01)
    args = ap.parse_args()
    work = Path(tempfile.mkdtemp(prefix="ps-dvwa-q-"))
    root = work / "dvwa"
    commit = chain.clone_dvwa(root)
    key = Ed25519PrivateKey.generate()
    approver = (key, key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex())
    log = AuditLog(work / "audit.jsonl")
    dvwa = chain.DvwaServer(root, 18090, args.db_host, args.db_port)
    front = Front(work / "nginx", 18090, 18091)
    client = ThroughFront(front)
    report = {"schema": SCHEMA, "dvwa_commit": commit, "route": ROUTE, "other_pages": list(OTHER_PAGES),
              "exploit_top_share_input": args.exploit_top_share, "incidents": {}}
    try:
        dvwa.setup_database()
        baseline = {i: [list(r) for r in dvwa.lookup(i)] for i in chain.LEGIT_IDS}
        report["before"] = observe(front, client, baseline)
        finding = Finding("dvwa-sqli-no-fix", "dvwa", ROUTE, args.exploit_top_share)
        decision = decide(finding)
        report["decision"] = {"action": decision.action, "reasons": decision.reasons}
        if decision.action != QUARANTINE:
            raise SystemExit(f"policy chose {decision.action}, not QUARANTINE")
        report["incidents"]["overbroad-quarantine"] = run_change(
            name="overbroad-quarantine", decision=decision, paths=["/vulnerabilities/"], front=front, client=client,
            baseline=baseline, log=log, approver=approver, expect_route_blocked=True)
        report["incidents"]["quarantine-sqli"] = run_change(
            name="quarantine-sqli", decision=decision, paths=[ROUTE], front=front, client=client,
            baseline=baseline, log=log, approver=approver, expect_route_blocked=True)
        # a fix becomes available: apply the registered prepared-statement rendering, then lift
        fixed = (chain.RENDERINGS["prepared_statement"]).read_text()
        (root / chain.TARGET_FILE).write_text(fixed)
        lift = Decision(decision.finding_id, QUARANTINE, ["fix applied; lift the quarantine"], decision.quarantine_paths)
        report["incidents"]["lift-after-fix"] = run_change(
            name="lift-after-fix", decision=lift, paths=[], front=front, client=client,
            baseline=baseline, log=log, approver=approver, expect_route_blocked=False)
        report["incidents"]["lift-after-fix"]["source_fix_sha256"] = hashlib.sha256(fixed.encode()).hexdigest()
    finally:
        front.stop()
        dvwa.stop()
    report["audit_log_chain_intact"] = log.verify_chain()
    report["audit_log"] = log.records()
    report["summary"] = {n: {k: i[k] for k in ("without_approval", "final_status", "include_after")}
                         | {"payloads_refused_after": not any(r["injection_succeeded"] for r in i["live_after"]["injection"].values()),
                            "other_pages_after": i["live_after"]["other_pages"],
                            "route_status_after": i["live_after"]["route_status"]}
                         for n, i in report["incidents"].items()}
    args.output.write_text(json.dumps(report, indent=1, sort_keys=True, default=str) + "\n")
    print(json.dumps(report["summary"], indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
