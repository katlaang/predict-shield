"""A source-code fix through the same apply-and-verify chain, against DVWA.

DVWA (Damn Vulnerable Web Application) is a public application written to
be vulnerable for security testing. It is cloned at a pinned commit and
run locally on PHP's built-in server with a disposable MariaDB, at its
"low" security level, with no network exposure.

Chain, per incident:

    detect   a real Semgrep scan with a repo-pinned rule finds request data
             reaching a mysqli query in vulnerabilities/sqli/source/low.php;
             fingerprint = rule + file + the switch case the sink sits in
    plan     pipeline.plan_sast_case maps the rule to the operator's
             registered fix (never a model's guess) and runs the policy gate
    stage    the fix is measured first on a disposable staging copy with the
             same live payloads and lookups; that measurement is the gate's
             estimate. Code fixes are approval tier.
    apply    change_execution.apply_change with a signed approval: dry run,
             `php -l`, registered renderings only, atomic write
    verify   the four-assertion SAST composite plus the opt-in dynamic check:
             live injection payloads against the running target must not
             return any row a legitimate lookup would not
    keep / roll back, with the target file checked against the snapshot

Two incidents run: the registered fix is first DVWA's own "medium" pattern
(escape the input, drop the quotes), a common incomplete fix; then a
prepared statement.
"""
from __future__ import annotations

import argparse
import hashlib
import http.cookiejar
import json
import os
import re
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
os.environ.setdefault("SEMGREP_ENABLE_VERSION_CHECK", "0")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

from predict_shield.ai_contracts import ActionPrediction, ActionTier, CandidateAction, EvidenceSnapshot, Interval  # noqa: E402
from predict_shield.assessment import Evidence, Outcome, assess  # noqa: E402
from predict_shield.change_execution import (  # noqa: E402
    AuditLog, ChangeSpec, RegisteredRenderingsAdapter, RegisteredTarget, Verification, apply_change, sign_approval,
)
from predict_shield.pipeline import plan_sast_case  # noqa: E402
from predict_shield.sast_findings import (  # noqa: E402
    FINDING_CONFIRMED_BEFORE_FIX, FINDING_RESOLVED, NO_NEW_HIGH_SEVERITY_FINDING, NO_REGRESSION,
    VULNERABILITY_BEHAVIOR_ABSENT, RegisteredScanner, ScanFinding, confirm_before_fix,
    confirm_no_new_high_severity, confirm_resolution, evaluate_fix,
)

SCHEMA = "predict-shield/dvwa-sast-chain/1"
DVWA_REPO = "https://github.com/digininja/DVWA"
DVWA_COMMIT = "502ac150ce37c20ca6e04cab7c5ca959f315f2d0"
TARGET_FILE = "vulnerabilities/sqli/source/low.php"
RULE_FILE = HERE / "php_sqli_rule.yml"
RULE_ID = "php-request-to-mysqli-query"
SERVICE = "dvwa-user-lookup"
ASSET = "dvwa:" + TARGET_FILE
PAYLOADS = ("1' OR '1'='1", "1 OR 1=1", "1' UNION SELECT user, password FROM users#",
            "1 UNION SELECT user, password FROM users")
LEGIT_IDS = ("1", "2", "3", "4", "5")
RENDERINGS = {
    "original": HERE / "original_low.php",
    "escape_without_quotes": HERE / "fix_escape_without_quotes.php",
    "prepared_statement": HERE / "fix_prepared_statement.php",
}


# ------------------------------------------------------------------ DVWA

def clone_dvwa(dest: Path) -> str:
    subprocess.run(["git", "clone", "-q", DVWA_REPO, str(dest)], check=True)
    subprocess.run(["git", "-C", str(dest), "checkout", "-q", DVWA_COMMIT], check=True)
    head = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"], capture_output=True, text=True,
                          check=True).stdout.strip()
    if head != DVWA_COMMIT:
        raise RuntimeError("DVWA checkout is not the pinned commit")
    shutil.copyfile(dest / "config" / "config.inc.php.dist", dest / "config" / "config.inc.php")
    if (dest / TARGET_FILE).read_bytes() != RENDERINGS["original"].read_bytes():
        raise RuntimeError("pinned DVWA low.php differs from the registered original rendering")
    return head


class DvwaServer:
    def __init__(self, docroot: Path, port: int, db_host: str, db_port: int):
        env = dict(os.environ, DB_SERVER=db_host, DB_PORT=str(db_port), DISABLE_AUTHENTICATION="true",
                   DEFAULT_SECURITY_LEVEL="low")
        self.base = f"http://127.0.0.1:{port}"
        # The opcode cache is off: with it on, PHP rechecks a changed file only
        # every opcache.revalidate_freq seconds, so a verification run right
        # after a change can exercise the previous code. (A production adapter
        # would reset the cache or reload PHP-FPM as its activation step.)
        self.process = subprocess.Popen(["php", "-d", "opcache.enable=0", "-d", "opcache.enable_cli=0",
                                         "-S", f"127.0.0.1:{port}", "-t", str(docroot)], env=env,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        for _ in range(50):
            try:
                self.opener.open(self.base + "/setup.php", timeout=2).read()
                return
            except OSError:
                time.sleep(0.2)
        raise RuntimeError("DVWA did not start")

    def setup_database(self) -> None:
        page = self.opener.open(self.base + "/setup.php").read().decode()
        token = re.search(r"name='user_token' value='([0-9a-f]+)'", page).group(1)
        body = urllib.parse.urlencode({"create_db": "Create / Reset Database", "user_token": token}).encode()
        result = self.opener.open(self.base + "/setup.php", data=body).read().decode()
        if "Setup successful" not in result:
            raise RuntimeError("DVWA database setup did not report success")

    def lookup(self, value: str) -> list[tuple[str, str]]:
        """Rows a request returns. A server error (a malformed query under an
        incomplete fix) returns no rows; it is still recorded as an error."""
        query = urllib.parse.urlencode({"id": value, "Submit": "Submit"})
        try:
            html = self.opener.open(self.base + "/vulnerabilities/sqli/?" + query, timeout=10).read()
            self.last_status = 200
        except urllib.error.HTTPError as error:
            html = error.read()
            self.last_status = error.code
        return re.findall(r"First name: ([^<]*)<br />Surname: ([^<]*)</pre>", html.decode(errors="replace"))

    def stop(self) -> None:
        self.process.terminate()
        self.process.wait(timeout=10)


def leading_id(payload: str) -> str:
    match = re.match(r"\d+", payload)
    return match.group(0) if match else ""


def injection_results(server: DvwaServer, baseline: dict[str, list]) -> dict:
    """A payload succeeds when it returns any row a legitimate lookup of its
    leading id would not."""
    out = {}
    for payload in PAYLOADS:
        rows = server.lookup(payload)
        allowed = baseline.get(leading_id(payload), [])
        out[payload] = {"rows": len(rows), "http_status": server.last_status,
                        "extra_rows": [r for r in rows if list(r) not in [list(a) for a in allowed]]}
        out[payload]["injection_succeeded"] = bool(out[payload]["extra_rows"])
    return out


def regression_results(server: DvwaServer, baseline: dict[str, list]) -> dict:
    return {i: [list(r) for r in server.lookup(i)] == baseline[i] for i in LEGIT_IDS}


# ------------------------------------------------------------------ scan

def semgrep_version() -> str:
    return subprocess.run(["semgrep", "--version"], capture_output=True, text=True, check=True).stdout.strip()


def scan(path: Path) -> list[dict]:
    done = subprocess.run(["semgrep", "--config", str(RULE_FILE), "--json", "--metrics=off", "--quiet", str(path)],
                          capture_output=True, text=True, check=True, timeout=120)
    return json.loads(done.stdout)["results"]


def fingerprint(rule_id: str, rel_path: str, source: str, line: int) -> str:
    """Rule + file + the `case` label of the switch branch the sink sits in.
    Stable across edits that move lines, distinct per database branch."""
    case = "none"
    for text in source.splitlines()[:line]:
        found = re.match(r"\s*case\s+([A-Z_]+)\s*:", text)
        if found:
            case = found.group(1)
    return hashlib.sha256(f"{rule_id}|{rel_path}|{case}".encode()).hexdigest()[:24] + ":" + case


def findings(path: Path, rel_path: str) -> dict[str, dict]:
    source = path.read_text()
    out = {}
    for result in scan(path):
        fp = fingerprint(result["check_id"], rel_path, source, result["start"]["line"])
        out[result["check_id"] + ":" + fp] = {"rule": result["check_id"], "fingerprint": fp,
                                              "line": result["start"]["line"],
                                              "severity": {"ERROR": "high", "WARNING": "medium"}.get(
                                                  result["extra"]["severity"], "low")}
    return out


# ------------------------------------------------------------------ chain

class PhpRenderingsAdapter(RegisteredRenderingsAdapter):
    """Registered renderings only, and each must also pass `php -l`."""

    def validate(self, candidate: str) -> None:
        super().validate(candidate)
        with tempfile.NamedTemporaryFile("w", suffix=".php", delete=False) as handle:
            handle.write(candidate)
        try:
            result = subprocess.run(["php", "-l", handle.name], capture_output=True, text=True)
        finally:
            os.unlink(handle.name)
        if result.returncode != 0:
            raise ValueError("php -l rejected the candidate: " + result.stdout.strip())


def run_incident(*, name: str, fix: str, target_root: Path, staging_root: Path, target: DvwaServer,
                 staging: DvwaServer, baseline: dict, registry: dict, log: AuditLog, approver) -> dict:
    now = datetime.now(timezone.utc)
    target_path = target_root / TARGET_FILE
    renderings = {k: v.read_text() for k, v in RENDERINGS.items()}
    adapter = PhpRenderingsAdapter(target_path, renderings)
    adapter.write(renderings["original"])
    (staging_root / TARGET_FILE).write_text(renderings["original"])
    incident = {"name": name, "registered_fix": fix}

    # detect
    before = findings(target_path, TARGET_FILE)
    tracked_key = next(k for k, f in before.items() if f["rule"] == RULE_ID and f["fingerprint"].endswith(":MYSQL"))
    tracked = before[tracked_key]
    incident["before_findings"] = sorted(before)
    incident["before_injection"] = injection_results(target, baseline)
    finding = ScanFinding(finding_id=f"{name}-sqli", asset=ASSET, scanner_id="semgrep-pinned-rule", rule_id=RULE_ID,
                          fingerprint=tracked["fingerprint"], file_path=TARGET_FILE, severity=tracked["severity"],
                          present=True, observed_at=now)

    # stage: measure the registered fix on the disposable copy
    (staging_root / TARGET_FILE).write_text(renderings[fix])
    staged_injection = injection_results(staging, baseline)
    staged_regression = regression_results(staging, baseline)
    (staging_root / TARGET_FILE).write_text(renderings["original"])
    residual = sum(r["injection_succeeded"] for r in staged_injection.values()) / len(PAYLOADS)
    disruption = sum(1 for ok in staged_regression.values() if not ok)
    incident["staging_measurement"] = {"payloads_succeeding": residual, "legit_lookups_broken": disruption}

    # plan
    action_id = "apply_registered_fix:" + fix
    actions = (CandidateAction(action_id, ActionTier.APPROVAL, (SERVICE,), "registered source fix", reversible=True),)
    snapshot = EvidenceSnapshot(snapshot_id=f"dvwa-scope:{name}", case_id=name, captured_at=now,
                                source_ids=("sast-finding:" + finding.finding_id,), trusted=True, scope_complete=True)
    prediction = ActionPrediction(action_id=action_id, snapshot_id=snapshot.snapshot_id,
                                  model_name="staging-measurement", model_version=DVWA_COMMIT[:12],
                                  predicted_at=now, residual_risk=Interval(residual, residual, residual),
                                  additional_errors={SERVICE: Interval(disruption, disruption, disruption)},
                                  calibration_supported=True,
                                  training_fingerprint=hashlib.sha256(json.dumps(staged_injection, sort_keys=True).encode()).hexdigest())
    plan = plan_sast_case(case_id=name, finding=finding, scanner_registry=registry, rule_to_action={RULE_ID: action_id},
                          actions=actions, predictions=(prediction,), scope_snapshot=snapshot,
                          remaining_error_budgets={SERVICE: 1.0}, now=now)
    plan["case_id"] = name
    incident["plan"] = {k: plan[k] for k in ("confirmed_present", "selection_status", "policy_screened", "reason")}

    # verify (independent of the executor)
    def verify() -> Verification:
        at = datetime.now(timezone.utc)
        after = findings(target_path, TARGET_FILE)
        after_finding = ScanFinding(finding_id=finding.finding_id, asset=ASSET, scanner_id=finding.scanner_id,
                                    rule_id=RULE_ID, fingerprint=tracked["fingerprint"], file_path=TARGET_FILE,
                                    severity=tracked["severity"], present=tracked_key in after, observed_at=at)
        new_high = [ScanFinding(finding_id="new-" + k, asset=ASSET, scanner_id=finding.scanner_id, rule_id=f["rule"],
                                fingerprint=f["fingerprint"], file_path=TARGET_FILE, severity=f["severity"],
                                present=True, observed_at=at)
                    for k, f in after.items() if k not in before and f["severity"] in ("high", "critical")]
        regression = regression_results(target, baseline)
        injection = injection_results(target, baseline)
        evidence = [
            confirm_before_fix(finding, registry, now=at),
            confirm_resolution(after_finding, registry, now=at),
            Evidence(asset=ASSET, assertion=NO_REGRESSION + ":" + ASSET, observed_pass=all(regression.values()),
                     observed_at=at, source="regression:dvwa-legit-lookups", independent=True),
            confirm_no_new_high_severity(ASSET, finding.scanner_id, registry, new_high, now=at),
            Evidence(asset=ASSET, assertion=VULNERABILITY_BEHAVIOR_ABSENT + ":" + ASSET,
                     observed_pass=not any(r["injection_succeeded"] for r in injection.values()),
                     observed_at=at, source="live-probe:dvwa-sqli-payloads", independent=True),
        ]
        scope = {
            FINDING_CONFIRMED_BEFORE_FIX: (ASSET, evidence[0].assertion),
            FINDING_RESOLVED: (ASSET, evidence[1].assertion),
            NO_REGRESSION: (ASSET, evidence[2].assertion),
            NO_NEW_HIGH_SEVERITY_FINDING: (ASSET, evidence[3].assertion),
            VULNERABILITY_BEHAVIOR_ABSENT: (ASSET, evidence[4].assertion),
        }
        verdict = evaluate_fix(scope, evidence, require_dynamic=True, now=at)
        outcome = Outcome.VERIFIED if verdict.accepted else Outcome.NOT_VERIFIED
        return Verification(outcome, "; ".join(verdict.blocking_reasons) or "all five assertions VERIFIED", {
            "assertions": {k: a.outcome.value for k, a in verdict.assessments.items()},
            "static_scan_says_resolved": tracked_key not in after,
            "remaining_findings": sorted(after),
            "regression": regression, "injection": injection,
        })

    spec = ChangeSpec(f"{name}:{fix}", name, "dvwa-sqli-source", action_id, renderings[fix])
    registered = RegisteredTarget("dvwa-sqli-source", "php_source_file", "lab", auto_apply_allowed=False,
                                  approver_keys={"lab-approver": approver[1]})
    dry = apply_change(plan=plan, spec=spec, target=registered, adapter=adapter, verify=verify, audit_log=log,
                       approval=None)
    incident["without_approval"] = dry["status"]
    approval = sign_approval(spec, "lab-approver", datetime.now(timezone.utc) + timedelta(minutes=10), approver[0])
    dry_signed = apply_change(plan=plan, spec=spec, target=registered, adapter=adapter, verify=verify, audit_log=log,
                              approval=approval)
    incident["dry_run"] = {"status": dry_signed["status"],
                           "target_unchanged": target_path.read_text() == renderings["original"]}
    record = apply_change(plan=plan, spec=spec, target=registered, adapter=adapter, verify=verify, audit_log=log,
                          approval=approval, dry_run=False)
    incident["final_status"] = record["status"]
    incident["verification"] = record.get("verification")
    incident["verification_reason"] = record.get("verification_reason")
    incident["verification_detail"] = record.get("verification_detail")
    current = target_path.read_text()
    incident["target_file_after"] = next((k for k, v in renderings.items() if v == current), "unregistered")
    incident["live_after"] = {"injection": injection_results(target, baseline),
                              "regression": regression_results(target, baseline)}
    return incident


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--db-host", default="127.0.0.1")
    parser.add_argument("--db-port", type=int, default=3306)
    args = parser.parse_args()

    work = Path(tempfile.mkdtemp(prefix="ps-dvwa-"))
    target_root, staging_root = work / "target", work / "staging"
    commit = clone_dvwa(target_root)
    shutil.copytree(target_root, staging_root)
    key = Ed25519PrivateKey.generate()
    approver = (key, key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex())
    registry = {"semgrep-pinned-rule": RegisteredScanner("semgrep-pinned-rule", "Semgrep OSS", semgrep_version())}
    log = AuditLog(work / "audit.jsonl")
    target = DvwaServer(target_root, 18080, args.db_host, args.db_port)
    staging = DvwaServer(staging_root, 18081, args.db_host, args.db_port)
    report = {"schema": SCHEMA, "dvwa_repository": DVWA_REPO, "dvwa_commit": commit,
              "semgrep_version": registry["semgrep-pinned-rule"].version,
              "rule_file_sha256": hashlib.sha256(RULE_FILE.read_bytes()).hexdigest(),
              "renderings_sha256": {k: hashlib.sha256(v.read_bytes()).hexdigest() for k, v in RENDERINGS.items()},
              "payloads": list(PAYLOADS), "incidents": {},
              "php_version": subprocess.run(["php", "-v"], capture_output=True, text=True).stdout.splitlines()[0],
              "php_server_flags": ["-d", "opcache.enable=0", "-d", "opcache.enable_cli=0"]}
    try:
        target.setup_database()
        baseline = {i: [list(r) for r in target.lookup(i)] for i in LEGIT_IDS}
        report["baseline_lookups"] = baseline
        if not all(baseline.values()):
            raise RuntimeError("baseline lookups returned nothing; DVWA is not serving its sample users")
        for name, fix in (("dvwa-incomplete-fix", "escape_without_quotes"), ("dvwa-prepared-statement", "prepared_statement")):
            report["incidents"][name] = run_incident(name=name, fix=fix, target_root=target_root, staging_root=staging_root,
                                                     target=target, staging=staging, baseline=baseline,
                                                     registry=registry, log=log, approver=approver)
    finally:
        target.stop()
        staging.stop()
    report["audit_log_chain_intact"] = log.verify_chain()
    report["audit_log"] = log.records()
    report["summary"] = {n: {"final_status": i["final_status"], "target_file_after": i["target_file_after"],
                             "static_scan_says_resolved": (i.get("verification_detail") or {}).get("static_scan_says_resolved"),
                             "assertions": (i.get("verification_detail") or {}).get("assertions"),
                             "live_injection_after": any(v["injection_succeeded"] for v in i["live_after"]["injection"].values()),
                             "staging": i["staging_measurement"], "without_approval": i["without_approval"]}
                         for n, i in report["incidents"].items()}
    report["summary"]["_audit_log_chain_intact"] = report["audit_log_chain_intact"]
    args.output.write_text(json.dumps(report, indent=1, sort_keys=True, default=str) + "\n")
    print(json.dumps(report["summary"], indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
