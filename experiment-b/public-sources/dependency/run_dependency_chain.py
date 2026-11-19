"""A dependency upgrade through the same apply-and-verify chain, with OSV.dev
as the source for the "no known vulnerability in the new version" check.

Target: a disposable npm project depending on lodash 4.17.11, the real
version affected by CVE-2020-8203 (prototype pollution in zipObjectDeep),
as in the existing real CVE pilot. Three registered upgrades are tried,
each from the same starting state:

    4.17.15   a real release still inside the CVE's affected range
    4.17.21   the release the existing pilot treats as the fix
    4.18.1    the current release when this lab was written

Per incident: the upgrade is measured first on a disposable staging copy
(the same independent behavior probe), which becomes the gate's estimate;
the action is approval tier; `change_execution.apply_change` dry-runs,
then writes package.json (registered renderings only) and runs `npm
install`; the four-assertion composite then decides keep or roll back:

    vulnerability_resolved   the independent child-process probe sees no
                             prototype pollution, at the expected version
    no_regression            the probe's benign zipObjectDeep call works
    no_known_vulnerability   OSV.dev (`osv_source.scan_with_osv`); range
                             evaluation and OSV's own version query must
                             agree, or the check is INDETERMINATE
    dependency_resolution    `npm ls` resolves the tree without errors

`--advisories registered` uses the two hand-registered advisories of the
existing pilot instead of OSV, for a machine that cannot reach OSV. The
report records which source each run used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "engine"))
PROBE = ROOT / "experiment-b" / "real-cve-remediation" / "independent_probe.js"

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

from predict_shield.ai_contracts import ActionPrediction, ActionTier, CandidateAction, EvidenceSnapshot, Interval  # noqa: E402
from predict_shield.assessment import Evidence, Outcome  # noqa: E402
from predict_shield.change_execution import (  # noqa: E402
    AuditLog, ChangeSpec, RegisteredRenderingsAdapter, RegisteredTarget, Verification, apply_change, sign_approval,
)
from predict_shield.osv_source import scan_with_osv  # noqa: E402
from predict_shield.post_patch_vulnerability_scan import KnownAdvisory, scan  # noqa: E402
from predict_shield.remediation_verification import (  # noqa: E402
    DEPENDENCY_RESOLUTION_OK, NO_NEW_KNOWN_VULNERABILITY, NO_REGRESSION, VULNERABILITY_RESOLVED, evaluate,
)
from predict_shield.selector import select_action  # noqa: E402
from predict_shield.versions import VersionRange  # noqa: E402

SCHEMA = "predict-shield/dependency-upgrade-chain/1"
PKG, BEFORE, CVE = "lodash", "4.17.11", "CVE-2020-8203"
UPGRADES = ("4.17.15", "4.17.21", "4.18.1")
SERVICE = "npm-lab-project"
ASSET = "npm-lab:" + PKG
REGISTERED_ADVISORIES = (
    KnownAdvisory("GHSA-p6mc-m468-83gw", PKG, (VersionRange("3.7.0", "4.17.19"),)),
    KnownAdvisory("GHSA-35jh-r3h4-6jhm", PKG, (VersionRange("0", "4.17.21"),)),
)


def package_json(version: str) -> str:
    return json.dumps({"name": "predict-shield-dependency-chain-lab", "version": "0.0.0", "private": True,
                       "dependencies": {PKG: version}}, indent=2, sort_keys=True) + "\n"


def npm_install(root: Path) -> None:
    for stale in (root / "node_modules", root / "package-lock.json"):
        if stale.is_dir():
            shutil.rmtree(stale)
        elif stale.exists():
            stale.unlink()
    subprocess.run(["npm", "install", "--prefix", str(root), "--ignore-scripts", "--no-audit", "--no-fund"],
                   check=True, capture_output=True, text=True, timeout=300)


def probe(root: Path) -> dict:
    out = subprocess.run(["node", str(PROBE), str(root)], check=True, capture_output=True, text=True, timeout=60)
    return json.loads(out.stdout)


def npm_ls_ok(root: Path) -> bool:
    return subprocess.run(["npm", "ls", "--prefix", str(root)], capture_output=True, text=True).returncode == 0


def known_vulnerability_evidence(version: str, source: str, now: datetime) -> tuple[Evidence, dict]:
    if source == "osv":
        result = scan_with_osv(PKG, "npm", version, now=now)
        return result.evidence, {"source": "osv.dev", "reason": result.reason,
                                 "advisories_considered": list(result.advisories_considered),
                                 "advisories_covering_version": list(result.advisories_covering_version),
                                 "osv_version_query_ids": list(result.osv_version_query_ids),
                                 "response_sha256": result.response_sha256}
    evidence = scan(PKG, version, REGISTERED_ADVISORIES, now=now)
    return evidence, {"source": "hand-registered advisories (no OSV access)",
                      "advisories_considered": [a.advisory_id for a in REGISTERED_ADVISORIES]}


def run_incident(version: str, *, project: Path, staging: Path, log: AuditLog, approver, advisories: str) -> dict:
    name = f"upgrade-{PKG}-{version}"
    renderings = {"original": package_json(BEFORE), version: package_json(version)}
    adapter = RegisteredRenderingsAdapter(project / "package.json", renderings,
                                          after_write=lambda: npm_install(project))
    adapter.write(renderings["original"])
    npm_install(project)
    before = probe(project)
    if before["observed_package_version"] != BEFORE or not before["benign_prototype_pollution_observed"]:
        raise RuntimeError("the starting state is not the confirmed vulnerable lodash")
    incident = {"name": name, "upgrade_to": version, "before": {k: before[k] for k in (
        "observed_package_version", "benign_prototype_pollution_observed", "benign_functionality_works")}}

    # stage
    (staging / "package.json").write_text(renderings[version])
    npm_install(staging)
    staged = probe(staging)
    residual = 1.0 if staged["benign_prototype_pollution_observed"] else 0.0
    disruption = 0.0 if staged["benign_functionality_works"] else 1.0
    incident["staging_measurement"] = {"prototype_pollution": staged["benign_prototype_pollution_observed"],
                                       "benign_function_works": staged["benign_functionality_works"]}

    # plan: the existing policy gate over the registered upgrade action
    now = datetime.now(timezone.utc)
    action_id = f"upgrade_{PKG}_{version.replace('.', '_')}"
    action = CandidateAction(action_id, ActionTier.APPROVAL, (SERVICE,), "registered dependency upgrade", reversible=True)
    snapshot = EvidenceSnapshot(snapshot_id=f"npm-scope:{name}", case_id=name, captured_at=now,
                                source_ids=("npm-lab:" + PKG,), trusted=True, scope_complete=True)
    prediction = ActionPrediction(action_id=action_id, snapshot_id=snapshot.snapshot_id, model_name="staging-measurement",
                                  model_version=version, predicted_at=now,
                                  residual_risk=Interval(residual, residual, residual),
                                  additional_errors={SERVICE: Interval(disruption, disruption, disruption)},
                                  calibration_supported=True,
                                  training_fingerprint=hashlib.sha256(json.dumps(staged, sort_keys=True).encode()).hexdigest())
    screened = select_action(snapshot, (action,), (prediction,), {SERVICE: 1.0})
    plan = {"case_id": name, "selection_status": "ESCALATE_FOR_EVIDENCE", "selected_action": None,
            "policy_screened": {a: {"decision": r.decision.value, "reason": r.reason}
                                for a, r in screened.screened.items()}}
    incident["plan"] = plan

    def verify() -> Verification:
        at = datetime.now(timezone.utc)
        post = probe(project)
        vuln_ev, vuln_detail = known_vulnerability_evidence(version, advisories, at)
        evidence = [
            Evidence(asset=ASSET, assertion="mitigated:" + CVE, observed_at=at, independent=True,
                     observed_pass=post["observed_package_version"] == version and not post["benign_prototype_pollution_observed"],
                     source="separate-child-node-behavior-probe"),
            Evidence(asset=ASSET, assertion="regression:" + ASSET, observed_at=at, independent=True,
                     observed_pass=post["benign_functionality_works"] is True, source="probe:benign-zipObjectDeep"),
            vuln_ev,
            Evidence(asset=ASSET, assertion="resolution:" + ASSET, observed_at=at, independent=True,
                     observed_pass=npm_ls_ok(project), source="npm-ls"),
        ]
        scope = {VULNERABILITY_RESOLVED: (ASSET, evidence[0].assertion), NO_REGRESSION: (ASSET, evidence[1].assertion),
                 NO_NEW_KNOWN_VULNERABILITY: (vuln_ev.asset, vuln_ev.assertion),
                 DEPENDENCY_RESOLUTION_OK: (ASSET, evidence[3].assertion)}
        verdict = evaluate(scope, evidence, now=at)
        return Verification(Outcome.VERIFIED if verdict.accepted else Outcome.NOT_VERIFIED,
                            "; ".join(verdict.blocking_reasons) or "all four assertions VERIFIED",
                            {"assertions": {k: a.outcome.value for k, a in verdict.assessments.items()},
                             "probe": {k: post[k] for k in ("observed_package_version",
                                                            "benign_prototype_pollution_observed",
                                                            "benign_functionality_works")},
                             "known_vulnerability_check": vuln_detail})

    spec = ChangeSpec(f"{name}", name, "npm-lab-package-json", action_id, renderings[version])
    target = RegisteredTarget("npm-lab-package-json", "npm_package_manifest", "lab", auto_apply_allowed=False,
                              approver_keys={"lab-approver": approver[1]})
    unsigned = apply_change(plan=plan, spec=spec, target=target, adapter=adapter, verify=verify, audit_log=log)
    approval = sign_approval(spec, "lab-approver", datetime.now(timezone.utc) + timedelta(minutes=15), approver[0])
    dry = apply_change(plan=plan, spec=spec, target=target, adapter=adapter, verify=verify, audit_log=log, approval=approval)
    record = apply_change(plan=plan, spec=spec, target=target, adapter=adapter, verify=verify, audit_log=log,
                          approval=approval, dry_run=False)
    after = probe(project)
    incident.update({
        "without_approval": unsigned["status"], "dry_run": dry["status"], "final_status": record["status"],
        "verification": record.get("verification"), "verification_reason": record.get("verification_reason"),
        "verification_detail": record.get("verification_detail"),
        "installed_after": after["observed_package_version"],
        "manifest_after": next((k for k, v in renderings.items() if v == (project / "package.json").read_text()),
                               "unregistered"),
    })
    return incident


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--advisories", choices=("osv", "registered"), default="osv")
    args = parser.parse_args()
    work = Path(tempfile.mkdtemp(prefix="ps-dep-chain-"))
    project, staging = work / "project", work / "staging"
    project.mkdir()
    staging.mkdir()
    key = Ed25519PrivateKey.generate()
    approver = (key, key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex())
    log = AuditLog(work / "audit.jsonl")
    report = {"schema": SCHEMA, "package": PKG, "starting_version": BEFORE, "cve": CVE,
              "advisory_source": args.advisories, "npm_version": subprocess.run(
                  ["npm", "--version"], capture_output=True, text=True).stdout.strip(),
              "probe_sha256": hashlib.sha256(PROBE.read_bytes()).hexdigest(), "incidents": {}}
    for version in UPGRADES:
        report["incidents"][version] = run_incident(version, project=project, staging=staging, log=log,
                                                    approver=approver, advisories=args.advisories)
    report["audit_log_chain_intact"] = log.verify_chain()
    report["audit_log"] = log.records()
    report["summary"] = {v: {"final_status": i["final_status"], "installed_after": i["installed_after"],
                             "assertions": (i.get("verification_detail") or {}).get("assertions"),
                             "covering_advisories": ((i.get("verification_detail") or {}).get(
                                 "known_vulnerability_check") or {}).get("advisories_covering_version"),
                             "without_approval": i["without_approval"]}
                         for v, i in report["incidents"].items()}
    report["summary"]["_audit_log_chain_intact"] = report["audit_log_chain_intact"]
    args.output.write_text(json.dumps(report, indent=1, sort_keys=True, default=str) + "\n")
    print(json.dumps(report["summary"], indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
