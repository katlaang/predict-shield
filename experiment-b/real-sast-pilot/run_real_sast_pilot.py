"""Real Semgrep scan -> sast_findings.py's four-assertion composite ->
real acceptance verdict, against one real SQL-injection fixture and its
real fix. Not production remediation; an exploratory lab pilot, the same
role the Maven and lodash pilots play for the dependency-upgrade composite.

This runs a real `semgrep` subprocess against a repo-pinned local rule file
(never the semgrep.dev registry: that keeps the scan reproducible without a
network dependency and matches the "registered ahead of time" rule every
other check in this pipeline follows) and a real regression check (an
actual Python subprocess asserting the fixed function still returns correct
results against a real sqlite3 database), then feeds the real results
through confirm_before_fix, confirm_resolution, confirm_no_new_high_severity
and evaluate_fix exactly as a caller would.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# The sandbox's egress proxy blocks semgrep.dev; --metrics=off stops the scan
# itself from reaching it, but `semgrep --version` separately checks for
# updates unless this is also set, and that check hangs against a refused
# connection instead of failing fast.
os.environ.setdefault("SEMGREP_ENABLE_VERSION_CHECK", "0")

sys.path.insert(0, str(Path(__file__).resolve()))
import fingerprint

from predict_shield.sast_findings import (
    FINDING_CONFIRMED_BEFORE_FIX,
    FINDING_RESOLVED,
    NO_NEW_HIGH_SEVERITY_FINDING,
    NO_REGRESSION,
    RegisteredScanner,
    ScanFinding,
    confirm_before_fix,
    confirm_no_new_high_severity,
    confirm_resolution,
    evaluate_fix,
)

HERE = Path(__file__).resolve().parent
RULE_FILE = HERE / "sqli_rule.yml"
VULNERABLE_FILE = HERE / "fixtures" / "vulnerable_before.py"
FIXED_FILE = HERE / "fixtures" / "fixed_after.py"
RULE_ID = "python-sql-string-concat"
ASSET = "real-sast-pilot:fixtures/get_user"
SCHEMA = "predict-shield/real-sast-fix-pilot/1"

def _semgrep_version() -> str:
    completed = subprocess.run(["semgrep", "--version"], capture_output=True, text=True,
                               timeout=30, check=True)
    return completed.stdout.strip()


def _scanner_registry(version: str) -> dict[str, RegisteredScanner]:
    """Built from the real, just-queried semgrep version, not a hardcoded
    guess: the registered scanner is pinned to whatever actually ran."""
    return {
        "semgrep-oss-local-rule": RegisteredScanner(
            scanner_id="semgrep-oss-local-rule", name="Semgrep OSS", version=version, trusted=True,
        ),
    }


def _scan(file_path: Path) -> list[dict]:
    """Run a real semgrep subprocess against one file, using only the
    repo-pinned local rule file, never the remote registry."""
    completed = subprocess.run(
        ["semgrep", "--config", str(RULE_FILE), "--json", "--metrics=off", "--quiet", str(file_path)],
        capture_output=True, text=True, timeout=60, check=True,
    )
    return json.loads(completed.stdout)["results"]


# Semgrep's own severity scale (INFO/WARNING/ERROR) is not the high/critical
# vocabulary sast_findings.py's confirm_no_new_high_severity expects; this
# maps one to the other so that check is not silently vacuous against a real
# scanner. A more complete integration would likely take this mapping from
# the operator's registration, not hardcode it here.
SEMGREP_SEVERITY_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def _mapped_severity(raw_severity: str) -> str:
    return SEMGREP_SEVERITY_MAP.get(raw_severity.upper(), "low")


def run(*, output: Path, work_dir: Path | None = None) -> dict:
    if output.exists():
        raise FileExistsError("Prior evidence cannot be overwritten")
    now = datetime.now(timezone.utc)
    scanner_version = _semgrep_version()
    scanner_registry = _scanner_registry(scanner_version)
    report: dict = {
        "schema": SCHEMA,
        "rule_id": RULE_ID,
        "scanner_version": scanner_version,
        "external_scanner_integration_production_ready": False,
        "dynamic_check_performed": False,
        "reachability_based_prioritization_used": False,
        "evaluated_against_real_production_codebase": False,
    }
    started = time.monotonic()

    # Scan both states at the *same* disposable path, copying each fixture's
    # content over it in turn: a real fix edits one file in place, and the
    # fingerprint includes the file's own name, so scanning two differently
    # named files would never let the "same fingerprint, now resolved" check
    # mean anything -- this is the mistake the first version of this pilot
    # made, caught by its own unit test. Everything that needs the file on
    # disk (including the new-finding fingerprinting below) stays inside
    # this block, before the disposable directory is cleaned up.
    import shutil
    import tempfile
    with tempfile.TemporaryDirectory(prefix="ps-real-sast-pilot-") as tmp:
        target = (work_dir or Path(tmp)) / "target.py"

        # 1. Real scan of the vulnerable state. Run it twice to confirm the
        # scanner deterministically reproduces the same finding, the same
        # purpose the CVE pilot's repeated pre-action probe served.
        shutil.copyfile(VULNERABLE_FILE, target)
        before_results_a = _scan(target)
        before_results_b = _scan(target)
        matches_a = [r for r in before_results_a if r["check_id"] == RULE_ID]
        matches_b = [r for r in before_results_b if r["check_id"] == RULE_ID]
        if not matches_a or not matches_b:
            raise ValueError("Scanner did not reproduce the known finding on the vulnerable fixture; "
                             "the lab fixture or rule file is broken, not a real resolved finding")
        report["scan_is_deterministic"] = (len(matches_a) == len(matches_b) == 1)

        before_line = matches_a[0]["start"]["line"]
        before_fp = fingerprint.compute(RULE_ID, str(target), before_line)
        before_finding = ScanFinding(
            finding_id="pilot-finding-0001", asset=ASSET, scanner_id="semgrep-oss-local-rule",
            rule_id=RULE_ID, fingerprint=before_fp, file_path=str(target),
            severity=_mapped_severity(matches_a[0]["extra"]["severity"]), present=True, observed_at=now,
        )
        before_evidence = confirm_before_fix(before_finding, scanner_registry, now=now)
        report["before_scan_raw"] = matches_a[0]
        report["before_fingerprint"] = before_fp

        # 2. Apply the real fix in place, over the same path, then re-scan
        # for the same fingerprint identity.
        shutil.copyfile(FIXED_FILE, target)
        after_results = _scan(target)
        after_matches_same_fp = [
            r for r in after_results
            if r["check_id"] == RULE_ID
            and fingerprint.compute(RULE_ID, str(target), r["start"]["line"]) == before_fp
        ]
        after_finding = ScanFinding(
            finding_id="pilot-finding-0001", asset=ASSET, scanner_id="semgrep-oss-local-rule",
            rule_id=RULE_ID, fingerprint=before_fp, file_path=str(target),
            severity=before_finding.severity, present=bool(after_matches_same_fp), observed_at=now,
        )
        after_evidence = confirm_resolution(after_finding, scanner_registry, now=now)
        report["after_scan_raw"] = after_results
        report["finding_still_present_after_fix"] = bool(after_matches_same_fp)

        # 3. Real regression check: an actual subprocess asserting the fixed
        # function still returns correct results against a real sqlite3 db.
        regression = subprocess.run(
            [sys.executable, str(HERE / "fixtures" / "regression_check_fixed.py")],
            capture_output=True, text=True, timeout=30, cwd=str(HERE),
        )
        report["regression_check_stdout"] = regression.stdout.strip()
        report["regression_check_returncode"] = regression.returncode
        from predict_shield.assessment import Evidence
        no_regression_evidence = Evidence(
            asset=ASSET, assertion=NO_REGRESSION + ":" + ASSET,
            observed_pass=(regression.returncode == 0), observed_at=now,
            source="regression-check:real-sast-pilot", independent=True,
        )

        # 4. Re-scan for any NEW high-or-critical finding introduced by the
        # fix, beyond the one finding we already know about and are
        # tracking above. Fingerprinted against the same disposable path
        # the fix was applied to, not a separately named fixture file.
        new_high_severity = [
            r for r in after_results
            if r["check_id"] != RULE_ID and _mapped_severity(r["extra"]["severity"]) in ("high", "critical")
        ]
        no_new_finding_scan_findings = []
        for r in new_high_severity:
            fp = fingerprint.compute(r["check_id"], str(target), r["start"]["line"])
            no_new_finding_scan_findings.append(ScanFinding(
                finding_id="new-" + fp, asset=ASSET, scanner_id="semgrep-oss-local-rule",
                rule_id=r["check_id"], fingerprint=fp, file_path=str(target),
                severity=_mapped_severity(r["extra"]["severity"]), present=True, observed_at=now,
            ))
        no_new_finding_evidence = confirm_no_new_high_severity(
            ASSET, "semgrep-oss-local-rule", scanner_registry, no_new_finding_scan_findings, now=now,
        )
        report["new_high_severity_findings_count"] = len(no_new_finding_scan_findings)

    # 5. Compose and evaluate, exactly as a real caller would. The temp
    # directory is gone by now; everything from here on is in-memory data
    # already extracted above, not a further file read.
    scope = {
        FINDING_CONFIRMED_BEFORE_FIX: (before_evidence.asset, before_evidence.assertion),
        FINDING_RESOLVED: (after_evidence.asset, after_evidence.assertion),
        NO_REGRESSION: (no_regression_evidence.asset, no_regression_evidence.assertion),
        NO_NEW_HIGH_SEVERITY_FINDING: (no_new_finding_evidence.asset, no_new_finding_evidence.assertion),
    }
    evidence = [before_evidence, after_evidence, no_regression_evidence, no_new_finding_evidence]
    verdict = evaluate_fix(scope, evidence, now=now)
    report["accepted"] = verdict.accepted
    report["blocking_reasons"] = list(verdict.blocking_reasons)
    report["assessments"] = {
        name: {"outcome": a.outcome.value, "reason": a.reason}
        for name, a in verdict.assessments.items()
    }
    report["elapsed_seconds"] = round(time.monotonic() - started, 3)
    report["sha256"] = hashlib.sha256(
        json.dumps(report, sort_keys=True, default=str, separators=(",", ":")).encode()
    ).hexdigest()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True, default=str) + "\n")
    print("REAL SAST PILOT RESULT: accepted =", verdict.accepted,
         "blocking_reasons =", verdict.blocking_reasons)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    run(output=args.output)


if __name__ == "__main__":
    main()
