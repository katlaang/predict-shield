"""A second, independent real target run through remediation_target.py's
generic registration mechanism -- not the lodash case again.

The lodash pilot (experiment-b/real-cve-remediation) proved the generic
mechanism reproduces a hand-written pilot's result, but it was still only
ever exercised against one project. This script registers a genuinely
different real CVE fix (minimist, CVE-2021-44906 / GHSA-xvch-5gv4-984h,
prototype pollution via `--_.constructor.constructor.prototype.foo bar`,
the exact PoC Snyk's own advisory SNYK-JS-MINIMIST-2429795 publishes,
fixed in 1.2.6) and runs it
through the exact same remediation_target.verify() path, with its own
independent probe written from scratch for this package (not reused from
the lodash pilot's helpers), to show the mechanism generalizes rather than
being tuned to one case.

Real npm installs, a real independent_probe.js subprocess, a real
`npm install --dry-run` dependency-resolution check, and a scan against
two real advisories (version ranges confirmed against OSV.dev, not
guessed: GHSA-xvch-5gv4-984h introduced 0 fixed 1.2.6; GHSA-vh95-rmgr-6w4m
introduced 0 fixed 0.2.1 and introduced 1.0.0 fixed 1.2.3). Negative
control: the before-fix install is independently probed too, and this
script refuses to proceed if the probe does not actually observe the
pollution on the vulnerable version -- crediting a fix that was never
really exercised would be worse than not piloting it at all.

Run from this directory (needs real npm/network access):

    PYTHONPATH=../../engine python verify_remediation_via_registration.py
"""
from __future__ import annotations

import json
import shlex
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from predict_shield.assessment import Evidence
from predict_shield.remediation_target import SCHEMA, load_target, verify

PKG = "minimist"
BEFORE = "1.2.5"
AFTER = "1.2.6"
CVE = "CVE-2021-44906"
PROBE = Path(__file__).resolve().with_name("independent_probe.js")
ASSET = "isolated-npm:" + PKG

ADVISORIES = [
    {"advisory_id": "GHSA-xvch-5gv4-984h", "package": PKG,
     "ranges": [{"introduced": "0", "fixed": "1.2.6"}]},
    {"advisory_id": "GHSA-vh95-rmgr-6w4m", "package": PKG,
     "ranges": [{"introduced": "0", "fixed": "0.2.1"},
                {"introduced": "1.0.0", "fixed": "1.2.3"}]},
]


def _npm_install(root: Path, version: str) -> None:
    root.mkdir(parents=True, exist_ok=True)
    subprocess.run(["npm", "install", f"{PKG}@{version}", "--prefix", str(root)],
                   check=True, capture_output=True, text=True, timeout=120)


def _probe(root: Path) -> dict:
    completed = subprocess.run(["node", str(PROBE), str(root)],
                               check=True, capture_output=True, text=True, timeout=30)
    return json.loads(completed.stdout)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ps-real-minimist-lab-") as tmp:
        before_root = Path(tmp) / "before"
        after_root = Path(tmp) / "after"

        # Negative control: the known-vulnerable version must actually be
        # observed as vulnerable by this exact probe before any fix is
        # credited with resolving it.
        _npm_install(before_root, BEFORE)
        pre = _probe(before_root)
        if pre["observed_package_version"] != BEFORE:
            print(f"Install did not land on the expected pre-fix version: {pre}", file=sys.stderr)
            return 1
        if not pre["pollution_observed"]:
            print("Negative control failed: the pre-fix version was not observed "
                 "as vulnerable by this probe, so a fix cannot honestly be credited "
                 "with resolving it.", file=sys.stderr)
            return 1

        _npm_install(after_root, AFTER)
        post = _probe(after_root)
        patched = (post["observed_package_version"] == AFTER
                  and post["pollution_observed"] is False
                  and post["benign_functionality_works"] is True)
        vulnerability_resolved = Evidence(
            asset=ASSET, assertion="mitigated:" + CVE, observed_pass=patched,
            observed_at=datetime.now(timezone.utc),
            source="independent-node-behavior-probe", independent=True,
        )

        # The probe always exits 0 and prints its JSON observation (so the
        # negative-control and vulnerability_resolved reads above never
        # fail on a vulnerable install); a real regression check needs a
        # real exit code, so this pipes that same JSON through a check that
        # fails if either benign functionality broke or pollution is still
        # observed. Making the probe's own exit code double as the
        # regression verdict would have been the same kind of vacuous-check
        # mistake the SAST pilot's severity check made earlier today.
        regression_command = (
            "bash", "-c",
            f"node {shlex.quote(str(PROBE))} {shlex.quote(str(after_root))} | "
            f"python3 -c \"import json,sys; d=json.load(sys.stdin); "
            f"sys.exit(0 if d['benign_functionality_works'] and not d['pollution_observed'] else 1)\"",
        )
        registration = {
            "schema": SCHEMA,
            "project": ASSET,
            "resolution_command": ["npm", "install", "--dry-run", "--prefix", str(after_root)],
            "resolution_cwd": str(after_root),
            "regression_command": list(regression_command),
            "regression_cwd": str(after_root),
            "package": PKG,
            "new_version": AFTER,
            "advisories": ADVISORIES,
        }
        registration_path = Path(tmp) / "registration.json"
        registration_path.write_text(json.dumps(registration, indent=2))

        target = load_target(registration_path)
        verdict = verify(target, vulnerability_resolved, now=datetime.now(timezone.utc))

        print("Pre-fix probe (negative control):", json.dumps(pre))
        print("Post-fix probe:", json.dumps(post))
        print()
        print("Overall accepted:", verdict.accepted)
        for reason in verdict.blocking_reasons:
            print("  blocking:", reason)
        for name, assessment in verdict.assessments.items():
            print(f"  {name}: {assessment.outcome.value}")

        return 0 if verdict.accepted else 1


if __name__ == "__main__":
    sys.exit(main())
