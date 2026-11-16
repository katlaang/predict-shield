"""A reusable, declarative way to register a remediation-verification
target, instead of writing a new one-off pilot script per project.

Before this module, the two real pilots this pipeline has
(`experiment-b/mechanism-lab/verify_remediation.py` for the Maven
project, `experiment-b/real-cve-remediation/verify_remediation.py` for
the npm lodash lab) each hand-wrote their own `ResolutionCheck`,
`RegressionSuite`, and advisory list inline in Python. That is two
real, working demonstrations, but not yet a mechanism an operator could
point at a third project without writing a third script. This module is
that mechanism: a project's resolver command, test command, and known
advisories are declared once as data (`RegisteredRemediationTarget`, or
the JSON schema `load_target()` reads), and `run_checks()` /
`verify()` run the three deterministic checks for real against whatever
target was registered.

Deliberately excluded from what this module runs: `vulnerability_resolved`.
That assertion needs a reviewed, CVE-specific confirmation probe (an
`exploit_confirmation.py` signature check, or an equivalent independent
behavior probe written and reviewed for that one vulnerability) --
nothing here invents or automates that probe for an arbitrary target.
The caller supplies that one assertion's `Evidence` separately, the same
boundary both existing pilots already respect: registering a project's
build/test commands is safe to generalize, generating a new exploit
probe per advisory is not, and this module does not blur that line.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable
import subprocess

from .assessment import Evidence
from .dependency_resolution_check import ResolutionCheck
from .dependency_resolution_check import check as check_resolution
from .post_patch_vulnerability_scan import KnownAdvisory, scan
from .regression_check import RegressionSuite
from .regression_check import check as check_regression
from .remediation_verification import (
    DEPENDENCY_RESOLUTION_OK,
    NO_NEW_KNOWN_VULNERABILITY,
    NO_REGRESSION,
    VULNERABILITY_RESOLVED,
    RemediationVerdict,
    evaluate,
)
from .versions import VersionRange

SCHEMA = "predict-shield/remediation-target/1"


@dataclass(frozen=True)
class RegisteredRemediationTarget:
    """Everything an operator registers ahead of time for one project:
    the resolver and test-suite invocations the deterministic checks
    need, and the package/new-version/advisory data the post-patch scan
    needs. `resolution.project` and `regression.project` are each
    check's own asset name and need not equal `project` itself (the two
    existing pilots use different asset names for the Maven project
    versus the isolated npm lab), so this does not force one shared
    asset where the underlying checks do not share one.
    """

    project: str
    resolution: ResolutionCheck
    regression: RegressionSuite
    package: str
    new_version: str
    advisories: tuple[KnownAdvisory, ...]

    def validate(self) -> None:
        if not self.project:
            raise ValueError("project required")
        if not self.package or not self.new_version:
            raise ValueError("package and new_version required for the post-patch scan")


def load_target(path: Path) -> RegisteredRemediationTarget:
    """Load a target from the declarative JSON schema this module defines,
    instead of a one-off Python script hand-building the same objects.
    Malformed or missing fields raise rather than default silently --
    a registration with the wrong command checks the wrong thing and
    should fail loudly, not quietly verify nothing."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("schema") != SCHEMA:
        raise ValueError(f"Unsupported remediation-target schema: {payload.get('schema')!r}")
    project = payload["project"]
    if not isinstance(project, str) or not project:
        raise ValueError("project must be a non-empty string")
    resolution = ResolutionCheck(
        project=payload.get("resolution_project", project),
        command=tuple(payload["resolution_command"]),
        cwd=payload["resolution_cwd"],
    )
    regression = RegressionSuite(
        project=payload.get("regression_project", project),
        command=tuple(payload["regression_command"]),
        cwd=payload["regression_cwd"],
    )
    advisories = tuple(
        KnownAdvisory(
            advisory_id=a["advisory_id"],
            package=a["package"],
            ranges=tuple(
                VersionRange(introduced=r.get("introduced"), fixed=r.get("fixed"))
                for r in a["ranges"]
            ),
        )
        for a in payload.get("advisories", [])
    )
    target = RegisteredRemediationTarget(
        project=project, resolution=resolution, regression=regression,
        package=payload["package"], new_version=payload["new_version"],
        advisories=advisories,
    )
    target.validate()
    return target


def run_checks(
    target: RegisteredRemediationTarget, vulnerability_resolved: Evidence, *,
    resolution_runner: Callable = subprocess.run,
    regression_runner: Callable = subprocess.run,
    resolution_timeout: float = 300.0, regression_timeout: float = 300.0,
    now: datetime | None = None,
) -> tuple[list[Evidence], dict[str, tuple[str, str]]]:
    """Run the three deterministic checks for real against the registered
    target, combine them with the caller-supplied `vulnerability_resolved`
    evidence, and build the `(asset, assertion)` scope
    `remediation_verification.evaluate()` requires.

    `now` is threaded into every check's own `observed_at`, not left to
    each one's independent real-clock default: `assess()` later compares
    every assertion's evidence age against this same `now`, so letting
    the checks timestamp themselves independently of it would make a
    perfectly real, passing result look stale (or future-dated) purely
    from clock skew between calls, not from an actual freshness problem.

    Does not call `evaluate()` itself: the caller decides the remaining
    `assess_kwargs` (`max_age_seconds`, `required_independent_checks`),
    the same division of responsibility `sast_findings.evaluate_fix` and
    `remediation_verification.evaluate` already use.
    """
    resolution_evidence = check_resolution(
        target.resolution, runner=resolution_runner, timeout=resolution_timeout, now=now)
    regression_evidence = check_regression(
        target.regression, runner=regression_runner, timeout=regression_timeout, now=now)
    rescan_evidence = scan(target.package, target.new_version, target.advisories, now=now)
    scope = {
        VULNERABILITY_RESOLVED: (vulnerability_resolved.asset, vulnerability_resolved.assertion),
        NO_REGRESSION: (regression_evidence.asset, regression_evidence.assertion),
        NO_NEW_KNOWN_VULNERABILITY: (rescan_evidence.asset, rescan_evidence.assertion),
        DEPENDENCY_RESOLUTION_OK: (resolution_evidence.asset, resolution_evidence.assertion),
    }
    evidence = [vulnerability_resolved, regression_evidence, rescan_evidence, resolution_evidence]
    return evidence, scope


def verify(
    target: RegisteredRemediationTarget, vulnerability_resolved: Evidence, *,
    resolution_runner: Callable = subprocess.run,
    regression_runner: Callable = subprocess.run,
    resolution_timeout: float = 300.0, regression_timeout: float = 300.0,
    now: datetime | None = None,
    **assess_kwargs,
) -> RemediationVerdict:
    """Convenience wrapper: run_checks() then remediation_verification.evaluate().
    `now` is forwarded to both (so every check's own evidence and the
    final assess() freshness comparison share one clock); the remaining
    run_checks()-specific keywords are kept separate from **assess_kwargs
    (max_age_seconds, required_independent_checks) so the latter only
    ever reach evaluate(), not the subprocess runners."""
    evidence, scope = run_checks(
        target, vulnerability_resolved,
        resolution_runner=resolution_runner, regression_runner=regression_runner,
        resolution_timeout=resolution_timeout, regression_timeout=regression_timeout,
        now=now,
    )
    return evaluate(scope, evidence, now=now, **assess_kwargs)
