"""Verifying a source-code vulnerability fix, not generating the rule that
found it. Detection engineering (writing or tuning SAST rules) is a
different problem from what this module does, and this module does not do
it: everything here takes a scanner's own finding as an untrusted input and
decides whether a fix to it can be accepted.

A dependency upgrade can be verified by checking a version number. A fix to
a finding such as SQL injection or unsafe deserialization cannot: there is
no version to check, only the scanner's own before/after read of the code.
That makes the composite acceptance pattern `remediation_verification.py`
already uses for dependency upgrades harder to apply here, not inapplicable:
this module adds the same four-assertions, all-or-nothing rule, with two
checks that do not exist for a dependency upgrade:

    * FINDING_CONFIRMED_BEFORE_FIX: the finding is actually present, at the
      claimed fingerprint, before any fix is credited with resolving it.
      This is a negative control, the same purpose the CVE pilot's
      pre-fix scan served in Section 4.4: it rules out crediting a fix for
      a hallucinated or mis-attributed report, rather than trusting the
      claim that a finding existed at all.
    * FINDING_RESOLVED: a re-scan at the same fingerprint no longer reports
      the finding. "Same fingerprint" means the scanner's own stable
      identifier for this finding (what CodeQL's `partialFingerprints` and
      Semgrep's `check_id` plus a content hash already exist to provide),
      never a raw line number: a patch shifts every line below it, so a
      line-number match would silently stop matching a finding that never
      moved, or falsely match an unrelated one that happens to land there.

NO_REGRESSION and NO_NEW_HIGH_SEVERITY_FINDING complete the four. This
module does not produce NO_REGRESSION evidence itself; it reuses whatever
`regression_check.check()` already produced for the same project, exactly
as `remediation_verification.py` does, rather than building a second
regression mechanism.

Fail-closed rules carried over from every other check in this pipeline:

    * A finding is only ever admitted from a scanner the operator
      registered ahead of time, pinned by tool and version, and marked
      trusted. An unregistered, untrusted or unpinned scanner is rejected
      before anything else runs.
    * A finding missing its fingerprint, rule ID or file path cannot be
      tracked across commits and is rejected outright, not silently
      accepted with a weaker match.
    * A stale scan (older than `max_age_seconds`) is rejected: accepting a
      fix on an outdated scan is not evidence the fix exists in the code
      being shipped.
    * `evaluate_fix()` adds no new trust and runs no checks itself. It
      only asks the existing `assessment.assess()` gate the four required
      questions and combines the outcomes with the same all-four-or-nothing
      rule used everywhere else: a failure or INDETERMINATE result on any
      one blocks acceptance even when the others pass.

What this module does NOT yet do, honestly, consistent with the Section 7.1
design sketch this implements:

    * The optional dynamic check for findings with a reachable, externally
      triggerable path is an opt-in fifth assertion
      (`VULNERABILITY_BEHAVIOR_ABSENT`, `evaluate_fix(require_dynamic=True)`).
      The caller produces its evidence from live exploitation attempts
      against the running target; this module does not run them.
    * Reachability-based prioritization using the existing dependency graph
      is not implemented. `severity` on a `ScanFinding` is carried through
      unchanged from the scanner's own rating; nothing here re-ranks it by
      exposure yet.
    * Nothing here calls a real scanner (Semgrep, CodeQL, or otherwise).
      `ScanFinding` is the shape a caller builds from a scanner's own
      output; no scanner integration exists in this repository yet.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from .assessment import Assessment, Evidence, Outcome, assess

SOURCE_PREFIX = "sast:"

HIGH_SEVERITIES = frozenset({"high", "critical"})

FINDING_CONFIRMED_BEFORE_FIX = "finding_confirmed_before_fix"
FINDING_RESOLVED = "finding_resolved"
NO_REGRESSION = "no_regression"
NO_NEW_HIGH_SEVERITY_FINDING = "no_new_high_severity_finding"
# Optional fifth assertion: live exploitation attempts against the running
# target fail after the fix. A static re-scan can pass an incomplete fix
# (escaping input while leaving it unquoted, for example), so a caller that
# can reach a running target should require this one too.
VULNERABILITY_BEHAVIOR_ABSENT = "vulnerability_behavior_absent"

# Every source-code fix this module evaluates must clear all four of these
# assertions. Adding the dynamic-check assertion later means adding its name
# here; nothing silently defaults to "not required".
REQUIRED_ASSERTIONS = (
    FINDING_CONFIRMED_BEFORE_FIX,
    FINDING_RESOLVED,
    NO_REGRESSION,
    NO_NEW_HIGH_SEVERITY_FINDING,
)


@dataclass(frozen=True)
class RegisteredScanner:
    """A static-analysis tool the operator has registered ahead of time,
    pinned to a specific version. An unpinned scanner is not reproducible
    evidence: the same rule catalog can change between runs."""

    scanner_id: str
    name: str
    version: str
    trusted: bool = True

    def validate(self) -> None:
        if not self.scanner_id:
            raise ValueError("scanner_id required")
        if not self.name:
            raise ValueError("name required")
        if not self.version:
            raise ValueError("version required: an unpinned scanner is not reproducible evidence")


@dataclass(frozen=True)
class ScanFinding:
    """One scanner's observation, at one point in time, of whether a
    fingerprinted finding is present. `fingerprint` must be the scanner's
    own stable identifier for this finding, never a raw line number."""

    finding_id: str
    asset: str
    scanner_id: str
    rule_id: str
    fingerprint: str
    file_path: str
    severity: str
    present: bool
    observed_at: datetime

    def _validate(self, now: datetime) -> None:
        if not self.finding_id or not self.asset or not self.scanner_id:
            raise ValueError("finding_id, asset and scanner_id are required")
        if not self.rule_id or not self.fingerprint or not self.file_path:
            raise ValueError("rule_id, fingerprint and file_path are required: "
                             "an unfingerprinted finding cannot be tracked across commits")
        if not self.severity:
            raise ValueError("severity is required")
        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")
        if self.observed_at > now:
            raise ValueError("observed_at is in the future: look-ahead scans are rejected")

    @property
    def key(self) -> str:
        """The scanner-stable identity this finding is tracked by across
        commits: rule plus fingerprint, never a file/line location."""
        return self.rule_id + ":" + self.fingerprint


def _check_registry(scanner_id: str, registry: dict[str, RegisteredScanner]) -> RegisteredScanner:
    scanner = registry.get(scanner_id)
    if scanner is None or not scanner.trusted:
        raise ValueError("scanner is not a registered, trusted source")
    scanner.validate()
    return scanner


def _check_freshness(observed_at: datetime, now: datetime, max_age_seconds: float) -> None:
    age_seconds = (now - observed_at).total_seconds()
    if age_seconds > max_age_seconds:
        raise ValueError("scan is stale: accepting a fix on an outdated scan is not evidence "
                         "the fix exists in the code being shipped")


def confirm_before_fix(finding: ScanFinding, registry: dict[str, RegisteredScanner], *,
                       now: datetime | None = None, max_age_seconds: float = 900.0) -> Evidence:
    """Admit a pre-fix scan as grounding evidence. The assertion holds
    (`observed_pass=True`) only when the finding was actually present: a
    pre-fix scan that reports no finding at this fingerprint means there is
    nothing here for a later fix to be credited with resolving.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    finding._validate(now)
    _check_registry(finding.scanner_id, registry)
    _check_freshness(finding.observed_at, now, max_age_seconds)
    return Evidence(asset=finding.asset, assertion=FINDING_CONFIRMED_BEFORE_FIX + ":" + finding.key,
                    observed_pass=finding.present, observed_at=finding.observed_at,
                    source=SOURCE_PREFIX + finding.scanner_id, independent=True)


def confirm_resolution(finding: ScanFinding, registry: dict[str, RegisteredScanner], *,
                       now: datetime | None = None, max_age_seconds: float = 900.0) -> Evidence:
    """Admit a post-fix scan at the same fingerprint. The assertion holds
    only when the finding is no longer present; a finding still present at
    this fingerprint is a failed resolution, not a pass.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    finding._validate(now)
    _check_registry(finding.scanner_id, registry)
    _check_freshness(finding.observed_at, now, max_age_seconds)
    return Evidence(asset=finding.asset, assertion=FINDING_RESOLVED + ":" + finding.key,
                    observed_pass=not finding.present, observed_at=finding.observed_at,
                    source=SOURCE_PREFIX + finding.scanner_id, independent=True)


def confirm_no_new_high_severity(asset: str, scanner_id: str, registry: dict[str, RegisteredScanner],
                                 new_high_severity_findings: list[ScanFinding], *,
                                 now: datetime | None = None, max_age_seconds: float = 900.0) -> Evidence:
    """Admit a re-scan of the files touched by the fix as evidence that it
    introduced no new high-or-critical finding. `new_high_severity_findings`
    must be the findings the re-scan reported at high or critical severity
    that were absent from the pre-fix scan; computing that diff is the
    caller's job, this function only checks the registry, freshness and
    severity of what it is given, and whether the set is empty.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    _check_registry(scanner_id, registry)
    for new_finding in new_high_severity_findings:
        new_finding._validate(now)
        if new_finding.severity.lower() not in HIGH_SEVERITIES:
            raise ValueError("new_high_severity_findings must each be high or critical severity")
        if new_finding.scanner_id != scanner_id:
            raise ValueError("new_high_severity_findings must all come from the scanner passed in")
    observed_at = max((f.observed_at for f in new_high_severity_findings), default=now)
    _check_freshness(observed_at, now, max_age_seconds)
    return Evidence(asset=asset, assertion=NO_NEW_HIGH_SEVERITY_FINDING,
                    observed_pass=len(new_high_severity_findings) == 0, observed_at=observed_at,
                    source=SOURCE_PREFIX + scanner_id, independent=True)


@dataclass(frozen=True)
class SastFixVerdict:
    accepted: bool
    assessments: dict[str, Assessment]

    @property
    def blocking_reasons(self) -> tuple[str, ...]:
        """One line per assertion that did not reach VERIFIED, for a human
        or a log to read without re-deriving the outcome."""
        return tuple(
            f"{name}: {assessment.outcome.value} -- {assessment.reason}"
            for name, assessment in self.assessments.items()
            if assessment.outcome is not Outcome.VERIFIED
        )


def evaluate_fix(scope: dict[str, tuple[str, str]], evidence: list[Evidence], *,
                 require_dynamic: bool = False, **assess_kwargs) -> SastFixVerdict:
    """Evaluate all four required assertions for one source-code fix and
    report whether it is accepted as a whole, following the same
    all-four-or-nothing rule `remediation_verification.evaluate()` uses for
    dependency upgrades.

    `scope` maps each name in `REQUIRED_ASSERTIONS` to the exact
    `(asset, assertion)` pair the corresponding evidence used: the two
    `confirm_*` functions above for the first two, and whatever
    `regression_check.check()` and `confirm_no_new_high_severity()`
    produced for the other two. Any name missing from `scope` is a caller
    error, not a verification outcome, so it raises rather than silently
    treating a required check as satisfied or skipped.
    """
    required = REQUIRED_ASSERTIONS + ((VULNERABILITY_BEHAVIOR_ABSENT,) if require_dynamic else ())
    missing = [name for name in required if name not in scope]
    if missing:
        raise ValueError("Missing required assertion scope for: " + ", ".join(missing))
    assessments = {
        name: assess(*scope[name], evidence, **assess_kwargs)
        for name in required
    }
    accepted = all(a.outcome is Outcome.VERIFIED for a in assessments.values())
    return SastFixVerdict(accepted, assessments)
