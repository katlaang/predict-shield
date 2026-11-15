"""Compose the independent checks a remediation needs before it counts as
verified, not just "the one named vulnerability is gone".

Today, confirming a fix means confirming one assertion: the vulnerability's
own behavior is no longer observed (`exploit_confirmation`, or any other
confirmation source that writes `Evidence` for the same scope). That leaves
a real gap: a fix that clears the named vulnerability can still break
another consumer, resolve to a dependency set the package manager would
reject, or move to a version that itself carries a different known
vulnerability. None of that is "VERIFIED" by any honest reading, but a
pipeline that checks only the first assertion would call it that anyway.

This module adds no new trust and runs no checks itself. It only asks the
existing `assessment.assess()` gate the three additional questions, each
against the Evidence the dedicated check modules already produced
(`regression_check`, `dependency_resolution_check`,
`post_patch_vulnerability_scan`), and combines the four outcomes with the
same fail-closed rule used everywhere else in this pipeline: every
assertion must independently reach VERIFIED, or the remediation as a whole
is not accepted.
"""
from __future__ import annotations

from dataclasses import dataclass

from .assessment import Assessment, Evidence, Outcome, assess

# Every remediation this module evaluates must clear all four of these
# assertions. Adding a fifth required check later means adding its name
# here and its (asset, assertion) scope to the caller's `scope` mapping;
# nothing silently defaults to "not required".
VULNERABILITY_RESOLVED = "vulnerability_resolved"
NO_REGRESSION = "no_regression"
NO_NEW_KNOWN_VULNERABILITY = "no_new_known_vulnerability"
DEPENDENCY_RESOLUTION_OK = "dependency_resolution_ok"

REQUIRED_ASSERTIONS = (
    VULNERABILITY_RESOLVED,
    NO_REGRESSION,
    NO_NEW_KNOWN_VULNERABILITY,
    DEPENDENCY_RESOLUTION_OK,
)


@dataclass(frozen=True)
class RemediationVerdict:
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


def evaluate(scope: dict[str, tuple[str, str]], evidence: list[Evidence],
             **assess_kwargs) -> RemediationVerdict:
    """Evaluate all four required assertions and report whether the
    remediation as a whole is accepted.

    `scope` maps each name in `REQUIRED_ASSERTIONS` to the exact
    `(asset, assertion)` pair the corresponding check module used for its
    `Evidence` records. The four checks naturally use different assets
    (an authorized host for the exploit confirmation, a project name for
    the regression and dependency checks, a `package@version` string for
    the post-patch scan), so this is not a single shared asset; callers
    build the mapping from whatever each check module returned.

    Any name missing from `scope` is a caller error, not a verification
    outcome, so it raises rather than silently treating a required check
    as satisfied or skipped. `assess_kwargs` (e.g. `required_independent_checks`,
    `max_age_seconds`, `now`) are passed through to every `assess()` call.
    """
    missing = [name for name in REQUIRED_ASSERTIONS if name not in scope]
    if missing:
        raise ValueError("Missing required assertion scope for: " + ", ".join(missing))
    assessments = {
        name: assess(*scope[name], evidence, **assess_kwargs)
        for name in REQUIRED_ASSERTIONS
    }
    accepted = all(a.outcome is Outcome.VERIFIED for a in assessments.values())
    return RemediationVerdict(accepted, assessments)
