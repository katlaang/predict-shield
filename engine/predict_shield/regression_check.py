"""Independent regression check: does the project's own test suite still pass
with a proposed fix applied.

A remediation that removes the named vulnerability can still break something
else the rest of the codebase depends on. The only honest way to catch that
is to actually run the consuming project's own test suite against the
changed dependency, not to assume one hand-picked "legitimate use still
works" probe stands in for the whole suite.

Like `dependency_resolution_check`, the command is registered by the
operator ahead of time for a given project, never invented from advisory
text or a model's reply. A failure to run the suite at all (timeout, missing
test runner) is reported as a failed probe, never as a pass.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from .assessment import Evidence

SOURCE = "regression-check"


@dataclass(frozen=True)
class RegressionSuite:
    """A reviewed, project-specific test-suite invocation, registered ahead of time."""
    project: str
    command: tuple[str, ...]
    cwd: str

    @property
    def assertion(self) -> str:
        return "no_regression:" + self.project


def check(suite: RegressionSuite, *, runner: Callable = subprocess.run,
         timeout: float = 600.0, now: datetime | None = None) -> Evidence:
    """Run the registered test suite and report whether it passed.

    A nonzero exit is a regression. A runner error (timeout, crash, missing
    executable) is not evidence of no regression either; it means this
    check could not be completed, so it is reported with `integrity_ok=False`
    rather than a clean pass.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    try:
        completed = runner(list(suite.command), cwd=suite.cwd,
                           capture_output=True, text=True, timeout=timeout)
        return Evidence(asset=suite.project, assertion=suite.assertion,
                        observed_pass=completed.returncode == 0, observed_at=now,
                        source=SOURCE, independent=True)
    except (subprocess.TimeoutExpired, OSError):
        return Evidence(asset=suite.project, assertion=suite.assertion,
                        observed_pass=None, observed_at=now, source=SOURCE,
                        independent=True, integrity_ok=False)
