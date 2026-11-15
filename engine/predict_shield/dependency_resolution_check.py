"""Deterministic dependency-resolution gate ("does this version even install cleanly").

Before any fix is even proposed as safe, the cheapest real check is whether
the package manager's own resolver accepts the proposed version alongside
everything else a project already depends on. This catches a real class of
wrong fix that has nothing to do with the vulnerability itself: a version
bump that conflicts with another package's declared version range.

This never guesses the command to run. The operator registers, ahead of
time, exactly which resolver invocation checks a given project (e.g.
`["npm", "install", "--dry-run"]` run inside that project's directory),
never something built from advisory text or a model reply.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from .assessment import Evidence

SOURCE = "dependency-resolution-check"


@dataclass(frozen=True)
class ResolutionCheck:
    """A reviewed, project-specific resolver invocation, registered ahead of time."""
    project: str
    command: tuple[str, ...]
    cwd: str

    @property
    def assertion(self) -> str:
        return "dependency_resolution_ok:" + self.project


def check(resolution: ResolutionCheck, *, runner: Callable = subprocess.run,
         timeout: float = 120.0, now: datetime | None = None) -> Evidence:
    """Run the registered resolver command and report whether it succeeded.

    A nonzero exit and a runner error (timeout, missing executable) both
    count as "could not confirm resolution succeeds". A crashed or timed-out
    resolver is not evidence the dependencies resolve; it is evidence this
    check could not be completed, so it is reported as a failed probe
    (`integrity_ok=False`), which `assess()` already treats as unusable
    evidence rather than a pass.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    try:
        completed = runner(list(resolution.command), cwd=resolution.cwd,
                           capture_output=True, text=True, timeout=timeout)
        return Evidence(asset=resolution.project, assertion=resolution.assertion,
                        observed_pass=completed.returncode == 0, observed_at=now,
                        source=SOURCE, independent=True)
    except (subprocess.TimeoutExpired, OSError):
        return Evidence(asset=resolution.project, assertion=resolution.assertion,
                        observed_pass=None, observed_at=now, source=SOURCE,
                        independent=True, integrity_ok=False)
