"""Pilot: run the dependency-resolution and regression checks for real against
the actual mechanism-lab Java project, instead of only the fake runners the
unit tests use.

This is the piece `engine/predict_shield/remediation_verification.py` needed
to stop being fixture-only: a real project with a real, registered test
command and a real, registered resolver command. `mechanism-lab` is a real
choice, not a convenient one: it is the one Java project in this repository
that is actually built and tested in CI today (see
`.github/workflows/experiment-b-mechanism.yml`), it has a real dependency
manager (Maven) and a real version to bump when a Spring Boot advisory
lands, and it has a real, network-free JUnit test
(`EnforcementControllerEpochTest`) that would actually fail if a dependency
bump broke the enforcement cache's isolation behavior.

What this intentionally does not do: confirm a specific CVE is resolved
(`vulnerability_resolved`, via `exploit_confirmation.py`). That check needs a
signature registered per advisory, the same way it already works for a
web-facing target; nothing here stands in for that. This script only pilots
the other three assertions `remediation_verification.REQUIRED_ASSERTIONS`
added: no regression, dependency resolution succeeds, and (noted below) the
new-version advisory rescan.

Run from the repository root:

    PYTHONPATH=engine python experiment-b/mechanism-lab/verify_remediation.py

Both checks run `mvn` inside the project's own `maven:3.9-eclipse-temurin-25`
build image via `docker run`, the same image its `Dockerfile` builds with,
rather than whatever Maven or JDK happens to be on the host. That needs a
running Docker daemon and real network access (to pull the image and to
resolve against Maven Central), so this only produces a real pass/fail
result where both exist (CI; not every sandboxed environment). Where they
do not, the fail-closed behavior built into `dependency_resolution_check`
and `regression_check` still applies: a check that cannot run reports
`integrity_ok=False`, never a silent pass, so a missing daemon or a blocked
network is reported honestly as "could not verify," not as success.
"""
from __future__ import annotations

import sys
from pathlib import Path

from predict_shield.dependency_resolution_check import ResolutionCheck
from predict_shield.dependency_resolution_check import check as check_resolution
from predict_shield.regression_check import RegressionSuite
from predict_shield.regression_check import check as check_regression
from predict_shield.remediation_verification import (
    DEPENDENCY_RESOLUTION_OK,
    NO_NEW_KNOWN_VULNERABILITY,
    NO_REGRESSION,
    VULNERABILITY_RESOLVED,
)

PROJECT = "mechanism-lab"
JAVA_DIR = Path(__file__).resolve().parent / "java"

# Run through the exact same maven:3.9-eclipse-temurin-25 image the project's
# own Dockerfile builds with, not whatever Maven/JDK the host happens to
# have. This matches the one other place this project is actually built
# (the Dockerfile), so a pass here means what the CI build already means.
_MAVEN_IMAGE = "maven:3.9-eclipse-temurin-25"


def _mvn_in_container(*goals: str) -> tuple[str, ...]:
    return ("docker", "run", "--rm", "-v", f"{JAVA_DIR}:/build", "-w", "/build",
           _MAVEN_IMAGE, "mvn", "-B", "-q", *goals)


RESOLUTION = ResolutionCheck(project=PROJECT, command=_mvn_in_container("dependency:resolve"),
                             cwd=str(JAVA_DIR))
REGRESSION = RegressionSuite(project=PROJECT, command=_mvn_in_container("test"),
                             cwd=str(JAVA_DIR))


def main() -> int:
    # Generous timeouts: the first run also has to pull the maven image.
    resolution_evidence = check_resolution(RESOLUTION, timeout=300.0)
    regression_evidence = check_regression(REGRESSION, timeout=300.0)

    for name, evidence in (("dependency resolution", resolution_evidence),
                           ("regression suite", regression_evidence)):
        if not evidence.integrity_ok:
            print(f"{name}: could not run (integrity_ok=False) -- "
                 f"this is reported as unverified, not a pass; see assertion "
                 f"{evidence.assertion!r} for the registered command")
        else:
            print(f"{name}: {'passed' if evidence.observed_pass else 'FAILED'} "
                 f"({evidence.assertion})")

    print()
    print("Not piloted here (needs a per-advisory registration, same as the "
         f"existing web-facing check): {VULNERABILITY_RESOLVED}")
    print(f"Not piloted here (needs a live advisory lookup for the bumped "
         f"version): {NO_NEW_KNOWN_VULNERABILITY}")
    print(f"Piloted for real against {PROJECT}: {NO_REGRESSION}, {DEPENDENCY_RESOLUTION_OK}")

    both_ran = resolution_evidence.integrity_ok and regression_evidence.integrity_ok
    both_passed = bool(resolution_evidence.observed_pass) and bool(regression_evidence.observed_pass)
    return 0 if (both_ran and both_passed) else 1


if __name__ == "__main__":
    sys.exit(main())
