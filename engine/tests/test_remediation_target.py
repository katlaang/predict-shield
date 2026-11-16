import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

from predict_shield.assessment import Evidence
from predict_shield.remediation_target import (
    SCHEMA,
    load_target,
    run_checks,
    verify,
)
from predict_shield.remediation_verification import (
    DEPENDENCY_RESOLUTION_OK,
    NO_NEW_KNOWN_VULNERABILITY,
    NO_REGRESSION,
    VULNERABILITY_RESOLVED,
)

NOW = datetime(2026, 11, 15, tzinfo=timezone.utc)


def _registration_payload(**overrides):
    payload = {
        "schema": SCHEMA,
        "project": "widget-api",
        "resolution_command": ["npm", "install", "--dry-run"],
        "resolution_cwd": "/tmp/widget-api",
        "regression_command": ["npm", "test"],
        "regression_cwd": "/tmp/widget-api",
        "package": "left-pad",
        "new_version": "2.3.0",
        "advisories": [
            {"advisory_id": "GHSA-fake-0001", "package": "left-pad",
             "ranges": [{"introduced": "0", "fixed": "2.0.0"}]},
        ],
    }
    payload.update(overrides)
    return payload


def _write(payload) -> Path:
    tmp = Path(tempfile.mkstemp(suffix=".json")[1])
    tmp.write_text(json.dumps(payload))
    return tmp


class LoadTargetTests(unittest.TestCase):
    def test_a_well_formed_registration_loads(self):
        target = load_target(_write(_registration_payload()))
        self.assertEqual(target.project, "widget-api")
        self.assertEqual(target.resolution.command, ("npm", "install", "--dry-run"))
        self.assertEqual(target.regression.command, ("npm", "test"))
        self.assertEqual(target.package, "left-pad")
        self.assertEqual(len(target.advisories), 1)

    def test_wrong_schema_is_rejected(self):
        with self.assertRaises(ValueError):
            load_target(_write(_registration_payload(schema="something-else/1")))

    def test_missing_project_is_rejected(self):
        payload = _registration_payload()
        del payload["project"]
        with self.assertRaises(KeyError):
            load_target(_write(payload))

    def test_empty_project_is_rejected(self):
        with self.assertRaises(ValueError):
            load_target(_write(_registration_payload(project="")))

    def test_resolution_and_regression_can_use_a_different_asset_name_than_project(self):
        # The two existing real pilots use a different asset name per check
        # than the project's own name (e.g. "isolated-npm:lodash"); loading
        # must not force one shared asset where the checks do not share one.
        target = load_target(_write(_registration_payload(
            resolution_project="isolated-npm:left-pad", regression_project="isolated-npm:left-pad")))
        self.assertEqual(target.resolution.project, "isolated-npm:left-pad")
        self.assertEqual(target.regression.project, "isolated-npm:left-pad")


class RunChecksTests(unittest.TestCase):
    def _vulnerability_resolved(self):
        return Evidence(asset="widget-api", assertion="cve-reproduced:CVE-2026-00001",
                        observed_pass=True, observed_at=NOW, source="reviewed-probe", independent=True)

    def test_a_clean_target_produces_a_scope_covering_all_four_assertions(self):
        target = load_target(_write(_registration_payload()))
        ok = MagicMock(returncode=0, stdout="", stderr="")
        evidence, scope = run_checks(
            target, self._vulnerability_resolved(),
            resolution_runner=MagicMock(return_value=ok), regression_runner=MagicMock(return_value=ok),
        )
        self.assertEqual(set(scope), {VULNERABILITY_RESOLVED, NO_REGRESSION,
                                      NO_NEW_KNOWN_VULNERABILITY, DEPENDENCY_RESOLUTION_OK})
        self.assertEqual(len(evidence), 4)

    def test_verify_accepts_when_every_real_check_passes_and_new_version_is_clean(self):
        target = load_target(_write(_registration_payload()))
        ok = MagicMock(returncode=0, stdout="", stderr="")
        verdict = verify(
            target, self._vulnerability_resolved(), now=NOW,
            resolution_runner=MagicMock(return_value=ok), regression_runner=MagicMock(return_value=ok),
        )
        self.assertTrue(verdict.accepted)
        self.assertEqual(verdict.blocking_reasons, ())

    def test_verify_blocks_when_the_real_regression_check_fails(self):
        target = load_target(_write(_registration_payload()))
        ok = MagicMock(returncode=0, stdout="", stderr="")
        failed = MagicMock(returncode=1, stdout="", stderr="")
        verdict = verify(
            target, self._vulnerability_resolved(), now=NOW,
            resolution_runner=MagicMock(return_value=ok), regression_runner=MagicMock(return_value=failed),
        )
        self.assertFalse(verdict.accepted)
        self.assertIn(NO_REGRESSION, "".join(verdict.blocking_reasons))

    def test_verify_blocks_when_the_new_version_still_matches_a_known_advisory(self):
        # package stays "left-pad" but new_version falls back inside the
        # registered advisory's affected range: the post-patch scan must
        # catch this exactly like it does for the hand-written pilots.
        target = load_target(_write(_registration_payload(new_version="1.9.9")))
        ok = MagicMock(returncode=0, stdout="", stderr="")
        verdict = verify(
            target, self._vulnerability_resolved(), now=NOW,
            resolution_runner=MagicMock(return_value=ok), regression_runner=MagicMock(return_value=ok),
        )
        self.assertFalse(verdict.accepted)
        self.assertIn(NO_NEW_KNOWN_VULNERABILITY, "".join(verdict.blocking_reasons))

    def test_verify_blocks_when_the_caller_supplied_probe_reports_unresolved(self):
        # vulnerability_resolved is deliberately never generated by this
        # module (it needs a reviewed, CVE-specific probe the caller
        # supplies); a reviewed probe that reports the vulnerability is
        # still present must still block acceptance through this path.
        target = load_target(_write(_registration_payload()))
        ok = MagicMock(returncode=0, stdout="", stderr="")
        unresolved = Evidence(asset="widget-api", assertion="cve-reproduced:CVE-2026-00001",
                              observed_pass=False, observed_at=NOW, source="reviewed-probe", independent=True)
        verdict = verify(
            target, unresolved, now=NOW,
            resolution_runner=MagicMock(return_value=ok), regression_runner=MagicMock(return_value=ok),
        )
        self.assertFalse(verdict.accepted)
        self.assertIn(VULNERABILITY_RESOLVED, "".join(verdict.blocking_reasons))


if __name__ == "__main__":
    unittest.main()
