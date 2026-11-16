"""Unit contracts only; the real semgrep subprocess and regression check run
in CI (and were run directly in this session to produce real evidence).
These tests mock the subprocess boundary and check the orchestration logic:
fingerprinting, severity mapping, and that a genuinely new high-severity
finding actually blocks acceptance rather than the check being vacuous.
"""
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import fingerprint
import run_real_sast_pilot as pilot

NOW = datetime(2026, 11, 15, 19, 0, tzinfo=timezone.utc)


def semgrep_result(check_id="python-sql-string-concat", line=9, severity="ERROR"):
    return {
        "check_id": check_id,
        "path": "fixture.py",
        "start": {"line": line, "col": 1, "offset": 0},
        "end": {"line": line, "col": 50, "offset": 50},
        "extra": {"severity": severity, "message": "test", "metadata": {},
                  "fingerprint": "requires login", "engine_kind": "OSS"},
    }


class FingerprintTests(unittest.TestCase):
    def test_same_function_same_fingerprint_across_a_one_line_edit(self):
        # A real fix edits one file in place; the fingerprint must survive
        # that, which is only meaningful when before and after are scanned
        # at the same path (see run_real_sast_pilot.run()'s target.py).
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "target.py"
            target.write_text("def get_user(conn, name):\n    return conn.execute(\"x\" + name)\n")
            fp_before = fingerprint.compute("rule", str(target), 2)
            target.write_text("def get_user(conn, name):\n    return conn.execute(\"x\", (name,))\n")
            fp_after = fingerprint.compute("rule", str(target), 2)
            self.assertEqual(fp_before, fp_after)

    def test_different_function_different_fingerprint(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "a.py"
            f.write_text("def one(x):\n    return x\n\n\ndef two(x):\n    return x\n")
            self.assertNotEqual(
                fingerprint.compute("rule", str(f), 2),
                fingerprint.compute("rule", str(f), 6),
            )

    def test_module_level_line_is_not_module_leaked_into_a_function(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "a.py"
            f.write_text("x = 1\n\n\ndef fn(y):\n    return y\n")
            fp_module = fingerprint.compute("rule", str(f), 1)
            fp_fn = fingerprint.compute("rule", str(f), 4)
            self.assertNotEqual(fp_module, fp_fn)


class SeverityMappingTests(unittest.TestCase):
    def test_error_maps_to_high(self):
        self.assertEqual(pilot._mapped_severity("ERROR"), "high")

    def test_warning_maps_to_medium(self):
        self.assertEqual(pilot._mapped_severity("WARNING"), "medium")

    def test_info_maps_to_low(self):
        self.assertEqual(pilot._mapped_severity("INFO"), "low")

    def test_unknown_defaults_to_low_not_high(self):
        # Fail closed in the conservative direction for *this* mapping: an
        # unrecognized label must not silently inflate severity.
        self.assertEqual(pilot._mapped_severity("WHATEVER"), "low")


class RunOrchestrationTests(unittest.TestCase):
    """Mocks the subprocess boundary (semgrep, the regression subprocess) to
    check the orchestration logic without depending on semgrep being
    installed in every environment that runs the unit suite."""

    def _run_with(self, before_results, after_results, regression_returncode=0):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "evidence.json"
            with patch.object(pilot, "_semgrep_version", return_value="1.999.0"), \
                 patch.object(pilot, "_scan", side_effect=[before_results, before_results, after_results]), \
                 patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=regression_returncode, stdout="", stderr="")
                return pilot.run(output=output)

    def test_a_clean_fix_with_no_new_finding_is_accepted(self):
        before = [semgrep_result()]
        after = []  # the fix removed the finding; nothing else introduced
        report = self._run_with(before, after)
        self.assertTrue(report["accepted"])
        self.assertEqual(report["new_high_severity_findings_count"], 0)

    def test_a_genuinely_new_high_severity_finding_blocks_acceptance(self):
        # Proves confirm_no_new_high_severity is not vacuous against real
        # semgrep severity strings (ERROR/WARNING/INFO), which was the bug
        # this module's first version had before the severity mapping fix.
        before = [semgrep_result()]
        after = [semgrep_result(check_id="python.other.new-issue", line=20, severity="ERROR")]
        report = self._run_with(before, after)
        self.assertFalse(report["accepted"])
        self.assertEqual(report["new_high_severity_findings_count"], 1)
        self.assertIn(pilot.NO_NEW_HIGH_SEVERITY_FINDING, "".join(report["blocking_reasons"]))

    def test_a_new_low_severity_finding_does_not_block_acceptance(self):
        before = [semgrep_result()]
        after = [semgrep_result(check_id="python.style.new-info", line=20, severity="INFO")]
        report = self._run_with(before, after)
        self.assertTrue(report["accepted"])
        self.assertEqual(report["new_high_severity_findings_count"], 0)

    def test_a_failing_regression_blocks_acceptance(self):
        before = [semgrep_result()]
        after = []
        report = self._run_with(before, after, regression_returncode=1)
        self.assertFalse(report["accepted"])
        self.assertIn(pilot.NO_REGRESSION, "".join(report["blocking_reasons"]))

    def test_finding_absent_from_the_before_scan_is_a_broken_fixture_error(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "evidence.json"
            with patch.object(pilot, "_semgrep_version", return_value="1.999.0"), \
                 patch.object(pilot, "_scan", side_effect=[[], []]):
                with self.assertRaises(ValueError):
                    pilot.run(output=output)

    def test_output_cannot_overwrite_existing_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "evidence.json"
            output.write_text("{}")
            with self.assertRaises(FileExistsError):
                pilot.run(output=output)


if __name__ == "__main__":
    unittest.main()
