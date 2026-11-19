"""OSV adapter, against recorded-shape responses (no network). The real
OSV.dev run happens in CI (public-sources.yml)."""
import io
import json
import unittest
from datetime import datetime, timezone

from predict_shield.assessment import Outcome, assess
from predict_shield.osv_source import NotRepresentable, ranges_for, scan_with_osv

NOW = datetime(2026, 11, 18, tzinfo=timezone.utc)


def vuln(vid, events, kind="SEMVER", name="lodash"):
    return {"id": vid, "affected": [{"package": {"name": name, "ecosystem": "npm"},
                                     "ranges": [{"type": kind, "events": events}]}]}


ALL = [vuln("GHSA-A", [{"introduced": "0"}, {"fixed": "4.17.19"}]),
       vuln("GHSA-B", [{"introduced": "4.0.0"}, {"fixed": "4.17.21"}])]


class FakeOpener:
    """Answers the all-versions query and the exact-version query."""

    def __init__(self, everything, by_version, fail=False):
        self.everything, self.by_version, self.fail = everything, by_version, fail

    def __call__(self, request, timeout=None):
        if self.fail:
            raise OSError("network unreachable")
        body = json.loads(request.data)
        vulns = self.by_version.get(body.get("version"), []) if "version" in body else self.everything
        return _Response(json.dumps({"vulns": vulns}).encode())


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class RangeTests(unittest.TestCase):
    def test_introduced_fixed_pairs_convert(self):
        ranges = ranges_for(ALL[0], "lodash", "npm")
        self.assertTrue(ranges[0].contains("4.17.11"))
        self.assertFalse(ranges[0].contains("4.17.21"))

    def test_open_ended_range_is_affected_from_there_on(self):
        (r,) = ranges_for(vuln("X", [{"introduced": "1.0.0"}]), "lodash", "npm")
        self.assertTrue(r.contains("9.0.0"))

    def test_last_affected_and_git_ranges_are_not_represented(self):
        with self.assertRaises(NotRepresentable):
            ranges_for(vuln("X", [{"introduced": "0"}, {"last_affected": "1.2.3"}]), "lodash", "npm")
        with self.assertRaises(NotRepresentable):
            ranges_for(vuln("X", [{"introduced": "abc"}], kind="GIT"), "lodash", "npm")

    def test_other_packages_are_ignored(self):
        self.assertEqual(ranges_for(vuln("X", [{"introduced": "0"}], name="other"), "lodash", "npm"), ())


class ScanTests(unittest.TestCase):
    def outcome(self, result):
        e = result.evidence
        return assess(e.asset, e.assertion, [e], now=NOW).outcome

    def test_both_methods_agree_the_version_is_clean(self):
        result = scan_with_osv("lodash", "npm", "4.17.21", opener=FakeOpener(ALL, {}), now=NOW)
        self.assertEqual(self.outcome(result), Outcome.VERIFIED)

    def test_both_methods_agree_the_version_is_affected(self):
        result = scan_with_osv("lodash", "npm", "4.17.15",
                               opener=FakeOpener(ALL, {"4.17.15": ALL}), now=NOW)
        self.assertEqual(self.outcome(result), Outcome.NOT_VERIFIED)
        self.assertEqual(result.advisories_covering_version, ("GHSA-A", "GHSA-B"))

    def test_disagreement_is_never_a_clean_result(self):
        # OSV's version query reports an advisory the ranges do not cover.
        result = scan_with_osv("lodash", "npm", "4.17.21",
                               opener=FakeOpener(ALL, {"4.17.21": [vuln("GHSA-NEW", [])]}), now=NOW)
        self.assertNotEqual(self.outcome(result), Outcome.VERIFIED)
        self.assertIn("disagree", result.reason)

    def test_unreachable_osv_is_never_a_clean_result(self):
        result = scan_with_osv("lodash", "npm", "4.17.21", opener=FakeOpener([], {}, fail=True), now=NOW)
        self.assertNotEqual(self.outcome(result), Outcome.VERIFIED)
        self.assertIn("could not be queried", result.reason)


if __name__ == "__main__":
    unittest.main()
