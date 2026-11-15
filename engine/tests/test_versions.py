import unittest

from predict_shield.versions import UnsupportedVersion, VersionRange, parse


class VersionTests(unittest.TestCase):
    def test_numeric_ordering_is_not_text_ordering(self):
        self.assertLess(parse("2.9.0"), parse("2.10.0"))
        self.assertEqual(parse("2.0"), parse("2.0.0"))
        self.assertEqual(parse("4.1.77.Final"), parse("4.1.77"))

    def test_qualifiers_that_cannot_be_ordered_are_refused(self):
        for version in ("2.0-beta9", "9.4.44.v20210927", "1.2.83_noneautotype", "latest", ""):
            with self.assertRaises(UnsupportedVersion):
                parse(version)

    def test_range_is_inclusive_below_and_exclusive_above(self):
        r = VersionRange("2.14.0", "2.17.1")
        self.assertEqual([r.contains(v) for v in ("2.13.9", "2.14.0", "2.17.0", "2.17.1", "3.0.0")],
                         [False, True, True, False, False])
        self.assertTrue(VersionRange(None, "1.5").contains("0.1"))
        self.assertTrue(VersionRange("1.5", None).contains("9.0"))

    def test_invalid_ranges_are_rejected(self):
        with self.assertRaises(ValueError):
            VersionRange(None, None)
        with self.assertRaises(ValueError):
            VersionRange("2.0", "1.0")
        with self.assertRaises(UnsupportedVersion):
            VersionRange(None, "2.0").contains("2.0-rc1")


if __name__ == "__main__":
    unittest.main()
