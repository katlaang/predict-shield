"""Unit contracts only; the real npm installs and the real independent_probe.js
subprocess run in CI (and were run directly in this session to produce real
evidence -- see the module docstring in verify_remediation_via_registration.py).
These tests mock the subprocess boundary and check that a probe which fails
the negative control is refused, rather than silently credited.
"""
import unittest
from unittest.mock import patch

import verify_remediation_via_registration as pilot


class NegativeControlTests(unittest.TestCase):
    def test_a_pre_fix_probe_that_never_observes_pollution_is_refused(self):
        # If the before-version probe reports no pollution, the exploit
        # payload did not actually land -- crediting the after-version fix
        # with resolving something that was never reproduced would be
        # exactly the mistake a negative control exists to catch.
        with patch.object(pilot, "_npm_install"), \
             patch.object(pilot, "_probe", return_value={
                 "observed_package_version": pilot.BEFORE,
                 "pollution_observed": False,
                 "benign_functionality_works": True,
             }):
            self.assertEqual(pilot.main(), 1)

    def test_a_pre_fix_probe_on_the_wrong_version_is_refused(self):
        with patch.object(pilot, "_npm_install"), \
             patch.object(pilot, "_probe", return_value={
                 "observed_package_version": "9.9.9",
                 "pollution_observed": True,
                 "benign_functionality_works": True,
             }):
            self.assertEqual(pilot.main(), 1)


if __name__ == "__main__":
    unittest.main()
