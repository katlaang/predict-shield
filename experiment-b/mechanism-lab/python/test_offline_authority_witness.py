"""Negative and bounded-outcome controls for offline authority witness.

All observations are test fixtures. These are not physical authority outages.
"""
from __future__ import annotations

import copy
import unittest

from offline_authority_witness import freeze_witness, validate_witness, offline_bounds


def example():
    witness = freeze_witness(
        {"trialId": "lab-trial-a", "revoked": True, "other": "uninterpreted"},
        authority_http=200,
        inventory=["enforcer-a", "enforcer-b", "enforcer-c", "gateway"],
        captured_at="2026-11-19T00:00:00Z",
    )
    nodes = [
        {"node": n, "revoked_probe_http": 403, "legitimate_probe_http": 200}
        for n in ("enforcer-a", "enforcer-b", "enforcer-c", "gateway")
    ]
    return witness, nodes


class OfflineWitnessTests(unittest.TestCase):
    def test_full_offline_probes_still_not_verified(self):
        witness, nodes = example()
        validate_witness(witness)
        result = offline_bounds(
            witness, authority_http=None, observed_at="2026-11-19T00:00:03Z",
            nodes=nodes,
        )
        self.assertEqual(result["revoked_denial_fraction_bounds"], [1., 1.])
        self.assertEqual(result["legitimate_access_fraction_bounds"], [1., 1.])
        self.assertEqual(result["verification_outcome"], "INDETERMINATE")
        self.assertIsNone(result["authority_truth_current"])
        self.assertFalse(result["full_reconciliation"])

    def test_missing_probe_is_unknown_not_success(self):
        witness, nodes = example()
        nodes[0]["revoked_probe_http"] = None
        nodes[1]["legitimate_probe_http"] = None
        result = offline_bounds(
            witness, authority_http=None, observed_at="2026-11-19T00:00:03Z",
            nodes=nodes,
        )
        self.assertEqual(result["revoked_denial_fraction_bounds"], [0.75, 1.0])
        self.assertEqual(result["legitimate_access_fraction_bounds"], [0.75, 1.0])
        self.assertEqual(result["revoked_unknown"], 1)

    def test_observed_wrong_http_is_failure_not_unknown(self):
        witness, nodes = example()
        nodes[0]["revoked_probe_http"] = 200
        nodes[1]["legitimate_probe_http"] = 403
        result = offline_bounds(
            witness, authority_http=None, observed_at="2026-11-19T00:00:03Z",
            nodes=nodes,
        )
        self.assertEqual(result["revoked_denial_fraction_bounds"], [0.75, 0.75])
        self.assertEqual(result["legitimate_access_fraction_bounds"], [0.75, 0.75])

    def test_incomplete_inventory_rejected(self):
        witness, nodes = example()
        for altered in (nodes[:-1], nodes[:3] + [nodes[0]]):
            with self.assertRaises(ValueError):
                offline_bounds(
                    witness, authority_http=None,
                    observed_at="2026-11-19T00:00:03Z", nodes=altered,
                )

    def test_witness_tampering_and_missing_source_prohibited(self):
        witness, nodes = example()
        for edit in (
            lambda w: w["policy"].update(revoked=False),
            lambda w: w.update(authority_http=None),
            lambda w: w.update(witness_sha256="0" * 64),
            lambda w: w.update(source_policy_sha256="0" * 64),
        ):
            altered = copy.deepcopy(witness)
            edit(altered)
            with self.assertRaises(ValueError):
                validate_witness(altered)

    def test_preoutage_witness_requires_live_revocation(self):
        with self.assertRaises(ValueError):
            freeze_witness({"trialId": "a", "revoked": False},
                           authority_http=200, inventory=["a", "b", "c", "d"],
                           captured_at="2026-11-19T00:00:00Z")
        with self.assertRaises(ValueError):
            freeze_witness({"trialId": "a", "revoked": True},
                           authority_http=None, inventory=["a", "b", "c", "d"],
                           captured_at="2026-11-19T00:00:00Z")

    def test_outage_order_and_live_authority_rejected(self):
        witness, nodes = example()
        for status, time in ((None, "2026-11-18T23:59:00Z"),
                             (None, "2026-11-19T00:00:00Z"),
                             (200, "2026-11-19T00:01:00Z"),
                             (503, "2026-11-19T00:01:00Z")):
            with self.subTest(status=status, time=time):
                with self.assertRaises(ValueError):
                    offline_bounds(witness, authority_http=status,
                                   observed_at=time, nodes=nodes)


if __name__ == "__main__":
    unittest.main()
