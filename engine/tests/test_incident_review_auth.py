"""Cryptographic reviewer provenance tests using disposable Ed25519 keys.

All incidents and reviewers here are synthetic laboratory fixtures.
"""
from __future__ import annotations

import copy
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from predict_shield.incident_review_auth import (
    RegisteredReviewer, review_message, verify_reviews, train_on_authenticated_reviews,
)
from predict_shield.incident_feedback import SCHEMA


def row(i, group, split, verdict):
    return {
        "schema": SCHEMA, "incident_id": f"review-case-{i}",
        "asset_group": group, "split": split, "detected_at": "2026-11-18T18:00:00Z",
        "signal_source_id": "ids-1", "alert_evidence_sha256": f"{1000+i:064x}",
        "pre_action_features": {
            "network_alert": verdict == "ATTACK",
            "endpoint_alert": i % 2 == 0,
            "known_vulnerability": False, "observed_remote_access": verdict == "ATTACK",
            "critical_service_count": 1, "independent_source_count": 1,
        },
        "independent_review": {
            "verdict": verdict, "reviewer_id": "independent-reviewer-1",
            "reviewed_at": "2026-11-18T20:00:00Z",
            "independent_evidence_sha256": f"{2000+i:064x}",
        },
    }


def fixture():
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ).hex()
    groups = ("train-a", "train-b", "calibrate-a", "test-a")
    registry = {
        "independent-reviewer-1": RegisteredReviewer(
            reviewer_id="independent-reviewer-1",
            public_key_ed25519_hex=public,
            permitted_asset_groups=frozenset(groups),
            independent_of_sources=frozenset(("ids-1",)),
        )
    }
    records = []
    for n, group in enumerate(groups):
        split = "train" if group.startswith("train") else "calibration" if group.startswith("calibrate") else "test"
        for offset, verdict in enumerate(("BENIGN", "ATTACK")):
            records.append(row(n * 2 + offset, group, split, verdict))
    records.append(row(10, "test-a", "test", "UNKNOWN"))
    return key, registry, [
        {"review": r, "signature": key.sign(review_message(r)).hex()} for r in records
    ]


class SignedReviewTests(unittest.TestCase):
    def test_signed_reviews_are_admitted_and_unknown_retained(self):
        _, registry, envelopes = fixture()
        prepared = verify_reviews(envelopes, registry)
        self.assertEqual(prepared["included"], 8)
        self.assertEqual(prepared["excluded_unknown"], 1)
        self.assertEqual(prepared["authentication"]["review_signatures_verified"], 9)
        self.assertFalse(prepared["authentication"]["ground_truth_confirmed"])

    def test_any_modified_verdict_or_feature_is_rejected(self):
        _, registry, envelopes = fixture()
        for mutate in (
            lambda r: r["independent_review"].update(verdict="BENIGN"),
            lambda r: r["pre_action_features"].update(network_alert=False),
            lambda r: r.update(asset_group="test-a"),
            lambda r: r.update(alert_evidence_sha256="c" * 64),
        ):
            with self.subTest(mutate=mutate):
                tampered = copy.deepcopy(envelopes)
                mutate(tampered[1]["review"])
                with self.assertRaises(ValueError):
                    verify_reviews(tampered, registry)

    def test_wrong_signer_and_unregistered_reviewer_rejected(self):
        key, registry, envelopes = fixture()
        bogus = Ed25519PrivateKey.generate()
        tampered = copy.deepcopy(envelopes)
        tampered[0]["signature"] = bogus.sign(review_message(tampered[0]["review"])).hex()
        with self.assertRaises(ValueError):
            verify_reviews(tampered, registry)
        tampered = copy.deepcopy(envelopes)
        tampered[0]["review"]["independent_review"]["reviewer_id"] = "unknown-reviewer"
        with self.assertRaises(ValueError):
            verify_reviews(tampered, registry)

    def test_registered_scope_and_independence_rejected(self):
        _, registry, envelopes = fixture()
        original = registry["independent-reviewer-1"]
        for altered in (
            RegisteredReviewer(original.reviewer_id, original.public_key_ed25519_hex,
                               frozenset(("train-a",)), original.independent_of_sources),
            RegisteredReviewer(original.reviewer_id, original.public_key_ed25519_hex,
                               original.permitted_asset_groups, frozenset(("other-ids",))),
        ):
            with self.subTest(altered=altered):
                with self.assertRaises(ValueError):
                    verify_reviews(envelopes, {"independent-reviewer-1": altered})

    def test_duplicate_reviews_and_wrong_envelope_rejected(self):
        _, registry, envelopes = fixture()
        with self.assertRaises(ValueError):
            verify_reviews(envelopes + [envelopes[0]], registry)
        with self.assertRaises(ValueError):
            verify_reviews([dict(envelopes[0], extra="no")], registry)

    def test_unauthenticated_key_claim_cannot_enter_validated_dataset(self):
        _, registry, envelopes = fixture()
        tampered = copy.deepcopy(envelopes)
        tampered[2]["signature"] = "0" * 128
        with self.assertRaises(ValueError):
            verify_reviews(tampered, registry)


@unittest.skipUnless(__import__("importlib").util.find_spec("sklearn") is not None,
                     "scikit-learn optional; train integration is run in dedicated CI")
class SignedTrainingTests(unittest.TestCase):
    def test_training_requires_all_signed_labels(self):
        _, registry, envelopes = fixture()
        model, report = train_on_authenticated_reviews(envelopes, registry)
        self.assertTrue(report["ai_model_trained"])
        self.assertEqual(report["review_authentication"]["review_signatures_verified"], 9)
        self.assertFalse(model["label_ground_truth_confirmed"])
        self.assertFalse(model["production_deployable"])
        bad = copy.deepcopy(envelopes)
        bad[0]["signature"] = "1" * 128
        with self.assertRaises(ValueError):
            train_on_authenticated_reviews(bad, registry)


if __name__ == "__main__":
    unittest.main()
