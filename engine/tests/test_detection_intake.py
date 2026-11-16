import unittest
from datetime import datetime, timedelta, timezone

from predict_shield.assessment import Outcome, assess
from predict_shield.detection_intake import (
    AdmissionResult,
    DetectionEvent,
    RegisteredDetectionSource,
    admit,
    to_reverification_subject_update,
)
from predict_shield.reverification import Subject

NOW = datetime(2026, 11, 15, 18, 0, tzinfo=timezone.utc)

REGISTRY = {
    "edr-01": RegisteredDetectionSource(source_id="edr-01", name="Lab EDR", trusted=True),
    "unreviewed-feed": RegisteredDetectionSource(source_id="unreviewed-feed", name="Unreviewed feed", trusted=False),
}


def detection(**overrides):
    base = dict(detection_id="det-0001", asset="gateway-01", source_id="edr-01",
               technique="T1190", confidence=0.9, observed_at=NOW - timedelta(minutes=2))
    base.update(overrides)
    return DetectionEvent(**base)


class DetectionAdmissionTests(unittest.TestCase):
    def test_registered_trusted_source_is_admitted(self):
        result = admit(detection(), REGISTRY, now=NOW)
        self.assertIsInstance(result, AdmissionResult)
        evidence = result.evidence
        self.assertEqual(evidence.asset, "gateway-01")
        self.assertEqual(evidence.assertion, "active_detection:T1190")
        self.assertTrue(evidence.observed_pass)
        self.assertTrue(evidence.independent)
        self.assertEqual(evidence.source, "detection:edr-01")
        self.assertEqual(result.asset, "gateway-01")
        self.assertEqual(result.confidence, 0.9)

    def test_unregistered_source_is_rejected(self):
        with self.assertRaises(ValueError):
            admit(detection(source_id="unknown-tool"), REGISTRY, now=NOW)

    def test_untrusted_registered_source_is_rejected(self):
        with self.assertRaises(ValueError):
            admit(detection(source_id="unreviewed-feed"), REGISTRY, now=NOW)

    def test_missing_technique_is_rejected(self):
        with self.assertRaises(ValueError):
            admit(detection(technique=""), REGISTRY, now=NOW)

    def test_confidence_out_of_range_is_rejected(self):
        with self.assertRaises(ValueError):
            admit(detection(confidence=1.5), REGISTRY, now=NOW)

    def test_future_dated_detection_is_rejected(self):
        with self.assertRaises(ValueError):
            admit(detection(observed_at=NOW + timedelta(minutes=5)), REGISTRY, now=NOW)

    def test_stale_detection_is_rejected(self):
        with self.assertRaises(ValueError):
            admit(detection(observed_at=NOW - timedelta(hours=1)), REGISTRY, now=NOW, max_age_seconds=900.0)

    def test_fresh_detection_within_window_is_admitted(self):
        admitted = admit(detection(observed_at=NOW - timedelta(seconds=800)),
                         REGISTRY, now=NOW, max_age_seconds=900.0)
        self.assertTrue(admitted.evidence.observed_pass)

    def test_admitted_detection_feeds_assess_as_one_independent_source(self):
        admitted = admit(detection(), REGISTRY, now=NOW)
        result = assess("gateway-01", "active_detection:T1190", [admitted.evidence], now=NOW)
        self.assertEqual(result.outcome, Outcome.VERIFIED)

    def test_a_refuting_independent_check_still_outvotes_an_admitted_detection(self):
        from predict_shield.assessment import Evidence
        admitted = admit(detection(), REGISTRY, now=NOW)
        refutation = Evidence(asset="gateway-01", assertion="active_detection:T1190",
                              observed_pass=False, observed_at=NOW, source="other-independent-check",
                              independent=True)
        result = assess("gateway-01", "active_detection:T1190", [admitted.evidence, refutation], now=NOW)
        self.assertEqual(result.outcome, Outcome.NOT_VERIFIED)


class ReverificationIntegrationTests(unittest.TestCase):
    def test_admitted_detection_marks_the_subject_changed_and_raises_risk(self):
        subject = Subject(subject_id="gateway-01", last_verified_at=100, risk=0.2, changed_at=None)
        admitted = admit(detection(confidence=0.9), REGISTRY, now=NOW)
        updated = to_reverification_subject_update(admitted, subject, now_seconds=500)
        self.assertEqual(updated.changed_at, 500)
        self.assertEqual(updated.risk, 0.9)

    def test_update_never_lowers_an_already_higher_risk(self):
        subject = Subject(subject_id="gateway-01", last_verified_at=100, risk=0.95, changed_at=None)
        admitted = admit(detection(confidence=0.3), REGISTRY, now=NOW)
        updated = to_reverification_subject_update(admitted, subject, now_seconds=500)
        self.assertEqual(updated.risk, 0.95)

    def test_mismatched_asset_is_rejected(self):
        subject = Subject(subject_id="other-asset", last_verified_at=100, risk=0.2, changed_at=None)
        admitted = admit(detection(), REGISTRY, now=NOW)
        with self.assertRaises(ValueError):
            to_reverification_subject_update(admitted, subject, now_seconds=500)

    def test_a_raw_detection_event_that_skipped_admission_is_rejected(self):
        subject = Subject(subject_id="gateway-01", last_verified_at=100, risk=0.2, changed_at=None)
        with self.assertRaises(TypeError):
            to_reverification_subject_update(detection(), subject, now_seconds=500)

    def test_an_unregistered_sources_detection_cannot_reach_the_scheduler(self):
        subject = Subject(subject_id="gateway-01", last_verified_at=100, risk=0.2, changed_at=None)
        with self.assertRaises(ValueError):
            admit(detection(source_id="unknown-tool"), REGISTRY, now=NOW)
        # No AdmissionResult was produced, so there is nothing a caller could
        # legitimately pass to to_reverification_subject_update at all.


if __name__=="__main__": unittest.main()
