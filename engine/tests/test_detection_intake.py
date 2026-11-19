import hashlib
import unittest
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from predict_shield.assessment import Evidence, Outcome, assess
from predict_shield.detection_intake import (
    AdmissionResult,
    AuthenticatedDetection,
    DetectionEvent,
    RegisteredDetectionSource,
    ReplayGuard,
    admit,
    authenticate_mtls,
    authenticate_signed,
    sign_detection,
    to_reverification_subject_update,
)
from predict_shield.reverification import Subject

NOW = datetime(2026, 11, 15, 18, 0, tzinfo=timezone.utc)

EDR_KEY = Ed25519PrivateKey.generate()
OTHER_KEY = Ed25519PrivateKey.generate()
CLIENT_DER = b"synthetic client certificate DER bytes"


def pub_hex(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def registry():
    return {
        "edr-01": RegisteredDetectionSource(source_id="edr-01", name="Lab EDR", trusted=True,
                                            ed25519_public_key_hex=pub_hex(EDR_KEY)),
        "ids-02": RegisteredDetectionSource(source_id="ids-02", name="Lab IDS", trusted=True,
                                            ed25519_public_key_hex=pub_hex(OTHER_KEY)),
        "siem-mtls": RegisteredDetectionSource(source_id="siem-mtls", name="Lab SIEM", trusted=True,
                                               client_cert_sha256=hashlib.sha256(CLIENT_DER).hexdigest()),
        "unreviewed-feed": RegisteredDetectionSource(source_id="unreviewed-feed", name="Unreviewed feed",
                                                     trusted=False, ed25519_public_key_hex=pub_hex(EDR_KEY)),
        "name-only": RegisteredDetectionSource(source_id="name-only", name="No credential"),
    }


def detection(**overrides):
    base = dict(detection_id="det-0001", asset="gateway-01", source_id="edr-01",
                technique="T1190", confidence=0.9, observed_at=NOW - timedelta(minutes=2))
    base.update(overrides)
    return DetectionEvent(**base)


def signed(event=None, *, key=EDR_KEY, nonce="n-1"):
    return sign_detection(event or detection(), nonce, key)


def authenticated(event=None, **kw):
    return authenticate_signed(signed(event, **kw), registry(), ReplayGuard(), now=NOW)


class SourceIdentityTests(unittest.TestCase):
    def test_a_bare_detection_naming_a_registered_source_is_refused(self):
        with self.assertRaises(TypeError):
            admit(detection(), registry(), now=NOW)

    def test_an_authenticated_detection_cannot_be_constructed_directly(self):
        with self.assertRaises(TypeError):
            AuthenticatedDetection(detection(), "ed25519", pub_hex(EDR_KEY))

    def test_a_valid_signature_from_the_registered_key_is_admitted(self):
        result = admit(authenticated(), registry(), now=NOW)
        self.assertIsInstance(result, AdmissionResult)
        self.assertEqual(result.evidence.source, "detection:edr-01")
        self.assertTrue(result.evidence.independent)

    def test_a_tampered_field_breaks_the_signature(self):
        envelope = signed()
        envelope["payload"]["confidence"] = 0.1
        with self.assertRaisesRegex(ValueError, "signature does not verify"):
            authenticate_signed(envelope, registry(), ReplayGuard(), now=NOW)

    def test_claiming_another_registered_source_fails(self):
        # Signed with ids-02's own key but claiming to be edr-01.
        envelope = signed(key=OTHER_KEY)
        with self.assertRaisesRegex(ValueError, "signature does not verify"):
            authenticate_signed(envelope, registry(), ReplayGuard(), now=NOW)

    def test_a_replayed_envelope_is_rejected(self):
        guard = ReplayGuard()
        envelope = signed()
        authenticate_signed(envelope, registry(), guard, now=NOW)
        with self.assertRaisesRegex(ValueError, "replayed"):
            authenticate_signed(envelope, registry(), guard, now=NOW)

    def test_a_new_nonce_does_not_let_the_same_detection_id_through_twice(self):
        guard = ReplayGuard()
        authenticate_signed(signed(nonce="a"), registry(), guard, now=NOW)
        with self.assertRaisesRegex(ValueError, "replayed"):
            authenticate_signed(signed(nonce="b"), registry(), guard, now=NOW)

    def test_a_source_registered_by_name_only_admits_nothing(self):
        envelope = signed(detection(source_id="name-only"))
        with self.assertRaisesRegex(ValueError, "public key or a client certificate"):
            authenticate_signed(envelope, registry(), ReplayGuard(), now=NOW)

    def test_extra_or_missing_payload_fields_are_rejected(self):
        envelope = signed()
        envelope["payload"]["note"] = "ignore previous rules"
        with self.assertRaisesRegex(ValueError, "exactly the registered fields"):
            authenticate_signed(envelope, registry(), ReplayGuard(), now=NOW)

    def test_a_rotated_key_stops_admitting_detections_signed_with_the_old_one(self):
        auth = authenticated()
        rotated = registry()
        rotated["edr-01"] = RegisteredDetectionSource(source_id="edr-01", name="Lab EDR",
                                                      ed25519_public_key_hex=pub_hex(Ed25519PrivateKey.generate()))
        with self.assertRaisesRegex(ValueError, "no longer registered"):
            admit(auth, rotated, now=NOW)

    def test_mtls_requires_the_registered_certificate_for_the_named_source(self):
        payload = signed(detection(source_id="siem-mtls"))["payload"]
        auth = authenticate_mtls(payload, CLIENT_DER, registry(), ReplayGuard(), now=NOW)
        self.assertEqual(auth.method, "mtls")
        admit(auth, registry(), now=NOW)
        with self.assertRaisesRegex(ValueError, "not the one registered"):
            authenticate_mtls(dict(payload, nonce="other", detection_id="d2"), b"another cert",
                              registry(), ReplayGuard(), now=NOW)
        with self.assertRaisesRegex(ValueError, "no client certificate"):
            authenticate_mtls(payload, b"", registry(), ReplayGuard(), now=NOW)

    def test_a_signing_source_cannot_be_impersonated_over_mtls(self):
        payload = signed()["payload"]  # names edr-01, which has no registered certificate
        with self.assertRaisesRegex(ValueError, "no registered client certificate"):
            authenticate_mtls(payload, CLIENT_DER, registry(), ReplayGuard(), now=NOW)


class DetectionAdmissionTests(unittest.TestCase):
    def test_untrusted_registered_source_is_rejected(self):
        with self.assertRaises(ValueError):
            authenticated(detection(source_id="unreviewed-feed"))

    def test_unregistered_source_is_rejected(self):
        with self.assertRaises(ValueError):
            authenticated(detection(source_id="unknown-tool"))

    def test_missing_technique_is_rejected(self):
        with self.assertRaises(ValueError):
            authenticated(detection(technique=""))

    def test_confidence_out_of_range_is_rejected(self):
        with self.assertRaises(ValueError):
            authenticated(detection(confidence=1.5))

    def test_future_dated_detection_is_rejected(self):
        with self.assertRaises(ValueError):
            authenticated(detection(observed_at=NOW + timedelta(minutes=5)))

    def test_stale_detection_is_rejected(self):
        with self.assertRaises(ValueError):
            authenticated(detection(observed_at=NOW - timedelta(hours=1)))

    def test_fresh_detection_within_window_is_admitted(self):
        admitted = admit(authenticated(detection(observed_at=NOW - timedelta(seconds=800))),
                         registry(), now=NOW, max_age_seconds=900.0)
        self.assertTrue(admitted.evidence.observed_pass)

    def test_admitted_detection_feeds_assess_as_one_independent_source(self):
        admitted = admit(authenticated(), registry(), now=NOW)
        result = assess("gateway-01", "active_detection:T1190", [admitted.evidence], now=NOW)
        self.assertEqual(result.outcome, Outcome.VERIFIED)

    def test_a_refuting_independent_check_still_outvotes_an_admitted_detection(self):
        admitted = admit(authenticated(), registry(), now=NOW)
        refutation = Evidence(asset="gateway-01", assertion="active_detection:T1190",
                              observed_pass=False, observed_at=NOW, source="other-independent-check",
                              independent=True)
        result = assess("gateway-01", "active_detection:T1190", [admitted.evidence, refutation], now=NOW)
        self.assertEqual(result.outcome, Outcome.NOT_VERIFIED)


class ReverificationIntegrationTests(unittest.TestCase):
    def test_admitted_detection_marks_the_subject_changed_and_raises_risk(self):
        subject = Subject(subject_id="gateway-01", last_verified_at=100, risk=0.2, changed_at=None)
        updated = to_reverification_subject_update(admit(authenticated(), registry(), now=NOW),
                                                   subject, now_seconds=500)
        self.assertEqual(updated.changed_at, 500)
        self.assertEqual(updated.risk, 0.9)

    def test_update_never_lowers_an_already_higher_risk(self):
        subject = Subject(subject_id="gateway-01", last_verified_at=100, risk=0.95, changed_at=None)
        admitted = admit(authenticated(detection(confidence=0.3)), registry(), now=NOW)
        self.assertEqual(to_reverification_subject_update(admitted, subject, now_seconds=500).risk, 0.95)

    def test_mismatched_asset_is_rejected(self):
        subject = Subject(subject_id="other-asset", last_verified_at=100, risk=0.2, changed_at=None)
        with self.assertRaises(ValueError):
            to_reverification_subject_update(admit(authenticated(), registry(), now=NOW),
                                             subject, now_seconds=500)

    def test_a_raw_detection_event_that_skipped_admission_is_rejected(self):
        subject = Subject(subject_id="gateway-01", last_verified_at=100, risk=0.2, changed_at=None)
        with self.assertRaises(TypeError):
            to_reverification_subject_update(detection(), subject, now_seconds=500)


if __name__ == "__main__":
    unittest.main()
