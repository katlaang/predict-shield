"""Intrusion-informed containment: "a new input to Assess: authorized
detections" (the framework design white paper's Phase 2 extension point).

Detection engineering (writing or generating rules for a SIEM, scoring
MITRE ATT&CK coverage) is a different problem from what this module does,
and this module does not do it. There is no rule generator here. What this
module does is narrower and matches what the design actually specifies:
decide whether an inbound detection alert, produced by a tool this pipeline
does not control, is admissible as evidence at all, and if so, raise the
urgency of the assertion it concerns using the mechanisms this pipeline
already has (`assessment.assess`, the re-verification scheduler), rather
than inventing new ones.

A detection alert is treated exactly like advisory text and threat feeds
elsewhere in this pipeline: untrusted by default. It is admitted only from
a source the operator registered ahead of time, following the same
fail-closed pattern `exploit_confirmation.py` already uses for registered
HTTP signatures:

    * A detection is only ever admitted if its source tool is in the
      operator's registered catalog ahead of time, and that source is
      marked trusted. An unregistered or untrusted source is rejected
      before anything else runs.
    * A detection with a confidence outside [0,1], a missing technique
      identifier, or a timestamp in the future relative to `now` is
      rejected outright, not silently clamped or defaulted.
    * A stale detection (older than `max_age_seconds`) is rejected:
      urgency only ever comes from a current signal, the same freshness
      rule `assessment.assess` already enforces for every other assertion.
    * Admission produces an `AdmissionResult` (carrying the `Evidence` for
      the existing `assessment.assess()` pipeline) and that result, not a
      raw `DetectionEvent`, is the only thing `to_reverification_subject_
      update()` accepts: a detection that never went through `admit()`
      cannot raise a subject's priority, enforced at runtime, not only by
      type hint. It never itself approves, executes, or verifies an
      action, and it does not change what counts as VERIFIED: a
      conflicting independent check can still outvote an admitted
      detection exactly as today.

What this module does NOT yet do: it does not tighten the policy gate's
own response deadlines or raise an action's approval tier based on
detection confidence.

Source identity. A registered name is not enough. Every source is
registered with a credential, and `admit()` accepts only an
`AuthenticatedDetection`, which only the two authenticators below can
produce:

    * `authenticate_signed()`: the detection's canonical JSON payload must
      carry a valid Ed25519 signature from the public key registered for
      the source it names. A payload that names one source but is signed
      by another source's key fails, because the signature is always
      checked against the named source's key.
    * `authenticate_mtls()`: the detection arrived over TLS with a client
      certificate whose SHA-256 fingerprint is the one registered for the
      source it names (`intake_server.py` terminates that TLS).

Both paths reject a reused (source, nonce) or (source, detection_id) pair
inside the freshness window, so a captured detection cannot be replayed.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from math import isfinite

from .assessment import Evidence
from .reverification import Subject

SOURCE_PREFIX = "detection:"


@dataclass(frozen=True)
class RegisteredDetectionSource:
    """A detection tool (SIEM, EDR, IDS) the operator has registered ahead
    of time. A detection from any other source_id is never admitted."""

    source_id: str
    name: str
    trusted: bool = True
    # At least one credential is required. A source registered by name
    # alone can never have a detection admitted.
    ed25519_public_key_hex: str = ""
    client_cert_sha256: str = ""

    def validate(self) -> None:
        if not self.source_id:
            raise ValueError("source_id required")
        if not self.name:
            raise ValueError("name required")
        if not self.ed25519_public_key_hex and not self.client_cert_sha256:
            raise ValueError("a registered source needs a public key or a client certificate fingerprint")
        if self.ed25519_public_key_hex and not _is_hex(self.ed25519_public_key_hex, 64):
            raise ValueError("ed25519_public_key_hex must be 32 bytes of hex")
        if self.client_cert_sha256 and not _is_hex(self.client_cert_sha256, 64):
            raise ValueError("client_cert_sha256 must be a SHA-256 hex digest")


def _is_hex(value: str, length: int) -> bool:
    return len(value) == length and all(c in "0123456789abcdef" for c in value)


@dataclass(frozen=True)
class DetectionEvent:
    """An inbound, untrusted claim that something is happening on `asset`.
    Nothing here is taken on faith: `admit()` checks it against the
    operator's registered source catalog, and against its own internal
    consistency, before it becomes evidence of anything."""

    detection_id: str
    asset: str
    source_id: str
    technique: str
    confidence: float
    observed_at: datetime

    def _validate(self, now: datetime) -> None:
        if not self.detection_id or not self.asset or not self.source_id:
            raise ValueError("detection_id, asset and source_id are required")
        if not self.technique:
            raise ValueError("technique is required: an ungrounded detection cannot be admitted")
        if not isfinite(self.confidence) or not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be finite in [0,1]")
        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")
        if self.observed_at > now:
            raise ValueError("observed_at is in the future: look-ahead detections are rejected")


_PAYLOAD_FIELDS = ("detection_id", "asset", "source_id", "technique",
                   "confidence", "observed_at", "nonce")
_AUTH_TOKEN = object()


def canonical_payload(event: DetectionEvent, nonce: str) -> bytes:
    """The exact bytes a source signs: sorted keys, no whitespace, UTC ISO time."""
    if not nonce or len(nonce) > 128:
        raise ValueError("nonce must be a non-empty string of at most 128 characters")
    payload = {
        "detection_id": event.detection_id, "asset": event.asset,
        "source_id": event.source_id, "technique": event.technique,
        "confidence": event.confidence,
        "observed_at": event.observed_at.astimezone(timezone.utc).isoformat(),
        "nonce": nonce,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _event_from_payload(payload: dict) -> tuple[DetectionEvent, str]:
    if not isinstance(payload, dict) or set(payload) != set(_PAYLOAD_FIELDS):
        raise ValueError("detection payload must have exactly the registered fields")
    confidence = payload["confidence"]
    if type(confidence) not in (int, float):
        raise ValueError("confidence must be a number")
    for name in ("detection_id", "asset", "source_id", "technique", "observed_at", "nonce"):
        if not isinstance(payload[name], str):
            raise ValueError(name + " must be a string")
    observed = datetime.fromisoformat(payload["observed_at"])
    event = DetectionEvent(detection_id=payload["detection_id"], asset=payload["asset"],
                           source_id=payload["source_id"], technique=payload["technique"],
                           confidence=float(confidence), observed_at=observed)
    return event, payload["nonce"]


class ReplayGuard:
    """Remembers (source, nonce) and (source, detection_id) for the freshness
    window. Anything older than the window is rejected as stale anyway, so
    memory stays bounded by the window. Thread-safe for the intake server."""

    def __init__(self, window_seconds: float = 900.0):
        if not isfinite(window_seconds) or window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.window_seconds = window_seconds
        self._seen: dict[tuple[str, str, str], datetime] = {}
        self._lock = threading.Lock()

    def check_and_record(self, event: DetectionEvent, nonce: str, now: datetime) -> None:
        keys = (("nonce", event.source_id, nonce), ("id", event.source_id, event.detection_id))
        with self._lock:
            cutoff = now.timestamp() - self.window_seconds
            for key in [k for k, t in self._seen.items() if t.timestamp() < cutoff]:
                del self._seen[key]
            if any(key in self._seen for key in keys):
                raise ValueError("replayed detection: nonce or detection_id already seen for this source")
            for key in keys:
                self._seen[key] = event.observed_at


@dataclass(frozen=True)
class AuthenticatedDetection:
    """A detection whose origin was cryptographically checked. Only
    `authenticate_signed()` and `authenticate_mtls()` can construct one."""

    event: DetectionEvent
    method: str
    credential_fingerprint: str
    _token: object = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        if self._token is not _AUTH_TOKEN:
            raise TypeError("AuthenticatedDetection is produced only by an authenticator")


def _source_for(event: DetectionEvent, registry: dict[str, RegisteredDetectionSource]) -> RegisteredDetectionSource:
    source = registry.get(event.source_id)
    if source is None or not source.trusted:
        raise ValueError("detection source is not a registered, trusted source")
    source.validate()
    return source


def _fresh(event: DetectionEvent, now: datetime, max_age_seconds: float) -> None:
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    event._validate(now)
    if (now - event.observed_at).total_seconds() > max_age_seconds:
        raise ValueError("detection is stale: urgency requires a current signal")


def authenticate_signed(envelope: dict, registry: dict[str, RegisteredDetectionSource],
                        replay_guard: ReplayGuard, *, now: datetime | None = None,
                        max_age_seconds: float = 900.0) -> AuthenticatedDetection:
    """Verify an Ed25519-signed detection against the named source's key."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    now = now or datetime.now(timezone.utc)
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
        raise ValueError("envelope must contain exactly payload and signature")
    event, nonce = _event_from_payload(envelope["payload"])
    source = _source_for(event, registry)
    if not source.ed25519_public_key_hex:
        raise ValueError("source has no registered signing key")
    signature = envelope["signature"]
    if not isinstance(signature, str) or not _is_hex(signature, 128):
        raise ValueError("signature must be 64 bytes of hex")
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(source.ed25519_public_key_hex))
    try:
        key.verify(bytes.fromhex(signature), canonical_payload(event, nonce))
    except InvalidSignature:
        raise ValueError("signature does not verify against the source's registered key") from None
    _fresh(event, now, max_age_seconds)
    replay_guard.check_and_record(event, nonce, now)
    return AuthenticatedDetection(event, "ed25519", source.ed25519_public_key_hex, _AUTH_TOKEN)


def authenticate_mtls(payload: dict, peer_certificate_der: bytes,
                      registry: dict[str, RegisteredDetectionSource], replay_guard: ReplayGuard, *,
                      now: datetime | None = None, max_age_seconds: float = 900.0) -> AuthenticatedDetection:
    """Accept a detection only from the client certificate registered for the
    source it names. The TLS layer must already have verified the chain."""
    now = now or datetime.now(timezone.utc)
    if not peer_certificate_der:
        raise ValueError("no client certificate presented")
    event, nonce = _event_from_payload(payload)
    source = _source_for(event, registry)
    if not source.client_cert_sha256:
        raise ValueError("source has no registered client certificate")
    fingerprint = hashlib.sha256(peer_certificate_der).hexdigest()
    if not hmac.compare_digest(fingerprint, source.client_cert_sha256):
        raise ValueError("client certificate is not the one registered for this source")
    _fresh(event, now, max_age_seconds)
    replay_guard.check_and_record(event, nonce, now)
    return AuthenticatedDetection(event, "mtls", fingerprint, _AUTH_TOKEN)


def sign_detection(event: DetectionEvent, nonce: str, private_key) -> dict:
    """Produce a signed envelope. Used by a forwarder holding the source's key."""
    return {"payload": json.loads(canonical_payload(event, nonce)),
            "signature": private_key.sign(canonical_payload(event, nonce)).hex()}


@dataclass(frozen=True)
class AdmissionResult:
    """Proof that a `DetectionEvent` passed `admit()`'s checks. This is the
    only object `to_reverification_subject_update()` accepts, and the only
    way to construct one is to call `admit()` successfully: a detection
    that was never admitted cannot reach the scheduler, by construction,
    not merely by convention."""

    evidence: Evidence
    asset: str
    confidence: float


def admit(authenticated: AuthenticatedDetection, registry: dict[str, RegisteredDetectionSource], *,
          now: datetime | None = None, max_age_seconds: float = 900.0) -> AdmissionResult:
    """Admit an authenticated detection from a registered, trusted, current
    and well-formed source. A bare `DetectionEvent`, which only names its
    source, is refused (`TypeError`). Anything else wrong is rejected
    outright (`ValueError`), never silently downgraded.

    The source is re-checked here, and the credential that authenticated
    the detection must still be the one registered: a key or certificate
    rotated out after authentication no longer admits anything.
    """
    if not isinstance(authenticated, AuthenticatedDetection):
        raise TypeError("only an authenticated detection can be admitted: a source name is not proof of origin")
    now = now or datetime.now(timezone.utc)
    detection = authenticated.event
    _fresh(detection, now, max_age_seconds)
    source = _source_for(detection, registry)
    registered = {"ed25519": source.ed25519_public_key_hex, "mtls": source.client_cert_sha256}.get(authenticated.method)
    if not registered or not hmac.compare_digest(registered, authenticated.credential_fingerprint):
        raise ValueError("the authenticating credential is no longer registered for this source")
    assertion = "active_detection:" + detection.technique
    evidence = Evidence(asset=detection.asset, assertion=assertion, observed_pass=True,
                        observed_at=detection.observed_at,
                        source=SOURCE_PREFIX + detection.source_id, independent=True)
    return AdmissionResult(evidence=evidence, asset=detection.asset, confidence=detection.confidence)


def to_reverification_subject_update(admitted: AdmissionResult, subject: Subject, *,
                                      now_seconds: int) -> Subject:
    """Reuse the existing re-verification scheduler, rather than building a
    second one: a current, admitted detection marks its subject changed
    (so every scheduling policy treats it as immediately due) and raises
    the subject's risk floor to at least the detection's confidence. This
    does not decide whether the underlying assertion is VERIFIED; that
    still only comes from `assessment.assess` over independent evidence,
    including whatever `admit()` above produced.

    `admitted` must be the `AdmissionResult` `admit()` returned, not a raw
    `DetectionEvent`: a detection that skipped admission is rejected
    outright here, the same fail-closed way every other unvetted input is
    rejected elsewhere in this pipeline.
    """
    if not isinstance(admitted, AdmissionResult):
        raise TypeError("a raw DetectionEvent cannot update the scheduler: it must first pass admit()")
    if subject.subject_id != admitted.asset:
        raise ValueError("subject does not match the detection's asset")
    raised_risk = max(subject.risk, admitted.confidence)
    return Subject(subject_id=subject.subject_id, last_verified_at=subject.last_verified_at,
                   risk=raised_risk, changed_at=now_seconds,
                   last_probe_cost=subject.last_probe_cost)
