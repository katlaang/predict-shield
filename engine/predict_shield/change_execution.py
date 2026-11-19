"""Apply a gated plan to a registered target, verify it independently, and
roll it back automatically if verification fails.

This is the step after "eligible plan". It takes a plan produced by the
existing pipeline (`pipeline.plan_script_integrity_case` and friends), a
concrete `ChangeSpec` derived from structured policy (never from model
text), a registered target and an adapter for that target, and runs:

    1. Authorization. The plan must have selected exactly this action. An
       automatic-tier plan may apply only to a target registered with
       `auto_apply_allowed=True`. Everything else, and every target in a
       production environment, needs an Ed25519-signed approval from an
       approver registered for that target, bound to this exact change
       digest, unexpired and unused.
    2. Dry run by default. `dry_run=True` returns the diff and changes
       nothing.
    3. Snapshot, validate, write atomically, activate. If validation or
       activation fails, the snapshot is restored and re-activated.
    4. Independent verification, supplied by the caller and run after
       activation. Only Outcome.VERIFIED keeps the change.
    5. Anything else rolls the change back, re-activates the snapshot and
       checks that the target's content is byte-identical to the snapshot.
    6. Every step is appended to a hash-chained audit log.

The adapters bundled here are a header-include file for nginx (CSP) and a
static HTML page (SRI pin). Both generate the target content themselves
from a structured policy, so a model or a detection cannot inject
directives or markup.
"""
from __future__ import annotations

import difflib
import hashlib
import hmac
import json
import os
import re
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Protocol

from .assessment import Outcome

ENVIRONMENTS = ("lab", "staging", "production")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


# ---------------------------------------------------------------- registry


@dataclass(frozen=True)
class RegisteredTarget:
    target_id: str
    kind: str
    environment: str
    auto_apply_allowed: bool = False
    # approver_id -> Ed25519 public key, raw 32 bytes as hex
    approver_keys: dict = field(default_factory=dict)

    def validate(self) -> None:
        if not self.target_id or not self.kind:
            raise ValueError("target_id and kind required")
        if self.environment not in ENVIRONMENTS:
            raise ValueError("environment must be one of " + ", ".join(ENVIRONMENTS))
        if self.environment == "production" and self.auto_apply_allowed:
            raise ValueError("a production target can never be registered for automatic apply")
        for approver, key in self.approver_keys.items():
            if not approver or not re.fullmatch(r"[0-9a-f]{64}", key or ""):
                raise ValueError("approver keys must be 32 bytes of hex")


@dataclass(frozen=True)
class ChangeSpec:
    change_id: str
    case_id: str
    target_id: str
    action_id: str
    new_content: str

    def digest(self) -> str:
        return _sha256(_canonical({
            "change_id": self.change_id, "case_id": self.case_id, "target_id": self.target_id,
            "action_id": self.action_id, "content_sha256": _sha256(self.new_content.encode("utf-8")),
        }))


# ---------------------------------------------------------------- approvals


def approval_message(change_digest: str, approver_id: str, expires_at: datetime) -> bytes:
    return _canonical({"change_digest": change_digest, "approver_id": approver_id,
                       "expires_at": expires_at.astimezone(timezone.utc).isoformat()})


def sign_approval(spec: ChangeSpec, approver_id: str, expires_at: datetime, private_key) -> dict:
    digest = spec.digest()
    return {"change_digest": digest, "approver_id": approver_id,
            "expires_at": expires_at.astimezone(timezone.utc).isoformat(),
            "signature": private_key.sign(approval_message(digest, approver_id, expires_at)).hex()}


def verify_approval(approval: dict, spec: ChangeSpec, target: RegisteredTarget, now: datetime) -> str:
    """Return the approver_id, or raise ValueError."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if not isinstance(approval, dict) or set(approval) != {"change_digest", "approver_id", "expires_at", "signature"}:
        raise ValueError("approval must contain exactly change_digest, approver_id, expires_at and signature")
    approver = approval["approver_id"]
    key_hex = target.approver_keys.get(approver)
    if not key_hex:
        raise ValueError("approver is not registered for this target")
    if not hmac.compare_digest(str(approval["change_digest"]), spec.digest()):
        raise ValueError("approval is for a different change")
    expires = datetime.fromisoformat(approval["expires_at"])
    if expires.tzinfo is None or expires <= now:
        raise ValueError("approval has expired")
    signature = approval["signature"]
    if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-f]{128}", signature):
        raise ValueError("approval signature must be 64 bytes of hex")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex)).verify(
            bytes.fromhex(signature), approval_message(spec.digest(), approver, expires))
    except InvalidSignature:
        raise ValueError("approval signature does not verify against the registered approver key") from None
    return approver


# ---------------------------------------------------------------- audit log


class AuditLog:
    """Append-only JSON lines, each record carrying the hash of the previous
    one. `verify_chain()` detects a removed, reordered or edited record."""

    GENESIS = "0" * 64

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def records(self) -> list[dict]:
        return [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def append(self, record: dict) -> dict:
        with self._lock:
            existing = self.records()
            previous = existing[-1]["record_sha256"] if existing else self.GENESIS
            body = dict(record, sequence=len(existing), previous_sha256=previous,
                        recorded_at=datetime.now(timezone.utc).isoformat())
            body["record_sha256"] = _sha256(_canonical(body))
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(body, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            return body

    def verify_chain(self) -> bool:
        previous = self.GENESIS
        for index, record in enumerate(self.records()):
            claimed = record.get("record_sha256")
            body = {k: v for k, v in record.items() if k != "record_sha256"}
            if (record.get("sequence") != index or record.get("previous_sha256") != previous
                    or _sha256(_canonical(body)) != claimed):
                return False
            previous = claimed
        return True

    def approval_used(self, change_digest: str, approver_id: str) -> bool:
        return any(r.get("approval_used") == [change_digest, approver_id] for r in self.records())


# ---------------------------------------------------------------- adapters


class TargetAdapter(Protocol):
    def read(self) -> str: ...
    def validate(self, candidate: str) -> None: ...
    def write(self, content: str) -> None: ...
    def activate(self) -> None: ...


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix="." + path.name + ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


_CSP_DIRECTIVES = {
    "default-src", "script-src", "connect-src", "img-src", "style-src", "font-src",
    "frame-src", "child-src", "form-action", "base-uri", "object-src", "frame-ancestors",
    "worker-src", "media-src", "manifest-src", "sandbox",
}
_CSP_SOURCE = re.compile(r"^('self'|'none'|'strict-dynamic'|'unsafe-inline'|"
                         r"[a-z][a-z0-9+.-]*:|[A-Za-z0-9.*-]+(:[0-9]{1,5})?|"
                         r"https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?|"
                         r"allow-scripts|allow-forms|allow-same-origin|allow-popups)$")


def render_csp(policy: dict) -> str:
    """Render a structured CSP {directive: [sources]} to a header value,
    refusing anything outside a small known grammar."""
    if not isinstance(policy, dict) or not policy:
        raise ValueError("CSP policy must be a non-empty mapping")
    parts = []
    for directive in sorted(policy):
        sources = policy[directive]
        if directive not in _CSP_DIRECTIVES:
            raise ValueError("unsupported CSP directive " + repr(directive))
        if not isinstance(sources, (list, tuple)) or not sources:
            raise ValueError("each CSP directive needs at least one source")
        for source in sources:
            if not isinstance(source, str) or not _CSP_SOURCE.match(source):
                raise ValueError("unsupported CSP source " + repr(source))
        parts.append(directive + " " + " ".join(sources))
    return "; ".join(parts)


def render_nginx_csp_include(policy: dict) -> str:
    return ("# Managed by PREDICT-SHIELD change_execution. Do not edit by hand.\n"
            'add_header Content-Security-Policy "' + render_csp(policy) + '" always;\n')


class NginxCspIncludeAdapter:
    """Manages one include file that nginx loads inside a server block.

    Validation runs `nginx -t` against the real configuration with the
    candidate in place. nginx only reads configuration on reload, so the
    running server is unaffected until `activate()`; a failed test restores
    the previous file before returning."""

    def __init__(self, include_path: Path, nginx_cmd: list[str]):
        self.include_path = Path(include_path)
        self.nginx_cmd = list(nginx_cmd)

    def read(self) -> str:
        return self.include_path.read_text(encoding="utf-8") if self.include_path.exists() else ""

    def validate(self, candidate: str) -> None:
        lines = [l for l in candidate.splitlines() if l.strip() and not l.lstrip().startswith("#")]
        if len(lines) != 1 or not re.fullmatch(r'add_header Content-Security-Policy "[^"\n;{}$\\]*(; [^"\n;{}$\\]*)*" always;', lines[0]):
            raise ValueError("include must contain exactly one generated CSP add_header line")
        previous = self.read()
        _atomic_write(self.include_path, candidate)
        result = subprocess.run(self.nginx_cmd + ["-t"], capture_output=True, text=True)
        if result.returncode != 0:
            _atomic_write(self.include_path, previous)
            raise ValueError("nginx -t rejected the candidate: " + result.stderr.strip()[-300:])
        _atomic_write(self.include_path, previous)

    def write(self, content: str) -> None:
        _atomic_write(self.include_path, content)

    def activate(self) -> None:
        result = subprocess.run(self.nginx_cmd + ["-s", "reload"], capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError("nginx reload failed: " + result.stderr.strip()[-300:])


def pin_script_in_html(html: str, script_url: str, sri: str) -> str:
    """Add or replace integrity/crossorigin on exactly one <script src=script_url> tag."""
    pattern = re.compile(r'<script\s+src="' + re.escape(script_url) + r'"[^>]*>', re.IGNORECASE)
    matches = pattern.findall(html)
    if len(matches) != 1:
        raise ValueError("the page must contain exactly one tag for the registered script")
    if not re.fullmatch(r"sha384-[A-Za-z0-9+/]{64}", sri):
        raise ValueError("SRI value must be a sha384 digest")
    return pattern.sub('<script src="' + script_url + '" integrity="' + sri + '" crossorigin="anonymous">', html)


class StaticHtmlSriAdapter:
    """Pins the registered script on a static page. Validation requires that
    the only difference from the current page is that one script tag."""

    def __init__(self, page_path: Path, script_url: str, after_write: Callable[[], None] | None = None):
        self.page_path = Path(page_path)
        self.script_url = script_url
        self.after_write = after_write

    def read(self) -> str:
        return self.page_path.read_text(encoding="utf-8")

    def validate(self, candidate: str) -> None:
        tag = re.compile(r'<script\s+src="' + re.escape(self.script_url) + r'"[^>]*>', re.IGNORECASE)
        if tag.sub("<SCRIPT>", candidate) != tag.sub("<SCRIPT>", self.read()):
            raise ValueError("candidate changes more than the registered script tag")
        if len(tag.findall(candidate)) != 1 or 'integrity="sha384-' not in tag.findall(candidate)[0]:
            raise ValueError("candidate does not pin the registered script")

    def write(self, content: str) -> None:
        _atomic_write(self.page_path, content)

    def activate(self) -> None:
        if self.after_write:
            self.after_write()


class RegisteredRenderingsAdapter:
    """A page that may only ever hold one of a fixed set of renderings the
    operator registered ahead of time (for example: the direct script tag,
    the SRI-pinned tag, the sandboxed-frame layout). A candidate that is
    not byte-identical to a registered rendering is refused, so no
    generated or detection-supplied markup can reach the page."""

    def __init__(self, page_path: Path, renderings: dict[str, str],
                 after_write: Callable[[], None] | None = None):
        if not renderings:
            raise ValueError("at least one registered rendering is required")
        self.page_path = Path(page_path)
        self.renderings = dict(renderings)
        self.after_write = after_write

    def rendering(self, name: str) -> str:
        return self.renderings[name]

    def current_rendering(self) -> str | None:
        current = self.read()
        return next((name for name, body in self.renderings.items() if body == current), None)

    def read(self) -> str:
        return self.page_path.read_text(encoding="utf-8")

    def validate(self, candidate: str) -> None:
        if candidate not in self.renderings.values():
            raise ValueError("candidate is not one of the registered renderings for this page")

    def write(self, content: str) -> None:
        _atomic_write(self.page_path, content)

    def activate(self) -> None:
        if self.after_write:
            self.after_write()


# ---------------------------------------------------------------- apply


@dataclass(frozen=True)
class Verification:
    outcome: Outcome
    reason: str
    detail: dict = field(default_factory=dict)


def _authorize(plan: dict, spec: ChangeSpec, target: RegisteredTarget, approval: dict | None,
               log: AuditLog, now: datetime) -> tuple[str, str | None]:
    if plan.get("case_id") != spec.case_id:
        raise PermissionError("plan and change are for different cases")
    screened = (plan.get("policy_screened") or {}).get(spec.action_id, {})
    automatic = plan.get("selection_status") == "ELIGIBLE_LAB_PLAN" and plan.get("selected_action") == spec.action_id
    approval_tier = screened.get("decision") == "PROPOSE_FOR_APPROVAL"
    if not automatic and not approval_tier:
        raise PermissionError("the plan did not select or propose this action")
    if automatic and target.auto_apply_allowed and approval is None:
        return "AUTOMATIC_POLICY", None
    if approval is None:
        raise PermissionError("this change needs a signed approval")
    approver = verify_approval(approval, spec, target, now)
    if log.approval_used(spec.digest(), approver):
        raise PermissionError("approval has already been used")
    return "SIGNED_APPROVAL", approver


def apply_change(*, plan: dict, spec: ChangeSpec, target: RegisteredTarget, adapter: TargetAdapter,
                 verify: Callable[[], Verification], audit_log: AuditLog,
                 approval: dict | None = None, dry_run: bool = True,
                 now: datetime | None = None) -> dict:
    """Run one gated change to completion. Returns the final record."""
    now = now or datetime.now(timezone.utc)
    target.validate()
    if spec.target_id != target.target_id:
        raise ValueError("change is for a different target")
    base = {"change_id": spec.change_id, "case_id": spec.case_id, "target_id": spec.target_id,
            "environment": target.environment, "action_id": spec.action_id,
            "change_digest": spec.digest()}
    try:
        authority, approver = _authorize(plan, spec, target, approval, audit_log, now)
    except (PermissionError, ValueError) as exc:
        return audit_log.append(dict(base, status="REFUSED", reason=str(exc)))
    base["authority"] = authority
    current = adapter.read()
    diff = "".join(difflib.unified_diff(current.splitlines(True), spec.new_content.splitlines(True),
                                        "current", "proposed"))
    if dry_run:
        return audit_log.append(dict(base, status="DRY_RUN", diff=diff))
    if approver:
        audit_log.append(dict(base, status="APPROVAL_CONSUMED", approval_used=[spec.digest(), approver]))
    snapshot = current
    snapshot_sha = _sha256(snapshot.encode("utf-8"))
    base["snapshot_sha256"] = snapshot_sha
    if current == spec.new_content:
        audit_log.append(dict(base, status="ALREADY_IN_PLACE"))
    else:
        try:
            adapter.validate(spec.new_content)
        except ValueError as exc:
            return audit_log.append(dict(base, status="REJECTED_BY_VALIDATION", reason=str(exc)))
        try:
            adapter.write(spec.new_content)
            adapter.activate()
        except Exception as exc:  # restore, then report
            adapter.write(snapshot)
            adapter.activate()
            return audit_log.append(dict(base, status="ACTIVATION_FAILED_RESTORED", reason=str(exc),
                                         restored=_sha256(adapter.read().encode()) == snapshot_sha))
        audit_log.append(dict(base, status="APPLIED_PENDING_VERIFICATION", diff=diff))
    verification = verify()
    if verification.outcome is Outcome.VERIFIED:
        return audit_log.append(dict(base, status="APPLIED_VERIFIED", verification=verification.outcome.value,
                                     verification_reason=verification.reason, verification_detail=verification.detail))
    adapter.write(snapshot)
    adapter.activate()
    restored = _sha256(adapter.read().encode("utf-8")) == snapshot_sha
    return audit_log.append(dict(base, status="ROLLED_BACK" if restored else "ROLLBACK_FAILED",
                                 verification=verification.outcome.value,
                                 verification_reason=verification.reason,
                                 verification_detail=verification.detail,
                                 restored_to_snapshot=restored))
