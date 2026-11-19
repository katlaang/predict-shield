import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from predict_shield.assessment import Outcome
from predict_shield.change_execution import (
    AuditLog,
    ChangeSpec,
    RegisteredTarget,
    StaticHtmlSriAdapter,
    Verification,
    apply_change,
    pin_script_in_html,
    render_csp,
    render_nginx_csp_include,
    sign_approval,
)

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)
APPROVER = Ed25519PrivateKey.generate()
APPROVER_HEX = APPROVER.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
OLD = render_nginx_csp_include({"script-src": ["'self'", "127.0.0.3:9000"]})
NEW = render_nginx_csp_include({"default-src": ["'self'"], "script-src": ["'self'", "127.0.0.3:9000"],
                                "form-action": ["'self'"]})


class MemoryAdapter:
    def __init__(self, content=OLD, *, reject=False, fail_activation=False):
        self.content = content
        self.reject = reject
        self.fail_activation = fail_activation
        self.activations = 0

    def read(self):
        return self.content

    def validate(self, candidate):
        if self.reject:
            raise ValueError("validator said no")

    def write(self, content):
        self.content = content

    def activate(self):
        self.activations += 1
        if self.fail_activation and self.content == NEW:
            raise RuntimeError("reload failed")


def plan(action="restrict_all_fetch_targets", status="ELIGIBLE_LAB_PLAN", decision="ELIGIBLE_AUTOMATIC"):
    return {"case_id": "case-1", "selection_status": status, "selected_action": action if status == "ELIGIBLE_LAB_PLAN" else None,
            "policy_screened": {action: {"decision": decision, "reason": "r"}}}


def spec(action="restrict_all_fetch_targets", content=NEW):
    return ChangeSpec("chg-1", "case-1", "site-csp", action, content)


def target(env="lab", auto=True):
    return RegisteredTarget("site-csp", "nginx_csp_header", env, auto_apply_allowed=auto,
                            approver_keys={"ops-lead": APPROVER_HEX})


def verified():
    return Verification(Outcome.VERIFIED, "independent checks passed")


def failed():
    return Verification(Outcome.NOT_VERIFIED, "sink was reached")


class ChangeExecutionTests(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(Path(tempfile.mkdtemp()) / "audit.jsonl")

    def run_change(self, **kw):
        args = dict(plan=plan(), spec=spec(), target=target(), adapter=MemoryAdapter(),
                    verify=verified, audit_log=self.log, dry_run=False, now=NOW)
        args.update(kw)
        return apply_change(**args)

    def test_dry_run_is_the_default_and_changes_nothing(self):
        adapter = MemoryAdapter()
        record = apply_change(plan=plan(), spec=spec(), target=target(), adapter=adapter,
                              verify=verified, audit_log=self.log, now=NOW)
        self.assertEqual(record["status"], "DRY_RUN")
        self.assertIn("+add_header", record["diff"])
        self.assertEqual(adapter.content, OLD)

    def test_automatic_plan_on_an_auto_apply_lab_target_applies_and_verifies(self):
        adapter = MemoryAdapter()
        record = self.run_change(adapter=adapter)
        self.assertEqual(record["status"], "APPLIED_VERIFIED")
        self.assertEqual(record["authority"], "AUTOMATIC_POLICY")
        self.assertEqual(adapter.content, NEW)

    def test_failed_verification_rolls_back_to_the_exact_snapshot(self):
        adapter = MemoryAdapter()
        record = self.run_change(adapter=adapter, verify=failed)
        self.assertEqual(record["status"], "ROLLED_BACK")
        self.assertTrue(record["restored_to_snapshot"])
        self.assertEqual(adapter.content, OLD)
        self.assertEqual(adapter.activations, 2)

    def test_indeterminate_verification_also_rolls_back(self):
        record = self.run_change(verify=lambda: Verification(Outcome.INDETERMINATE, "canary not seen"))
        self.assertEqual(record["status"], "ROLLED_BACK")

    def test_validation_failure_never_writes(self):
        adapter = MemoryAdapter(reject=True)
        record = self.run_change(adapter=adapter)
        self.assertEqual(record["status"], "REJECTED_BY_VALIDATION")
        self.assertEqual((adapter.content, adapter.activations), (OLD, 0))

    def test_activation_failure_restores_the_snapshot(self):
        adapter = MemoryAdapter(fail_activation=True)
        record = self.run_change(adapter=adapter)
        self.assertEqual(record["status"], "ACTIVATION_FAILED_RESTORED")
        self.assertTrue(record["restored"])
        self.assertEqual(adapter.content, OLD)

    def test_a_plan_that_did_not_select_the_action_is_refused(self):
        record = self.run_change(plan=plan(action="block_vendor_script"))
        self.assertEqual(record["status"], "REFUSED")

    def test_automatic_plan_on_a_target_not_registered_for_auto_apply_needs_approval(self):
        record = self.run_change(target=target(auto=False))
        self.assertEqual(record["status"], "REFUSED")
        self.assertIn("signed approval", record["reason"])

    def test_production_can_never_be_registered_for_auto_apply(self):
        with self.assertRaises(ValueError):
            self.run_change(target=target(env="production", auto=True))

    def test_approval_tier_action_applies_with_a_valid_signed_approval_once(self):
        p = plan(action="block_vendor_script", status="ESCALATE_FOR_EVIDENCE", decision="PROPOSE_FOR_APPROVAL")
        s = spec(action="block_vendor_script")
        approval = sign_approval(s, "ops-lead", NOW + timedelta(minutes=30), APPROVER)
        record = self.run_change(plan=p, spec=s, target=target(env="production", auto=False), approval=approval)
        self.assertEqual(record["status"], "APPLIED_VERIFIED")
        self.assertEqual(record["authority"], "SIGNED_APPROVAL")
        again = self.run_change(plan=p, spec=s, target=target(env="production", auto=False), approval=approval)
        self.assertEqual(again["status"], "REFUSED")
        self.assertIn("already been used", again["reason"])

    def test_forged_expired_or_mismatched_approvals_are_refused(self):
        p = plan(action="block_vendor_script", status="ESCALATE_FOR_EVIDENCE", decision="PROPOSE_FOR_APPROVAL")
        s = spec(action="block_vendor_script")
        forged = sign_approval(s, "ops-lead", NOW + timedelta(minutes=30), Ed25519PrivateKey.generate())
        expired = sign_approval(s, "ops-lead", NOW - timedelta(seconds=1), APPROVER)
        other = sign_approval(spec(action="block_vendor_script", content=OLD), "ops-lead",
                              NOW + timedelta(minutes=30), APPROVER)
        unknown = sign_approval(s, "someone-else", NOW + timedelta(minutes=30), APPROVER)
        for approval, reason in ((forged, "does not verify"), (expired, "expired"),
                                 (other, "different change"), (unknown, "not registered")):
            record = self.run_change(plan=p, spec=s, target=target(auto=False), approval=approval)
            self.assertEqual(record["status"], "REFUSED", reason)
            self.assertIn(reason, record["reason"])

    def test_the_audit_log_detects_an_edited_record(self):
        self.run_change()
        self.assertTrue(self.log.verify_chain())
        lines = self.log.path.read_text().splitlines()
        record = json.loads(lines[-1])
        record["status"] = "ROLLED_BACK"
        lines[-1] = json.dumps(record, sort_keys=True)
        self.log.path.write_text("\n".join(lines) + "\n")
        self.assertFalse(self.log.verify_chain())


class RenderingTests(unittest.TestCase):
    def test_csp_rendering_refuses_injection(self):
        for bad in ({"script-src": ["'self'; report-uri https://evil"]},
                    {"script-src": ['x" always; return 302 https://evil; #']},
                    {"unknown-directive": ["'self'"]},
                    {"script-src": []}):
            with self.assertRaises(ValueError):
                render_csp(bad)

    def test_csp_rendering_is_deterministic(self):
        self.assertEqual(render_csp({"script-src": ["'self'"], "default-src": ["'none'"]}),
                         "default-src 'none'; script-src 'self'")

    def test_sri_pin_touches_only_the_registered_tag(self):
        url = "http://127.0.0.3:9000/widget.js"
        html = f'<html><script src="{url}"></script><script src="/own.js"></script></html>'
        sri = "sha384-" + "A" * 64
        pinned = pin_script_in_html(html, url, sri)
        self.assertIn(f'integrity="{sri}"', pinned)
        self.assertIn('<script src="/own.js">', pinned)
        page = Path(tempfile.mkdtemp()) / "page.html"
        page.write_text(html)
        adapter = StaticHtmlSriAdapter(page, url)
        adapter.validate(pinned)
        with self.assertRaises(ValueError):
            adapter.validate(pinned.replace("/own.js", "/evil.js"))


if __name__ == "__main__":
    unittest.main()
