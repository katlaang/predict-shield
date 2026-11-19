"""End-to-end chain in a disposable lab: detect, plan, apply, verify, and
keep or roll back, with no human step except a signed approval where the
policy requires one.

Real components: nginx serving the operator's page on loopback, a vendor
server, a sink standing in for an attacker destination, headless
Chromium as the page visitor and as the verifier's browser, and the
existing engine modules for every decision:

    monitor      verification_cycle.select_probes / record_probe, real fetches
    detect       script_integrity hash check over the real fetched bytes
    plan         pipeline.plan_script_integrity_case: AI containment proposal,
                 then the deterministic policy gate
    apply        change_execution.apply_change: authorization, dry run first,
                 nginx -t, atomic write, reload
    verify       an HTTP client independent of the executor confirms the
                 change is live; Chromium with the compromised script still
                 being served, plus the sink's own log, must both show no
                 page data leaving (two independent sources)
    keep / undo  anything short of VERIFIED rolls back automatically, and
                 the served state is then checked against the snapshot

Each incident starts from the same baseline and uses one exfiltration
channel. The proposer is either a real model (`--model ollama:<name>`) or
`FixedChoiceModel`, which always returns one named action so that each
path through the chain (keep, roll back, approval) is exercised
deterministically. The report says which was used for every incident.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT / "experiment-b" / "real-script-integrity-pilot"))
sys.path.insert(0, str(HERE))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
from playwright.sync_api import sync_playwright  # noqa: E402

import lab_servers  # noqa: E402
import nginx_lab  # noqa: E402
from run_real_script_integrity_pilot import _hosts, _load  # noqa: E402
from predict_shield.ai_contracts import ActionPrediction, ActionTier, CandidateAction, EvidenceSnapshot, Interval  # noqa: E402
from predict_shield.assessment import Outcome, assess  # noqa: E402
from predict_shield.change_execution import (  # noqa: E402
    AuditLog, ChangeSpec, NginxCspIncludeAdapter, RegisteredRenderingsAdapter, RegisteredTarget,
    Verification, apply_change, render_csp, render_nginx_csp_include, sign_approval,
)
from predict_shield.detection_intake import (  # noqa: E402
    RegisteredDetectionSource, to_reverification_subject_update,
)
from predict_shield.intake_server import DetectionIntakeServer  # noqa: E402
from predict_shield.language_model import OllamaModel  # noqa: E402
from predict_shield.live_feed import LiveFeedServer, LiveState  # noqa: E402
from predict_shield.pipeline import plan_script_integrity_case  # noqa: E402
from predict_shield.script_integrity import (  # noqa: E402
    HASH_MATCHES_TRUSTED, NO_PROHIBITED_NETWORK_BEHAVIOR, BrowserBehaviorCapture, RegisteredScript,
    RegisteredSite, confirm_controlled_sink_log, confirm_hash_matches_trusted,
    confirm_no_prohibited_network_behavior, fetch_page, fetch_response_headers, fetch_script_observation,
    sri_value,
)
from predict_shield.script_risk_proposer import ModelScriptRiskProposer  # noqa: E402
from predict_shield.verification_cycle import TrackedControl, record_probe, select_probes  # noqa: E402

SCHEMA = "predict-shield/end-to-end-chain/1"
SERVICE = "lab-checkout-page"

# The catalog the operator registers. Tier is a property of the action.
ACTIONS = (
    CandidateAction("restrict_all_fetch_targets", ActionTier.AUTOMATIC, (SERVICE,),
                    "page CSP allows no fetch, image or form destination but self", reversible=True),
    CandidateAction("isolate_in_sandboxed_frame", ActionTier.AUTOMATIC, (SERVICE,),
                    "vendor script runs only in a sandboxed frame", reversible=True),
    CandidateAction("sri_pin", ActionTier.AUTOMATIC, (SERVICE,),
                    "vendor script pinned to its trusted hash", reversible=True),
    CandidateAction("block_vendor_script", ActionTier.APPROVAL, (SERVICE,),
                    "vendor script not allowed to load", reversible=True),
)
PERMITTED = {
    "hash_mismatch": tuple(a.action_id for a in ACTIONS),
    "unregistered_domain": ("restrict_all_fetch_targets", "block_vendor_script"),
}
# Per-action outcome estimates registered from the measured containment
# matrix (real-script-integrity-pilot schema /4, six channels): residual
# risk is the share of channels the action did not contain, and the
# disruption estimate is whether the widget stopped working.
MEASURED_PRIOR = {
    "restrict_all_fetch_targets": (3 / 6, 0.0),
    "isolate_in_sandboxed_frame": (0.0, 0.0),
    "sri_pin": (0.0, 1.0),
    "block_vendor_script": (0.0, 1.0),
}
PRIOR_FINGERPRINT = hashlib.sha256(json.dumps(MEASURED_PRIOR, sort_keys=True).encode()).hexdigest()


class FixedChoiceModel:
    """Deterministic stand-in for the model: always picks one named action.
    Used to drive each path of the chain on purpose. Not model output."""

    def __init__(self, action_id: str):
        self.action_id = action_id
        self.name = "fixed-choice:" + action_id

    def complete(self, system: str, prompt: str) -> str:
        return json.dumps({"severity": "high", "action": self.action_id,
                           "rationale": "fixed choice for a deterministic chain test"})


def predictions_for(snapshot: EvidenceSnapshot, now: datetime) -> tuple[ActionPrediction, ...]:
    out = []
    for action_id, (risk, errors) in MEASURED_PRIOR.items():
        out.append(ActionPrediction(
            action_id=action_id, snapshot_id=snapshot.snapshot_id,
            model_name="measured-containment-prior", model_version="pilot-schema-4",
            predicted_at=now, residual_risk=Interval(risk, risk, risk),
            additional_errors={SERVICE: Interval(errors, errors, errors)},
            calibration_supported=True, training_fingerprint=PRIOR_FINGERPRINT))
    return tuple(out)


class Lab:
    def __init__(self, workdir: Path):
        self.state = lab_servers.VendorState()
        self.sink = lab_servers.SinkState()
        self.vendor_server = lab_servers.start_server("127.0.0.3", lab_servers.make_vendor_handler(self.state))
        self.sink_server = lab_servers.start_server("127.0.0.2", lab_servers.make_sink_handler(self.sink))
        self.state.vendor_origin = "http://%s:%d" % self.vendor_server.server_address
        self.state.sink_origin = "http://%s:%d" % self.sink_server.server_address
        self.vendor_host = self.vendor_server.server_address[0]
        self.vendor_source = self.state.vendor_origin.split("://", 1)[1]
        self.script_url = self.state.vendor_origin + "/widget.js"
        self.nginx = nginx_lab.NginxLab(workdir / "nginx", self.state.vendor_origin)
        self.baseline_policy = {"script-src": ["'self'", self.vendor_source]}
        self.renderings = {
            "direct": nginx_lab.direct_page(self.script_url),
            "sri_pinned": nginx_lab.pinned_page(self.script_url, sri_value(hashlib.sha384(lab_servers.GOOD_SCRIPT).hexdigest())),
            "isolated": nginx_lab.isolated_page(),
        }
        self.nginx.provision(render_nginx_csp_include(self.baseline_policy), self.renderings["direct"])
        self.nginx.start()
        self.page_url = self.nginx.origin + "/page.html"
        self.allowed_hosts = ("127.0.0.1", self.vendor_host)
        self.script = RegisteredScript(script_id="lab-vendor-widget", url=self.script_url,
                                       trusted_sha384=(hashlib.sha384(lab_servers.GOOD_SCRIPT).hexdigest(),))
        self.site = RegisteredSite(site_id=SERVICE, allowed_script_domains=("127.0.0.1", self.vendor_host),
                                   prohibited_sinks=(self.sink_server.server_address[0],))
        self.csp_adapter = NginxCspIncludeAdapter(self.nginx.csp_include, self.nginx.cmd)
        self.page_adapter = RegisteredRenderingsAdapter(self.nginx.page, self.renderings)

    def reset(self) -> None:
        """Return to the registered baseline between incidents (lab only)."""
        self.state.script_body = lab_servers.GOOD_SCRIPT
        self.csp_adapter.write(render_nginx_csp_include(self.baseline_policy))
        self.csp_adapter.activate()
        self.page_adapter.write(self.renderings["direct"])
        self.wait_served(csp=render_csp(self.baseline_policy), body=self.renderings["direct"])

    def served(self) -> tuple[str | None, str]:
        headers, body = fetch_page(self.page_url, self.allowed_hosts, allow_private_addresses=True)
        return headers.get("content-security-policy"), body

    def wait_served(self, *, csp: str | None = None, body: str | None = None, timeout: float = 8.0,
                    stable_reads: int = 6) -> bool:
        """True once `stable_reads` consecutive independent fetches all match.
        After an nginx reload, workers of the previous generation can still
        answer for a short while, so one matching read is not proof."""
        deadline = time.monotonic() + timeout
        streak = 0
        while time.monotonic() < deadline:
            served_csp, served_body = self.served()
            if (csp is None or served_csp == csp) and (body is None or served_body == body):
                streak += 1
                if streak >= stable_reads:
                    return True
            else:
                streak = 0
            time.sleep(0.1)
        return False

    def sink_hits(self) -> int:
        with self.sink.lock:
            return len(self.sink.hits)

    def stop(self) -> None:
        self.nginx.stop()
        self.vendor_server.shutdown()
        self.sink_server.shutdown()


def change_for(lab: Lab, action_id: str, case_id: str) -> tuple[ChangeSpec, object, dict]:
    """Map a registered action to a concrete change. Content comes only from
    structured policy or registered renderings."""
    v = lab.vendor_source
    if action_id == "restrict_all_fetch_targets":
        policy = {"default-src": ["'self'"], "script-src": ["'self'", v], "form-action": ["'self'"]}
        content, adapter, expected = render_nginx_csp_include(policy), lab.csp_adapter, {"csp": render_csp(policy)}
        target = "site-csp"
    elif action_id == "block_vendor_script":
        policy = {"script-src": ["'self'"]}
        content, adapter, expected = render_nginx_csp_include(policy), lab.csp_adapter, {"csp": render_csp(policy)}
        target = "site-csp"
    elif action_id == "sri_pin":
        content, adapter, expected = lab.renderings["sri_pinned"], lab.page_adapter, {"body": lab.renderings["sri_pinned"]}
        target = "site-page"
    elif action_id == "isolate_in_sandboxed_frame":
        content, adapter, expected = lab.renderings["isolated"], lab.page_adapter, {"body": lab.renderings["isolated"]}
        target = "site-page"
    else:
        raise ValueError("no change mapping for " + action_id)
    return ChangeSpec(f"{case_id}:{action_id}", case_id, target, action_id, content), adapter, expected


def make_verifier(lab: Lab, playwright, expected: dict):
    """Independent of the executor: its own HTTP client for the live state,
    a fresh Chromium for behavior, and the sink's own log."""

    def verify() -> Verification:
        live = lab.wait_served(**expected)
        served_csp, served_body = lab.served()
        if not live:
            return Verification(Outcome.INDETERMINATE, "change not observed live by an independent HTTP client",
                                {"served_csp": served_csp})
        now = datetime.now(timezone.utc)
        observation = fetch_script_observation(lab.script, lab.allowed_hosts, now=now, allow_private_addresses=True)
        compromise_live = observation.sha384 not in lab.script.trusted_sha384
        before = lab.sink_hits()
        trial = _load(playwright, lab.page_url, lab.script_url)
        hits = lab.sink_hits() - before
        capture = BrowserBehaviorCapture(sent_hosts=tuple(_hosts(trial.sent_hosts)),
                                         blocked_hosts=tuple(_hosts(trial.blocked_hosts)),
                                         canary_observed=trial.canary_observed,
                                         exposure_exercised=compromise_live and trial.vendor_script_requested)
        browser_ev = confirm_no_prohibited_network_behavior(lab.site, capture, now, now=now)
        sink_ev = confirm_controlled_sink_log(lab.site, hits, now, now=now)
        verdict = assess(lab.site.site_id, NO_PROHIBITED_NETWORK_BEHAVIOR, [browser_ev, sink_ev],
                         required_independent_checks=2, now=now)
        return Verification(verdict.outcome, verdict.reason, {
            "served_csp": served_csp, "compromised_script_still_served": compromise_live,
            "sink_hits": hits, "sent_hosts": list(capture.sent_hosts), "canary_observed": trial.canary_observed,
            "widget_working": trial.button_enabled is True,
            "page_navigated_away": trial.button_enabled is None,
        })

    return verify


def monitor_until_detected(lab: Lab, malicious: bytes, *, interval: int, seed: int,
                           policy: str = "fixed", admitted: list | None = None,
                           visit=None, subject_id: str | None = None) -> dict:
    """The re-verification scheduler over real fetches. The vendor turns
    malicious at a random moment; returns when a probe records NOT VERIFIED.

    With `admitted` (a list the intake server appends authenticated
    detections to), each new detection for this subject marks it changed,
    which the 'adaptive' and 'change' policies treat as due at once. With
    `visit`, a real browser visits the page on every loop, the way users
    do, so an IDS can see the page's traffic."""
    rng = random.Random(seed)
    start = int(time.time())
    subject = subject_id or lab.script.script_id
    control = TrackedControl(subject_id=subject, asset=lab.script.script_id,
                             assertion=HASH_MATCHES_TRUSTED, last_verified_at=start, risk=0.3)
    if policy == "fixed":
        control = TrackedControl(subject_id=subject, asset=lab.script.script_id, assertion=HASH_MATCHES_TRUSTED,
                                 last_verified_at=start - interval, risk=0.3)
    tamper_at = time.monotonic() + rng.uniform(0.5, 1.5 * min(interval, 4))
    tampered_at = None
    consumed = 0
    triggers = []
    deadline = time.monotonic() + max(10 * min(interval, 6), 30) + 10
    while time.monotonic() < deadline:
        if tampered_at is None and time.monotonic() >= tamper_at:
            lab.state.script_body = malicious
            tampered_at = time.monotonic()
        if visit is not None:
            visit()
        if admitted is not None:
            while consumed < len(admitted):
                item = admitted[consumed]
                consumed += 1
                if item.asset == control.subject_id:
                    updated = to_reverification_subject_update(item, control.subject(), now_seconds=int(time.time()))
                    control = TrackedControl(subject_id=control.subject_id, asset=control.asset,
                                             assertion=control.assertion, last_verified_at=control.last_verified_at,
                                             risk=updated.risk, changed_at=updated.changed_at)
                    triggers.append({"source": item.evidence.source,
                                     "seconds_after_tamper": None if tampered_at is None
                                     else round(time.monotonic() - tampered_at, 3)})
        now = int(time.time())
        requests = select_probes([control], now=now, budget=1, policy=policy, interval=interval)
        if requests:
            observed = datetime.fromtimestamp(now, tz=timezone.utc)
            obs = fetch_script_observation(lab.script, lab.allowed_hosts, now=observed, allow_private_addresses=True)
            control, record = record_probe(control, requests[0], [confirm_hash_matches_trusted(lab.script, obs, now=observed)],
                                           observed_at=now, requested_at=now)
            if record.outcome is Outcome.NOT_VERIFIED:
                if tampered_at is None:
                    raise RuntimeError("clean script reported NOT VERIFIED")
                return {"detected": True, "seconds_from_tamper_to_detection": round(time.monotonic() - tampered_at, 3),
                        "scheduler_policy": policy, "interval_seconds": interval,
                        "probe_due_to": requests[0].due_to,
                        "detection_triggers": triggers, "observation": obs}
        time.sleep(0.05)
    return {"detected": False, "scheduler_policy": policy, "interval_seconds": interval, "detection_triggers": triggers}


def run_incident(lab: Lab, playwright, log: AuditLog, *, case_id: str, channel: str, model,
                 targets: dict[str, RegisteredTarget], live: LiveState, approver=None, interval: int = 2,
                 seed: int = 1, policy: str = "fixed", admitted: list | None = None,
                 visit_page: bool = False, subject_id: str | None = None,
                 detection_notes: tuple[str, ...] = ()) -> dict:
    lab.reset()
    incident = {"case_id": case_id, "channel": channel, "proposer_model": model.name,
                "proposer_is_real_model": not isinstance(model, FixedChoiceModel)}
    live.incident(case_id, stage="monitoring", channel=channel)
    visit = (lambda: _load(playwright, lab.page_url, lab.script_url)) if visit_page else None
    detection = monitor_until_detected(lab, lab_servers.malicious_script(lab.state.sink_origin, channel),
                                       interval=interval, seed=seed, policy=policy, admitted=admitted,
                                       visit=visit, subject_id=subject_id)
    incident["detection"] = {k: v for k, v in detection.items() if k != "observation"}
    if not detection["detected"]:
        incident["final_status"] = "NOT_DETECTED"
        live.incident(case_id, stage="done", final_status="NOT_DETECTED")
        return incident
    live.incident(case_id, stage="detected",
                  seconds_from_tamper_to_detection=detection["seconds_from_tamper_to_detection"])
    now = datetime.now(timezone.utc)
    page_load = _load(playwright, lab.page_url, lab.script_url)
    snapshot = EvidenceSnapshot(snapshot_id=f"lab-scope:{case_id}", case_id=case_id, captured_at=now,
                                source_ids=("script-integrity:" + lab.script.script_id,),
                                trusted=True, scope_complete=True)
    plan = plan_script_integrity_case(
        case_id=case_id, script=lab.script, site=lab.site, observation=detection["observation"],
        observed_domains=tuple(_hosts(page_load.requested_hosts)), observed_at=now,
        proposer=ModelScriptRiskProposer(model), permitted_actions_by_reason=PERMITTED, actions=ACTIONS,
        predictions=predictions_for(snapshot, now), scope_snapshot=snapshot,
        remaining_error_budgets={SERVICE: 5.0}, asset_criticality="high",
        detection_notes=detection_notes, now=now)
    incident["plan"] = {k: plan[k] for k in ("finding_reason", "ai_proposal_status", "ai_severity_advisory",
                                             "ai_proposal_rationale", "selection_status", "selected_action",
                                             "policy_screened", "reason", "dispatch_authorized")}
    action = plan.get("selected_action") or next(
        (a for a, r in plan["policy_screened"].items() if r["decision"] == "PROPOSE_FOR_APPROVAL"), None)
    live.incident(case_id, stage="planned", proposed_action=action, plan_status=plan["selection_status"])
    if action is None:
        incident["final_status"] = "PLAN_ESCALATED"
        live.incident(case_id, stage="done", final_status="PLAN_ESCALATED")
        return incident
    spec, adapter, expected = change_for(lab, action, case_id)
    target = targets[spec.target_id]
    verify = make_verifier(lab, playwright, expected)
    baseline = lab.served()
    dry = apply_change(plan=plan, spec=spec, target=target, adapter=adapter, verify=verify, audit_log=log)
    incident["dry_run"] = {"status": dry["status"], "served_unchanged": lab.served() == baseline}
    steps = []
    live.incident(case_id, stage="applying")
    if dry["status"] == "REFUSED" and approver is not None:
        steps.append({"without_approval": dry["status"], "reason": dry["reason"]})
        approval = sign_approval(spec, approver[0], datetime.now(timezone.utc) + timedelta(minutes=10), approver[1])
        record = apply_change(plan=plan, spec=spec, target=target, adapter=adapter, verify=verify,
                              audit_log=log, approval=approval, dry_run=False)
    elif dry["status"] == "REFUSED":
        incident["final_status"] = "REFUSED"
        incident["refusal_reason"] = dry["reason"]
        live.incident(case_id, stage="done", final_status="REFUSED")
        return incident
    else:
        record = apply_change(plan=plan, spec=spec, target=target, adapter=adapter, verify=verify,
                              audit_log=log, dry_run=False)
    incident["approval_steps"] = steps
    incident["applied_action"] = action
    incident["authority"] = record.get("authority")
    incident["final_status"] = record["status"]
    incident["verification"] = record.get("verification")
    incident["verification_detail"] = record.get("verification_detail")
    # nginx reloads asynchronously: wait for the state the outcome implies,
    # then read it with an independent client. A state that never converges
    # is reported as such, not assumed.
    if record["status"] == "APPLIED_VERIFIED":
        converged = lab.wait_served(**expected)
    else:
        converged = lab.wait_served(csp=baseline[0], body=baseline[1])
    served_csp, served_body = lab.served()
    incident["served_state_converged"] = converged
    incident["served_after"] = {
        "csp": served_csp,
        "page_rendering": next((n for n, b in lab.renderings.items() if b == served_body), "unregistered"),
        "matches_change": (served_csp == expected.get("csp")) if "csp" in expected else served_body == expected.get("body"),
        "matches_baseline": (served_csp, served_body) == baseline,
    }
    detail = incident.get("verification_detail") or {}
    live.incident(case_id, stage="done", applied_action=action, authority=incident["authority"],
                  verification=incident["verification"], final_status=incident["final_status"],
                  widget_working=detail.get("widget_working"))
    live.panel("audit", {"records": [{k: r.get(k) for k in ("sequence", "case_id", "status", "target_id", "record_sha256")}
                                     for r in log.records()], "chain_intact": log.verify_chain()})
    return incident


def build_model(spec: str, default_action: str):
    if spec.startswith("ollama:"):
        return OllamaModel(spec.split(":", 1)[1])
    return FixedChoiceModel(default_action)


def start_intake(workdir: Path, live: LiveState, ids_public_hex: str):
    """The TLS intake server, with a throwaway CA and server certificate.
    Admitted detections are appended to a list the monitor consumes and are
    published to the live feed."""
    sys.path.insert(0, str(ROOT / "engine" / "tests"))
    from pki_fixture import TestPKI
    pki = TestPKI("chain-intake")
    cert, key, _ = pki.issue("intake", server=True)
    admitted: list = []
    published: list = []

    def on_admitted(result):
        admitted.append(result)
        published.append({"at": datetime.now(timezone.utc).isoformat(), "source": result.evidence.source,
                          "authentication": "ed25519", "assertion": result.evidence.assertion})
        live.panel("intake", {"admitted": list(published), "rejected": len(server.rejections)})
        live.event("detection_admitted", source=result.evidence.source, asset=result.asset)

    registry = {"suricata-lab": RegisteredDetectionSource("suricata-lab", "Suricata on lab loopback",
                                                          ed25519_public_key_hex=ids_public_hex)}
    server = DetectionIntakeServer(host="127.0.0.1", port=0, certfile=cert, keyfile=key, client_ca_file=None,
                                   registry=registry, on_admitted=on_admitted).start()
    live.panel("intake", {"admitted": [], "rejected": 0})
    return server, pki, admitted


def _wait_for(check, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return True
        time.sleep(0.25)
    return False


def check_live_view(playwright, url: str, expected_cases: list[str], feed: LiveFeedServer) -> dict:
    """Open the live dashboard in a real browser against the running feed,
    confirm it shows every completed incident from the feed, confirm the
    feed advances, then stop the feed and confirm the page stops claiming
    to be live. Polls from outside the page: the dashboard's CSP forbids
    eval, so in-page predicates are not used."""
    browser = playwright.chromium.launch()
    try:
        page = browser.new_page()
        page.goto(url)
        showed_live = _wait_for(lambda: page.text_content("#feed") == "LIVE", 10)
        rendered = _wait_for(lambda: page.locator("#incidents tr").count() >= len(expected_cases), 10)
        rows = [page.locator("#incidents tr").nth(i).get_attribute("data-case")
                for i in range(page.locator("#incidents tr").count())]
        first = page.text_content("#served-at")
        page.wait_for_timeout(2500)
        second = page.text_content("#served-at")
        feed.stop()
        went_dark = _wait_for(lambda: page.text_content("#feed") == "NO LIVE DATA", 15)
        return {"showed_live": showed_live, "rendered_cases": rows,
                "all_cases_rendered": rendered and sorted(rows) == sorted(expected_cases),
                "feed_timestamp_advanced": first != second,
                "reports_no_live_data_after_feed_stops": went_dark}
    finally:
        browser.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model", default="fixed",
                        help="'fixed' drives each registered path; 'ollama:<model>' runs a real model incident too")
    parser.add_argument("--model-digest", default="")
    parser.add_argument("--ids", choices=("none", "suricata"), default="none",
                        help="run the IDS-triggered incident with a real Suricata on loopback")
    parser.add_argument("--ids-sudo", action="store_true", help="start Suricata through sudo (CI runners)")
    args = parser.parse_args()

    approver_key = Ed25519PrivateKey.generate()
    approver_hex = approver_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    targets = {
        "site-csp": RegisteredTarget("site-csp", "nginx_csp_header", "lab", auto_apply_allowed=True,
                                     approver_keys={"lab-approver": approver_hex}),
        "site-page": RegisteredTarget("site-page", "static_page_rendering", "lab", auto_apply_allowed=True,
                                      approver_keys={"lab-approver": approver_hex}),
    }
    workdir = Path(tempfile.mkdtemp(prefix="ps-chain-"))
    log = AuditLog(workdir / "audit.jsonl")
    live = LiveState()
    feed = LiveFeedServer(live, page=ROOT / "demo" / "live.html", script=ROOT / "demo" / "live.js").start()
    lab = Lab(workdir)
    report = {"schema": SCHEMA, "started_at": datetime.now(timezone.utc).isoformat(),
              "nginx_version": __import__("subprocess").run([nginx_lab.NGINX_BINARY, "-v"], capture_output=True, text=True).stderr.strip(),
              "measured_prior_fingerprint": PRIOR_FINGERPRINT, "live_feed_url": feed.url, "incidents": {}}
    suricata = forwarder = intake = None
    try:
        with sync_playwright() as pw:
            plan = [
                ("A_fetch_contained_by_csp", "fetch", "restrict_all_fetch_targets", None),
                ("B_navigation_not_contained_by_csp", "navigation", "restrict_all_fetch_targets", None),
                ("C_navigation_contained_by_isolation", "navigation", "isolate_in_sandboxed_frame", None),
                ("D_popup_block_needs_approval", "popup", "block_vendor_script", ("lab-approver", approver_key)),
            ]
            for index, (name, channel, action, approver) in enumerate(plan):
                report["incidents"][name] = run_incident(
                    lab, pw, log, case_id=f"chain-{index}", channel=channel, live=live,
                    model=FixedChoiceModel(action), targets=targets, approver=approver, seed=index + 7)
            if args.model.startswith("ollama:"):
                model = build_model(args.model, "")
                incident = run_incident(lab, pw, log, case_id="chain-real-model", channel="fetch", live=live,
                                        model=model, targets=targets, approver=None, seed=99)
                incident["model_digest"] = args.model_digest
                report["incidents"]["E_real_model_fetch"] = incident
            if args.ids == "suricata":
                from ids_forwarder import AlertMapping, EveForwarder, Suricata
                ids_key = Ed25519PrivateKey.generate()
                ids_hex = ids_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
                intake, pki, admitted = start_intake(workdir, live, ids_hex)
                suricata = Suricata(workdir / "suricata", command_prefix=["sudo"] if args.ids_sudo else None)
                report["suricata_version"] = suricata.start()
                forwarder = EveForwarder(
                    eve_path=suricata.eve,
                    mapping=AlertMapping(asset=SERVICE, page_origin=lab.nginx.origin,
                                         sink_hosts=(lab.sink_server.server_address[0],)),
                    source_id="suricata-lab", private_key=ids_key, intake_host="127.0.0.1",
                    intake_port=intake.port, ca_file=pki.ca_file).start()
                incident = run_incident(
                    lab, pw, log, case_id="chain-ids", channel="fetch", live=live,
                    model=FixedChoiceModel("isolate_in_sandboxed_frame"), targets=targets, seed=42,
                    policy="adaptive", interval=300, admitted=admitted, visit_page=True, subject_id=SERVICE,
                    detection_notes=("Suricata sid 9900001: page data sent to a registered sink",))
                incident["ids"] = {"alerts_seen": forwarder.stats.alerts_seen, "dropped": forwarder.stats.dropped,
                                   "posted": forwarder.stats.posted[:5], "posted_total": len(forwarder.stats.posted),
                                   "intake_rejections": len(intake.rejections), "admitted_total": len(admitted)}
                report["incidents"]["F_ids_triggered_isolation"] = incident
            report["live_view_check"] = check_live_view(
                pw, feed.url, [i["case_id"] for i in report["incidents"].values()], feed)
            feed = None
    finally:
        if forwarder:
            forwarder.stop()
        if suricata:
            suricata.stop()
        if intake:
            intake.stop()
        if feed:
            feed.stop()
        lab.stop()
    report["audit_log_records"] = len(log.records())
    report["audit_log_chain_intact"] = log.verify_chain()
    report["audit_log"] = log.records()
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    report["summary"] = {name: {"final_status": i.get("final_status"), "applied_action": i.get("applied_action"),
                                "authority": i.get("authority"),
                                "widget_working": (i.get("verification_detail") or {}).get("widget_working"),
                                "served_matches_change": (i.get("served_after") or {}).get("matches_change"),
                                "served_matches_baseline": (i.get("served_after") or {}).get("matches_baseline"),
                                "dry_run_left_site_unchanged": (i.get("dry_run") or {}).get("served_unchanged"),
                                "probe_due_to": i["detection"].get("probe_due_to"),
                                "seconds_from_tamper_to_detection": i["detection"].get("seconds_from_tamper_to_detection")}
                         for name, i in report["incidents"].items()}
    report["summary"]["_audit_log_chain_intact"] = report["audit_log_chain_intact"]
    report["summary"]["_live_view_check"] = report.get("live_view_check")
    args.output.write_text(json.dumps(report, indent=1, sort_keys=True, default=str) + "\n")
    print(json.dumps(report["summary"], indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
