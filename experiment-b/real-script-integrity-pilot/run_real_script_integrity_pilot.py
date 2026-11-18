"""Real controlled-adversary-simulation pilot for third-party script
integrity: a real Playwright-driven Chromium load of a real local page,
a real vendor script served by a real local HTTP server, and a real
separate local server standing in for an attacker-controlled destination.

This is a controlled adversary simulation, not AI-assisted red teaming:
every scenario below is manually constructed, not generated, adapted or
prioritized by a model. See `engine/predict_shield/script_integrity.py`
for why the checks exercised here cannot be satisfied by a hash
comparison alone, and `docs/development/ROADMAP.md` for this
capability's built/planned boundary.

Three origins, all loopback addresses on this machine: the operator's
own site (127.0.0.1, serves the page and its CSP header), the third-party
vendor (127.0.0.3, serves the script) and a sink (127.0.0.2) standing in
for an attacker-controlled destination.

Detection scenarios:

    A. Negative control: clean vendor script, real page load, real CSP
       header. All four assertions must VERIFY, and the page's own
       button must actually become enabled (the script really ran).
    B. Malicious tamper: the vendor starts serving a compromised script.
       The fetch probe's hash check must flag it, and a real Chromium
       load must show the script actually reaching the sink over the
       network, confirmed separately by the sink server's own log.
    C. Benign vendor update (false-positive control): different, benign
       bytes whose hash was pre-registered. Must NOT be flagged.
    D. Unregistered-domain injection: the page's markup gains a second,
       undeclared script pointing at the sink. The hash check alone
       misses this; the browser's real network capture must not.
    E. CSP enforcement toggle: missing, wildcard and correctly scoped.

Containment verification, every trial with the COMPROMISED script live
at the vendor, each judged by two independent sources (the browser's
own capture and the sink server's own log, both required) and each
recording functional disruption:

    F1. Block the vendor script (CSP script-src 'self').
    F2. Restrict where scripts may send data (CSP connect-src 'self'),
        leaving the vendor script itself allowed to run.
    F3. Ineffective containment (CSP allows the vendor and restricts
        nothing else): the verifier must report NOT VERIFIED, proving it
        can fail a containment rather than only ever passing one.

Controls on the containment verifier itself, the two ways an absence of
a prohibited request could mean nothing:

    G. Instrumentation not live: the F2 trial again, but with the browser
       capture deliberately not attached, so the page-owned canary is not
       recorded. Must be INDETERMINATE, never VERIFIED.
    H. Exposure not exercised: the F2 CSP again, but with the clean
       script live at the vendor, so there is no compromise to contain.
       Must be INDETERMINATE, never VERIFIED.

The probe detection latency (scenario B) is the time from the tamper to
the fetch probe flagging it when a probe runs immediately afterward. It
deliberately excludes the re-verification scheduling interval, which
dominates real-world detection time and depends on the scheduler's
probe budget, not on this probe.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab_servers

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "engine"))
from predict_shield.assessment import assess
from predict_shield.script_integrity import (
    CSP_ENFORCED,
    HASH_MATCHES_TRUSTED,
    NO_PROHIBITED_NETWORK_BEHAVIOR,
    NO_UNREGISTERED_DOMAIN,
    BrowserBehaviorCapture,
    RegisteredScript,
    RegisteredSite,
    confirm_controlled_sink_log,
    confirm_csp_enforced,
    confirm_hash_matches_trusted,
    confirm_no_prohibited_network_behavior,
    confirm_no_unregistered_domain,
    evaluate,
    fetch_response_headers,
    fetch_script_observation,
)

SCHEMA = "predict-shield/real-script-integrity-pilot/2"


def _sha384(body: bytes) -> str:
    return hashlib.sha384(body).hexdigest()


@dataclass
class PageTrial:
    requested_hosts: set
    sent_hosts: set
    blocked_hosts: set
    canary_observed: bool
    vendor_script_requested: bool
    button_enabled: bool


def _load(playwright, url: str, vendor_script_url: str, *, instrument: bool = True,
          timeout_ms: int = 5000) -> PageTrial:
    """Load `url` in a real headless Chromium page. With `instrument`,
    record every request the page attempts, which ones actually left
    the browser and which the browser refused to send, and whether the page-owned
    canary request was recorded. Without it, nothing is recorded -- the
    deliberate dead-instrumentation control (scenario G)."""
    requested, sent, blocked = set(), set(), set()
    flags = {"canary": False, "vendor": False}
    browser = playwright.chromium.launch()
    try:
        page = browser.new_page()
        if instrument:
            def on_request(req):
                requested.add(urlparse(req.url).hostname)
                if req.url == vendor_script_url:
                    flags["vendor"] = True

            def on_finished(req):
                sent.add(urlparse(req.url).hostname)
                if urlparse(req.url).path == "/canary.gif":
                    flags["canary"] = True

            def on_failed(req):
                # Only a request the browser refused to send counts as
                # blocked. Any other failure (aborted, opaque response)
                # happened after the request left the browser, so the
                # destination may already have received its contents.
                host = urlparse(req.url).hostname
                failure = (req.failure or "").lower()
                if failure == "csp" or "blocked_by_csp" in failure or "blocked_by_client" in failure:
                    blocked.add(host)
                else:
                    sent.add(host)

            page.on("request", on_request)
            page.on("requestfinished", on_finished)
            page.on("requestfailed", on_failed)
        page.goto(url, timeout=timeout_ms)
        page.wait_for_timeout(700)
        try:
            enabled = page.is_enabled("#checkout-button")
        except Exception:
            enabled = False
        return PageTrial(requested, sent, blocked, flags["canary"], flags["vendor"], enabled)
    finally:
        browser.close()


def _hosts(values) -> list:
    return sorted(h for h in values if h)


def run(output_path: Path) -> dict:
    state = lab_servers.VendorState()
    site_server = lab_servers.start_server("127.0.0.1", lab_servers.make_site_handler(state))
    vendor_server = lab_servers.start_server("127.0.0.3", lab_servers.make_vendor_handler(state))
    sink_state = lab_servers.SinkState()
    sink_server = lab_servers.start_server("127.0.0.2", lab_servers.make_sink_handler(sink_state))
    site_host, site_port = site_server.server_address
    vendor_host, vendor_port = vendor_server.server_address
    sink_host, sink_port = sink_server.server_address
    state.site_origin = f"http://{site_host}:{site_port}"
    state.vendor_origin = f"http://{vendor_host}:{vendor_port}"
    state.sink_origin = f"http://{sink_host}:{sink_port}"
    page_url = state.site_origin + "/page.html"
    vendor_script_url = state.vendor_origin + "/widget.js"

    good_hash = _sha384(lab_servers.GOOD_SCRIPT)
    benign_update_hash = _sha384(lab_servers.BENIGN_UPDATE_SCRIPT)
    malicious_body = lab_servers.malicious_script(state.sink_origin)
    malicious_hash = _sha384(malicious_body)

    allowed_hosts = (vendor_host, site_host)
    script = RegisteredScript(script_id="lab-vendor-widget", url=vendor_script_url,
                              trusted_sha384=(good_hash,))
    # Every destination a clean page load is expected to contact: the
    # site's own host (the navigation itself and the canary) plus the one
    # registered vendor. The CSP check is scoped to script-src alone.
    site = RegisteredSite(site_id="lab-checkout-page", allowed_script_domains=(vendor_host, site_host),
                          prohibited_sinks=(sink_host,))
    vendor_csp_source = f"{vendor_host}:{vendor_port}"

    def set_state(*, body: bytes | None = None, csp: str | None | bool = False, extra: str | None = None):
        with state.lock:
            if body is not None:
                state.script_body = body
            if csp is not False:
                state.csp_header = csp
            if extra is not None:
                state.extra_script_tag = extra

    def sink_hits() -> int:
        with sink_state.lock:
            return len(sink_state.hits)

    report: dict = {"schema": SCHEMA, "started_at": datetime.now(timezone.utc).isoformat(),
                    "site_origin": state.site_origin, "vendor_origin": state.vendor_origin,
                    "sink_origin": state.sink_origin, "scenarios": {}, "containment": {}}

    def containment_trial(label: str, action: str, csp: str, body: bytes, expected_hash: str,
                          *, instrument: bool = True) -> dict:
        set_state(body=body, csp=csp, extra="")
        now = datetime.now(timezone.utc)
        probe = fetch_script_observation(script, allowed_hosts, now=now)
        compromise_live = probe.sha384 == expected_hash
        hits_before = sink_hits()
        trial = _load(playwright, page_url, vendor_script_url, instrument=instrument)
        hits = sink_hits() - hits_before
        capture = BrowserBehaviorCapture(
            sent_hosts=tuple(_hosts(trial.sent_hosts)),
            blocked_hosts=tuple(_hosts(trial.blocked_hosts)),
            canary_observed=trial.canary_observed,
            exposure_exercised=compromise_live and trial.vendor_script_requested,
        )
        browser_ev = confirm_no_prohibited_network_behavior(site, capture, now, now=now)
        sink_ev = confirm_controlled_sink_log(site, hits, now, now=now)
        verdict = assess(site.site_id, NO_PROHIBITED_NETWORK_BEHAVIOR, [browser_ev, sink_ev],
                         required_independent_checks=2, now=now)
        return {
            "containment_action": action, "csp_header": csp,
            "compromised_script_live_at_vendor": compromise_live,
            "browser_attempted_vendor_script": trial.vendor_script_requested,
            "canary_observed": trial.canary_observed,
            "exposure_exercised": capture.exposure_exercised,
            "sent_hosts": list(capture.sent_hosts),
            "blocked_hosts": list(capture.blocked_hosts),
            "sink_server_hits": hits,
            "browser_evidence": ("UNINFORMATIVE" if browser_ev.observed_pass is None
                                 else ("PASS" if browser_ev.observed_pass else "FAIL")),
            "sink_log_evidence": "PASS" if sink_ev.observed_pass else "FAIL",
            "containment_outcome": verdict.outcome.value,
            "containment_reason": verdict.reason,
            "button_enabled": trial.button_enabled,
            "functional_disruption_detected": not trial.button_enabled,
        }

    with sync_playwright() as playwright:
        # --- A. Negative control -------------------------------------------------
        set_state(body=lab_servers.GOOD_SCRIPT, csp=f"script-src 'self' {vendor_csp_source}")
        now_a = datetime.now(timezone.utc)
        obs_a = fetch_script_observation(script, allowed_hosts, now=now_a)
        headers_a = fetch_response_headers(page_url, allowed_hosts)
        hits_before = sink_hits()
        trial_a = _load(playwright, page_url, vendor_script_url)
        capture_a = BrowserBehaviorCapture(
            sent_hosts=tuple(_hosts(trial_a.sent_hosts)),
            blocked_hosts=tuple(_hosts(trial_a.blocked_hosts)),
            canary_observed=trial_a.canary_observed,
            exposure_exercised=(obs_a.sha384 == good_hash) and trial_a.vendor_script_requested,
        )
        hash_ev = confirm_hash_matches_trusted(script, obs_a, now=now_a)
        domain_ev = confirm_no_unregistered_domain(site, tuple(_hosts(trial_a.requested_hosts)), now_a, now=now_a)
        csp_ev = confirm_csp_enforced(site, headers_a.get("content-security-policy"), now_a, now=now_a)
        behavior_ev = confirm_no_prohibited_network_behavior(site, capture_a, now_a, now=now_a)
        sink_ev_a = confirm_controlled_sink_log(site, sink_hits() - hits_before, now_a, now=now_a)
        scope = {
            HASH_MATCHES_TRUSTED: (hash_ev.asset, hash_ev.assertion),
            NO_UNREGISTERED_DOMAIN: (domain_ev.asset, domain_ev.assertion),
            CSP_ENFORCED: (csp_ev.asset, csp_ev.assertion),
            NO_PROHIBITED_NETWORK_BEHAVIOR: (behavior_ev.asset, behavior_ev.assertion),
        }
        verdict_a = evaluate(scope, [hash_ev, domain_ev, csp_ev, behavior_ev, sink_ev_a], now=now_a)
        report["scenarios"]["A_negative_control"] = {
            "accepted": verdict_a.accepted, "blocking_reasons": list(verdict_a.blocking_reasons),
            "button_enabled_by_real_script_execution": trial_a.button_enabled,
            "canary_observed": trial_a.canary_observed,
            "observed_hosts": _hosts(trial_a.requested_hosts),
        }

        # --- B. Malicious tamper --------------------------------------------------
        tamper_started = time.monotonic()
        set_state(body=malicious_body)
        now_b = datetime.now(timezone.utc)
        obs_b = fetch_script_observation(script, allowed_hosts, now=now_b)
        probe_latency = time.monotonic() - tamper_started
        hits_before = sink_hits()
        trial_b = _load(playwright, page_url, vendor_script_url)
        hits_b = sink_hits() - hits_before
        hash_ev_b = confirm_hash_matches_trusted(script, obs_b, now=now_b)
        report["scenarios"]["B_malicious_tamper"] = {
            "hash_matches_trusted": hash_ev_b.observed_pass,
            "probe_detection_latency_seconds": round(probe_latency, 4),
            "probe_detection_latency_excludes_scheduling_interval": True,
            "real_browser_reached_sink": sink_host in trial_b.sent_hosts,
            "sink_server_hits": hits_b,
            "observed_hosts": _hosts(trial_b.requested_hosts),
        }

        # --- C. Benign vendor update (false-positive control) ----------------------
        script_c = RegisteredScript(script_id="lab-vendor-widget", url=script.url,
                                    trusted_sha384=(good_hash, benign_update_hash))
        set_state(body=lab_servers.BENIGN_UPDATE_SCRIPT)
        now_c = datetime.now(timezone.utc)
        obs_c = fetch_script_observation(script_c, allowed_hosts, now=now_c)
        hash_ev_c = confirm_hash_matches_trusted(script_c, obs_c, now=now_c)
        trial_c = _load(playwright, page_url, vendor_script_url)
        domain_ev_c = confirm_no_unregistered_domain(site, tuple(_hosts(trial_c.requested_hosts)), now_c, now=now_c)
        report["scenarios"]["C_benign_vendor_update"] = {
            "new_hash_was_preregistered": True,
            "hash_matches_trusted": hash_ev_c.observed_pass,
            "false_positive_occurred": not (hash_ev_c.observed_pass and domain_ev_c.observed_pass),
        }

        # --- D. Unregistered-domain injection (static markup, clean hash) ----------
        set_state(body=lab_servers.GOOD_SCRIPT, extra=f'<script src="{state.sink_origin}/decoy.js"></script>',
                  csp=f"script-src 'self' {vendor_csp_source} {sink_host}:{sink_port}")
        now_d = datetime.now(timezone.utc)
        obs_d = fetch_script_observation(script, allowed_hosts, now=now_d)
        hash_ev_d = confirm_hash_matches_trusted(script, obs_d, now=now_d)
        trial_d = _load(playwright, page_url, vendor_script_url)
        domain_ev_d = confirm_no_unregistered_domain(site, tuple(_hosts(trial_d.requested_hosts)), now_d, now=now_d)
        report["scenarios"]["D_unregistered_domain_injection"] = {
            "hash_matches_trusted": hash_ev_d.observed_pass,
            "no_unregistered_domain_passed": domain_ev_d.observed_pass,
            "observed_hosts": _hosts(trial_d.requested_hosts),
            "caught_by_domain_check_despite_clean_hash": hash_ev_d.observed_pass and not domain_ev_d.observed_pass,
        }
        set_state(extra="")

        # --- E. CSP enforcement toggle ----------------------------------------------
        csp_results = {}
        for label, header in (("missing", None), ("wildcard", "script-src *"),
                              ("correctly_scoped", f"script-src 'self' {vendor_csp_source}")):
            set_state(csp=header)
            headers_e = fetch_response_headers(page_url, allowed_hosts)
            now_e = datetime.now(timezone.utc)
            csp_results[label] = confirm_csp_enforced(
                site, headers_e.get("content-security-policy"), now_e, now=now_e).observed_pass
        report["scenarios"]["E_csp_enforcement_toggle"] = csp_results

        # --- F. Containment verification, compromised script live -----------------
        report["containment"]["F1_block_vendor_script"] = containment_trial(
            "F1", "block_vendor_script", "script-src 'self'", malicious_body, malicious_hash)
        report["containment"]["F2_restrict_connect_src"] = containment_trial(
            "F2", "restrict_connect_src", f"script-src 'self' {vendor_csp_source}; connect-src 'self'",
            malicious_body, malicious_hash)
        report["containment"]["F3_ineffective_containment"] = containment_trial(
            "F3", "ineffective_allow_vendor_only", f"script-src 'self' {vendor_csp_source}",
            malicious_body, malicious_hash)

        # --- G/H. Controls on the containment verifier itself ----------------------
        report["containment"]["G_instrumentation_not_live"] = containment_trial(
            "G", "restrict_connect_src", f"script-src 'self' {vendor_csp_source}; connect-src 'self'",
            malicious_body, malicious_hash, instrument=False)
        report["containment"]["H_exposure_not_exercised"] = containment_trial(
            "H", "restrict_connect_src", f"script-src 'self' {vendor_csp_source}; connect-src 'self'",
            lab_servers.GOOD_SCRIPT, malicious_hash)

    vendor_server.shutdown()
    site_server.shutdown()
    sink_server.shutdown()
    c = report["containment"]
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    report["summary"] = {
        "negative_control_accepted": report["scenarios"]["A_negative_control"]["accepted"],
        "malicious_tamper_caught_by_hash": not report["scenarios"]["B_malicious_tamper"]["hash_matches_trusted"],
        "malicious_tamper_real_network_reach_confirmed":
            report["scenarios"]["B_malicious_tamper"]["real_browser_reached_sink"]
            and report["scenarios"]["B_malicious_tamper"]["sink_server_hits"] > 0,
        "probe_detection_latency_seconds": report["scenarios"]["B_malicious_tamper"]["probe_detection_latency_seconds"],
        "false_positive_occurred": report["scenarios"]["C_benign_vendor_update"]["false_positive_occurred"],
        "unregistered_domain_caught_despite_clean_hash":
            report["scenarios"]["D_unregistered_domain_injection"]["caught_by_domain_check_despite_clean_hash"],
        "containment_outcomes": {k: v["containment_outcome"] for k, v in c.items()},
        "containment_functional_disruption": {k: v["functional_disruption_detected"]
                                              for k, v in c.items() if k.startswith("F")},
    }
    output_path.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.output)
    print(json.dumps(report["summary"], indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
