"""Real controlled-adversary-simulation pilot for third-party script
integrity: a real Playwright-driven Chromium load of a real local page,
a real vendor script served by a real local HTTP server, and a real
second local server standing in for an attacker-controlled destination.

This is a controlled adversary simulation, not AI-assisted red teaming:
every scenario below is manually constructed, not generated, adapted or
prioritized by a model. See `engine/predict_shield/script_integrity.py`
for why the checks exercised here cannot be satisfied by a hash
comparison alone, and `docs/development/ROADMAP.md` for this
capability's honest built/planned boundary.

Scenarios, all against the same running pair of servers:

    A. Negative control: real vendor script, real page load, real CSP
       header. All four assertions must VERIFY, and the page's own
       button must actually become enabled (the script really ran).
    B. Malicious tamper: the vendor server starts serving a compromised
       script. The real fetch probe's hash check must flag it, and
       (the correction this pilot exists to prove) a real Chromium load
       must show the script actually reaching the attacker-controlled
       sink server over the network -- not merely that the hash changed.
    C. Benign vendor update (false-positive control): the served script
       changes again, to different but non-malicious bytes, with the
       new hash pre-registered the way an operator reviewing a real
       vendor release would. This must NOT be flagged.
    D. Unregistered-domain injection: the page's own markup gains a
       second, undeclared <script src> pointing at the sink server.
       The hash check alone would miss this; the domain check, built
       from a real browser's own network activity, must not.
    E. CSP enforcement toggle: with no header, a wildcard header, and a
       correctly scoped header, confirming the check's effect, not just
       the header's presence.
    F. Containment side effect, measured honestly: with CSP tightened to
       block the vendor script entirely (one real containment action),
       record whether the page's own button still becomes enabled. If
       it does not, that is a real functional disruption this report
       states plainly rather than omitting.

Detection time, false-positive occurrence and functional disruption are
all measured from the real runs below, not asserted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from playwright.sync_api import sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab_servers

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "engine"))
from predict_shield.script_integrity import (
    CSP_ENFORCED,
    HASH_MATCHES_TRUSTED,
    NO_PROHIBITED_NETWORK_BEHAVIOR,
    NO_UNREGISTERED_DOMAIN,
    FetchRejected,
    RegisteredScript,
    RegisteredSite,
    ScriptObservation,
    confirm_csp_enforced,
    confirm_hash_matches_trusted,
    confirm_no_prohibited_network_behavior,
    confirm_no_unregistered_domain,
    evaluate,
    fetch_response_headers,
    fetch_script_observation,
)

SCHEMA = "predict-shield/real-script-integrity-pilot/1"


def _sha384(body: bytes) -> str:
    return hashlib.sha384(body).hexdigest()


def _load_and_capture(playwright, url: str, timeout_ms: int = 5000):
    """Load `url` in a real headless Chromium page and return the set of
    hostnames actually contacted, and whether the checkout button ended
    up enabled. This is the real network capture the behavioral and
    domain assertions in script_integrity.py require as input; nothing
    here re-derives it from the script's own source text."""
    from urllib.parse import urlparse
    hosts: set[str] = set()
    browser = playwright.chromium.launch()
    try:
        page = browser.new_page()
        page.on("request", lambda req: hosts.add(urlparse(req.url).hostname))
        page.goto(url, timeout=timeout_ms)
        page.wait_for_timeout(500)
        try:
            enabled = page.is_enabled("#checkout-button")
        except Exception:
            enabled = False
        return hosts, enabled
    finally:
        browser.close()


def run(output_path: Path) -> dict:
    state = lab_servers.VendorState()
    site_server = lab_servers.start_server("127.0.0.1", lab_servers.make_site_handler(state))
    vendor_server = lab_servers.start_server("127.0.0.3", lab_servers.make_vendor_handler(state))
    sink_server = lab_servers.start_server("127.0.0.2", lab_servers.make_sink_handler(
        sink_state := lab_servers.SinkState()))
    site_host, site_port = site_server.server_address
    vendor_host, vendor_port = vendor_server.server_address
    sink_host, sink_port = sink_server.server_address
    state.site_origin = f"http://{site_host}:{site_port}"
    state.vendor_origin = f"http://{vendor_host}:{vendor_port}"
    state.sink_origin = f"http://{sink_host}:{sink_port}"

    good_hash = _sha384(lab_servers.GOOD_SCRIPT)
    benign_update_hash = _sha384(lab_servers.BENIGN_UPDATE_SCRIPT)
    malicious_body = lab_servers.malicious_script(state.sink_origin)

    allowed_hosts = (vendor_host, site_host)
    script = RegisteredScript(script_id="lab-vendor-widget", url=state.vendor_origin + "/widget.js",
                              trusted_sha384=(good_hash,))
    # allowed_script_domains covers every destination a clean page load
    # is expected to contact: the site's own host (the top-level
    # navigation itself) plus the one registered third-party vendor.
    # The CSP check below is scoped more narrowly, to script-src alone,
    # and treats the site's own host as 'self' the way a real browser does.
    site = RegisteredSite(site_id="lab-checkout-page", allowed_script_domains=(vendor_host, site_host),
                          prohibited_sinks=(sink_host,))

    report: dict = {"schema": SCHEMA, "started_at": datetime.now(timezone.utc).isoformat(),
                    "site_origin": state.site_origin, "vendor_origin": state.vendor_origin,
                    "sink_origin": state.sink_origin, "scenarios": {}}

    with sync_playwright() as playwright:
        # --- A. Negative control -------------------------------------------------
        state.csp_header = f"script-src 'self' {vendor_host}:{vendor_port}"
        now_a = datetime.now(timezone.utc)
        obs_a = fetch_script_observation(script, allowed_hosts, now=now_a)
        headers_a = fetch_response_headers(state.site_origin + "/page.html", allowed_hosts)
        hosts_a, enabled_a = _load_and_capture(playwright, state.site_origin + "/page.html")
        hash_ev = confirm_hash_matches_trusted(script, obs_a, now=now_a)
        domain_ev = confirm_no_unregistered_domain(site, tuple(hosts_a), now_a, now=now_a)
        csp_ev = confirm_csp_enforced(site, headers_a.get("content-security-policy"), now_a, now=now_a)
        behavior_ev = confirm_no_prohibited_network_behavior(site, tuple(hosts_a), now_a, now=now_a)
        scope = {
            HASH_MATCHES_TRUSTED: (hash_ev.asset, hash_ev.assertion),
            NO_UNREGISTERED_DOMAIN: (domain_ev.asset, domain_ev.assertion),
            CSP_ENFORCED: (csp_ev.asset, csp_ev.assertion),
            NO_PROHIBITED_NETWORK_BEHAVIOR: (behavior_ev.asset, behavior_ev.assertion),
        }
        verdict_a = evaluate(scope, [hash_ev, domain_ev, csp_ev, behavior_ev], now=now_a)
        report["scenarios"]["A_negative_control"] = {
            "accepted": verdict_a.accepted, "blocking_reasons": list(verdict_a.blocking_reasons),
            "button_enabled_by_real_script_execution": enabled_a,
            "observed_hosts": sorted(h for h in hosts_a if h),
        }

        # --- B. Malicious tamper --------------------------------------------------
        tamper_started = time.monotonic()
        with state.lock:
            state.script_body = malicious_body
        now_b = datetime.now(timezone.utc)
        obs_b = fetch_script_observation(script, allowed_hosts, now=now_b)
        detection_time_seconds = time.monotonic() - tamper_started
        hosts_b, enabled_b = _load_and_capture(playwright, state.site_origin + "/page.html")
        hash_ev_b = confirm_hash_matches_trusted(script, obs_b, now=now_b)
        domain_ev_b = confirm_no_unregistered_domain(site, tuple(hosts_b), now_b, now=now_b)
        behavior_ev_b = confirm_no_prohibited_network_behavior(site, tuple(hosts_b), now_b, now=now_b)
        report["scenarios"]["B_malicious_tamper"] = {
            "hash_matches_trusted": hash_ev_b.observed_pass,
            "detection_time_seconds": round(detection_time_seconds, 4),
            "real_browser_reached_sink": not behavior_ev_b.observed_pass,
            "sink_server_recorded_hits": list(sink_state.hits),
            "observed_hosts": sorted(h for h in hosts_b if h),
            "domain_check_passed": domain_ev_b.observed_pass,
        }

        # --- C. Benign vendor update (false-positive control) ----------------------
        script_c = RegisteredScript(script_id="lab-vendor-widget", url=script.url,
                                    trusted_sha384=(good_hash, benign_update_hash))
        with state.lock:
            state.script_body = lab_servers.BENIGN_UPDATE_SCRIPT
        now_c = datetime.now(timezone.utc)
        obs_c = fetch_script_observation(script_c, allowed_hosts, now=now_c)
        hash_ev_c = confirm_hash_matches_trusted(script_c, obs_c, now=now_c)
        hosts_c, _ = _load_and_capture(playwright, state.site_origin + "/page.html")
        domain_ev_c = confirm_no_unregistered_domain(site, tuple(hosts_c), now_c, now=now_c)
        false_positive_occurred = not (hash_ev_c.observed_pass and domain_ev_c.observed_pass)
        report["scenarios"]["C_benign_vendor_update"] = {
            "new_hash_was_preregistered": True,
            "hash_matches_trusted": hash_ev_c.observed_pass,
            "false_positive_occurred": false_positive_occurred,
        }

        # --- D. Unregistered-domain injection (static markup, clean hash) ----------
        with state.lock:
            state.script_body = lab_servers.GOOD_SCRIPT
            state.extra_script_tag = f'<script src="{state.sink_origin}/decoy.js"></script>'
        now_d = datetime.now(timezone.utc)
        obs_d = fetch_script_observation(script, allowed_hosts, now=now_d)
        hash_ev_d = confirm_hash_matches_trusted(script, obs_d, now=now_d)
        hosts_d, _ = _load_and_capture(playwright, state.site_origin + "/page.html")
        domain_ev_d = confirm_no_unregistered_domain(site, tuple(hosts_d), now_d, now=now_d)
        report["scenarios"]["D_unregistered_domain_injection"] = {
            "hash_matches_trusted": hash_ev_d.observed_pass,
            "no_unregistered_domain_passed": domain_ev_d.observed_pass,
            "observed_hosts": sorted(h for h in hosts_d if h),
            "caught_by_domain_check_despite_clean_hash": hash_ev_d.observed_pass and not domain_ev_d.observed_pass,
        }
        with state.lock:
            state.extra_script_tag = ""

        # --- E. CSP enforcement toggle ----------------------------------------------
        csp_results = {}
        for label, header in (
            ("missing", None),
            ("wildcard", "script-src *"),
            ("correctly_scoped", f"script-src 'self' {vendor_host}:{vendor_port}"),
        ):
            with state.lock:
                state.csp_header = header
            headers_e = fetch_response_headers(state.site_origin + "/page.html", allowed_hosts)
            now_e = datetime.now(timezone.utc)
            csp_ev_e = confirm_csp_enforced(site, headers_e.get("content-security-policy"), now_e, now=now_e)
            csp_results[label] = csp_ev_e.observed_pass
        report["scenarios"]["E_csp_enforcement_toggle"] = csp_results

        # --- F. Containment side effect, measured honestly --------------------------
        with state.lock:
            state.script_body = lab_servers.GOOD_SCRIPT
            # Contain by tightening CSP to 'self' only, revoking the vendor
            # host's permission to run script at all.
            state.csp_header = "script-src 'self'"
        _, enabled_f = _load_and_capture(playwright, state.site_origin + "/page.html")
        report["scenarios"]["F_containment_side_effect"] = {
            "containment_action": "tighten_csp_to_self_only",
            "button_enabled_after_containment": enabled_f,
            "functional_disruption_detected": not enabled_f,
        }

    vendor_server.shutdown()
    site_server.shutdown()
    sink_server.shutdown()
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    report["summary"] = {
        "detection_time_seconds": report["scenarios"]["B_malicious_tamper"]["detection_time_seconds"],
        "false_positive_occurred": report["scenarios"]["C_benign_vendor_update"]["false_positive_occurred"],
        "functional_disruption_detected": report["scenarios"]["F_containment_side_effect"][
            "functional_disruption_detected"],
        "negative_control_accepted": report["scenarios"]["A_negative_control"]["accepted"],
        "malicious_tamper_caught_by_hash": not report["scenarios"]["B_malicious_tamper"]["hash_matches_trusted"],
        "malicious_tamper_real_network_reach_confirmed":
            report["scenarios"]["B_malicious_tamper"]["real_browser_reached_sink"],
        "unregistered_domain_caught_despite_clean_hash":
            report["scenarios"]["D_unregistered_domain_injection"]["caught_by_domain_check_despite_clean_hash"],
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
