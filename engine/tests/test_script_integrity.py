"""Unit tests for script_integrity.py's four-assertion composite."""
import http.server
import threading
import unittest
from datetime import datetime, timedelta, timezone

from predict_shield.assessment import Outcome
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
    fetch_script_observation,
)

NOW = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)
GOOD_SHA384 = "a" * 96
BAD_SHA384 = "b" * 96

SCRIPT = RegisteredScript(script_id="vendor-widget", url="https://cdn.vendor.example/widget.js",
                          trusted_sha384=(GOOD_SHA384,))
SITE = RegisteredSite(site_id="example-sme.com", allowed_script_domains=("cdn.vendor.example",),
                      prohibited_sinks=("attacker.example",))


class _Handler(http.server.BaseHTTPRequestHandler):
    body = b"var x = 1;"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *args):
        pass


class _RedirectHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "http://evil.example/x.js")
        self.end_headers()

    def log_message(self, *args):
        pass


def _serve(handler_cls):
    server = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


class FetchTargetTests(unittest.TestCase):
    def test_fetch_from_a_registered_host_succeeds_and_hashes_the_real_body(self):
        server = _serve(_Handler)
        try:
            host, port = server.server_address
            script = RegisteredScript(script_id="local", url=f"http://{host}:{port}/widget.js",
                                      trusted_sha384=(GOOD_SHA384,))
            observation = fetch_script_observation(script, (host,), now=NOW)
            self.assertEqual(observation.status_code, 200)
            self.assertEqual(len(observation.sha384), 96)
        finally:
            server.shutdown()

    def test_fetch_from_an_unregistered_host_is_rejected_before_any_request(self):
        with self.assertRaises(FetchRejected):
            fetch_script_observation(SCRIPT, ("some-other-host.example",), now=NOW)

    def test_a_redirect_to_an_unregistered_host_is_not_followed(self):
        server = _serve(_RedirectHandler)
        try:
            host, port = server.server_address
            script = RegisteredScript(script_id="local", url=f"http://{host}:{port}/widget.js",
                                      trusted_sha384=(GOOD_SHA384,))
            with self.assertRaises(FetchRejected):
                fetch_script_observation(script, (host,), now=NOW)
        finally:
            server.shutdown()


class HashAssertionTests(unittest.TestCase):
    def test_a_trusted_hash_verifies(self):
        obs = ScriptObservation(script_id="vendor-widget", sha384=GOOD_SHA384, status_code=200, fetched_at=NOW)
        evidence = confirm_hash_matches_trusted(SCRIPT, obs, now=NOW)
        self.assertTrue(evidence.observed_pass)

    def test_a_tampered_hash_fails(self):
        obs = ScriptObservation(script_id="vendor-widget", sha384=BAD_SHA384, status_code=200, fetched_at=NOW)
        evidence = confirm_hash_matches_trusted(SCRIPT, obs, now=NOW)
        self.assertFalse(evidence.observed_pass)

    def test_a_stale_observation_is_rejected(self):
        obs = ScriptObservation(script_id="vendor-widget", sha384=GOOD_SHA384, status_code=200,
                                fetched_at=NOW - timedelta(hours=2))
        with self.assertRaises(ValueError):
            confirm_hash_matches_trusted(SCRIPT, obs, now=NOW, max_age_seconds=900)


class DomainAssertionTests(unittest.TestCase):
    def test_only_registered_domains_pass(self):
        evidence = confirm_no_unregistered_domain(SITE, ("cdn.vendor.example",), NOW, now=NOW)
        self.assertTrue(evidence.observed_pass)

    def test_an_undeclared_destination_fails_even_if_not_a_script_tag(self):
        # This is the fetch/XHR/sendBeacon case, not only a <script src>.
        evidence = confirm_no_unregistered_domain(SITE, ("cdn.vendor.example", "exfil.example"), NOW, now=NOW)
        self.assertFalse(evidence.observed_pass)


class CspAssertionTests(unittest.TestCase):
    def test_a_missing_header_fails(self):
        evidence = confirm_csp_enforced(SITE, None, NOW, now=NOW)
        self.assertFalse(evidence.observed_pass)

    def test_a_wildcard_script_src_does_not_count_as_enforced(self):
        evidence = confirm_csp_enforced(SITE, "script-src *", NOW, now=NOW)
        self.assertFalse(evidence.observed_pass)

    def test_a_properly_scoped_header_passes(self):
        evidence = confirm_csp_enforced(SITE, "script-src 'self' cdn.vendor.example", NOW, now=NOW)
        self.assertTrue(evidence.observed_pass)

    def test_an_unregistered_host_in_the_header_does_not_pass(self):
        evidence = confirm_csp_enforced(SITE, "script-src 'self' some-other-cdn.example", NOW, now=NOW)
        self.assertFalse(evidence.observed_pass)


class BehavioralAssertionTests(unittest.TestCase):
    def test_no_prohibited_destination_reached_passes(self):
        evidence = confirm_no_prohibited_network_behavior(SITE, ("cdn.vendor.example",), NOW, now=NOW)
        self.assertTrue(evidence.observed_pass)

    def test_a_prohibited_destination_actually_reached_fails_even_with_a_clean_hash(self):
        # The point of this assertion: an allowlisted-domain script can
        # still cause the browser to reach a prohibited sink. A hash
        # match (tested separately above) says nothing about this.
        evidence = confirm_no_prohibited_network_behavior(
            SITE, ("cdn.vendor.example", "attacker.example"), NOW, now=NOW)
        self.assertFalse(evidence.observed_pass)


class CompositeEvaluateTests(unittest.TestCase):
    def _scope_and_evidence(self, *, hash_pass=True, domain_pass=True, csp_pass=True, behavior_pass=True):
        hash_obs = ScriptObservation(script_id="vendor-widget",
                                     sha384=GOOD_SHA384 if hash_pass else BAD_SHA384,
                                     status_code=200, fetched_at=NOW)
        hash_ev = confirm_hash_matches_trusted(SCRIPT, hash_obs, now=NOW)
        domains = ("cdn.vendor.example",) if domain_pass else ("cdn.vendor.example", "evil.example")
        domain_ev = confirm_no_unregistered_domain(SITE, domains, NOW, now=NOW)
        header = "script-src 'self' cdn.vendor.example" if csp_pass else None
        csp_ev = confirm_csp_enforced(SITE, header, NOW, now=NOW)
        reached = ("cdn.vendor.example",) if behavior_pass else ("attacker.example",)
        behavior_ev = confirm_no_prohibited_network_behavior(SITE, reached, NOW, now=NOW)
        scope = {
            HASH_MATCHES_TRUSTED: (hash_ev.asset, hash_ev.assertion),
            NO_UNREGISTERED_DOMAIN: (domain_ev.asset, domain_ev.assertion),
            CSP_ENFORCED: (csp_ev.asset, csp_ev.assertion),
            NO_PROHIBITED_NETWORK_BEHAVIOR: (behavior_ev.asset, behavior_ev.assertion),
        }
        return scope, [hash_ev, domain_ev, csp_ev, behavior_ev]

    def test_all_four_verified_accepts(self):
        scope, evidence = self._scope_and_evidence()
        verdict = evaluate(scope, evidence, now=NOW)
        self.assertTrue(verdict.accepted)
        self.assertEqual(verdict.blocking_reasons, ())

    def test_hash_mismatch_alone_blocks_acceptance(self):
        scope, evidence = self._scope_and_evidence(hash_pass=False)
        verdict = evaluate(scope, evidence, now=NOW)
        self.assertFalse(verdict.accepted)
        self.assertEqual(verdict.assessments[HASH_MATCHES_TRUSTED].outcome, Outcome.NOT_VERIFIED)

    def test_clean_hash_but_prohibited_behavior_still_blocks_acceptance(self):
        # The central correction: hash equality cannot substitute for the
        # behavioral check.
        scope, evidence = self._scope_and_evidence(hash_pass=True, behavior_pass=False)
        verdict = evaluate(scope, evidence, now=NOW)
        self.assertFalse(verdict.accepted)
        self.assertEqual(verdict.assessments[NO_PROHIBITED_NETWORK_BEHAVIOR].outcome, Outcome.NOT_VERIFIED)

    def test_missing_required_assertion_in_scope_raises(self):
        scope, evidence = self._scope_and_evidence()
        del scope[CSP_ENFORCED]
        with self.assertRaises(ValueError):
            evaluate(scope, evidence, now=NOW)


if __name__ == "__main__":
    unittest.main()
