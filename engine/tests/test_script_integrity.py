"""Unit tests for script_integrity.py's four-assertion composite."""
import http.server
import threading
import unittest
from datetime import datetime, timedelta, timezone

from predict_shield.assessment import Outcome, assess
from predict_shield.script_integrity import (
    CSP_ENFORCED,
    HASH_MATCHES_TRUSTED,
    NO_PROHIBITED_NETWORK_BEHAVIOR,
    NO_UNREGISTERED_DOMAIN,
    BrowserBehaviorCapture,
    FetchRejected,
    RegisteredScript,
    RegisteredSite,
    ScriptObservation,
    confirm_controlled_sink_log,
    confirm_csp_enforced,
    confirm_hash_matches_trusted,
    confirm_no_prohibited_network_behavior,
    confirm_no_unregistered_domain,
    evaluate,
    fetch_script_observation,
    SRI_PINNED,
    confirm_sri_pinned,
    sri_value,
)
import base64
import hashlib
import socket

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
            observation = fetch_script_observation(script, (host,), now=NOW, allow_private_addresses=True)
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
                fetch_script_observation(script, (host,), now=NOW, allow_private_addresses=True)
        finally:
            server.shutdown()


def fake_resolver(*answers):
    """A resolver that returns a different answer on every call, the
    shape of a DNS-rebinding attack, and counts how often it is asked."""
    calls = []

    def resolve(host, port, type=None):
        address = answers[min(len(calls), len(answers) - 1)]
        calls.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in address]
    resolve.calls = calls
    return resolve


class PinnedFetchTests(unittest.TestCase):
    def test_a_private_address_is_refused_by_default(self):
        server = _serve(_Handler)
        try:
            host, port = server.server_address
            script = RegisteredScript(script_id="local", url=f"http://{host}:{port}/widget.js",
                                      trusted_sha384=(GOOD_SHA384,))
            with self.assertRaises(FetchRejected):
                fetch_script_observation(script, (host,), now=NOW)
        finally:
            server.shutdown()

    def test_a_public_name_that_resolves_to_an_internal_address_is_refused(self):
        resolver = fake_resolver(["10.0.0.5"])
        with self.assertRaises(FetchRejected):
            fetch_script_observation(SCRIPT, ("cdn.vendor.example",), now=NOW, resolver=resolver)

    def test_a_mixed_public_and_private_answer_is_refused_outright(self):
        resolver = fake_resolver(["93.184.216.34", "127.0.0.1"])
        with self.assertRaises(FetchRejected):
            fetch_script_observation(SCRIPT, ("cdn.vendor.example",), now=NOW, resolver=resolver)

    def test_the_name_is_resolved_once_and_the_connection_goes_to_that_address(self):
        # A rebinding resolver answers with the real server first and an
        # internal address on any later lookup. The fetch must resolve
        # once and connect to the first answer; a second lookup at
        # connect time would have been redirected.
        server = _serve(_Handler)
        try:
            host, port = server.server_address
            resolver = fake_resolver([host], ["10.0.0.5"])
            script = RegisteredScript(script_id="local", url=f"http://lab.example:{port}/widget.js",
                                      trusted_sha384=(GOOD_SHA384,))
            observation = fetch_script_observation(script, ("lab.example",), now=NOW,
                                                   allow_private_addresses=True, resolver=resolver)
            self.assertEqual(observation.status_code, 200)
            self.assertEqual(len(resolver.calls), 1)
            self.assertEqual(observation.sha384, hashlib.sha384(_Handler.body).hexdigest())
        finally:
            server.shutdown()

    def test_a_non_200_response_is_not_hashed_as_the_script(self):
        class _NotFound(_Handler):
            def do_GET(self):
                self.send_response(404)
                self.end_headers()
        server = _serve(_NotFound)
        try:
            host, port = server.server_address
            script = RegisteredScript(script_id="local", url=f"http://{host}:{port}/widget.js",
                                      trusted_sha384=(GOOD_SHA384,))
            with self.assertRaises(FetchRejected):
                fetch_script_observation(script, (host,), now=NOW, allow_private_addresses=True)
        finally:
            server.shutdown()


class PinnedHttpsTests(unittest.TestCase):
    """The HTTPS path connects to the pinned address but must still verify
    the server certificate against the registered hostname."""

    @classmethod
    def setUpClass(cls):
        import shutil, subprocess, tempfile
        if not shutil.which("openssl"):
            raise unittest.SkipTest("openssl not available")
        cls.tmp = tempfile.mkdtemp()
        cls.cert, cls.key = f"{cls.tmp}/cert.pem", f"{cls.tmp}/key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=lab.example", "-addext", "subjectAltName=DNS:lab.example",
                        "-keyout", cls.key, "-out", cls.cert], check=True, capture_output=True)

    def _serve_tls(self):
        import ssl
        server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def _client_context(self):
        import ssl
        context = ssl.create_default_context(cafile=self.cert)
        return context

    def test_the_certificate_is_verified_against_the_registered_hostname(self):
        server = self._serve_tls()
        try:
            port = server.server_address[1]
            script = RegisteredScript(script_id="tls", url=f"https://lab.example:{port}/widget.js",
                                      trusted_sha384=(GOOD_SHA384,))
            observation = fetch_script_observation(
                script, ("lab.example",), now=NOW, allow_private_addresses=True,
                resolver=fake_resolver(["127.0.0.1"]), ssl_context=self._client_context())
            self.assertEqual(observation.status_code, 200)
        finally:
            server.shutdown()

    def test_a_certificate_for_a_different_name_is_refused(self):
        server = self._serve_tls()
        try:
            port = server.server_address[1]
            script = RegisteredScript(script_id="tls", url=f"https://other.example:{port}/widget.js",
                                      trusted_sha384=(GOOD_SHA384,))
            with self.assertRaises(FetchRejected):
                fetch_script_observation(
                    script, ("other.example",), now=NOW, allow_private_addresses=True,
                    resolver=fake_resolver(["127.0.0.1"]), ssl_context=self._client_context())
        finally:
            server.shutdown()


class SriTests(unittest.TestCase):
    def test_sri_value_matches_the_browser_format(self):
        digest = hashlib.sha384(b"var x = 1;").digest()
        self.assertEqual(sri_value(digest.hex()), "sha384-" + base64.b64encode(digest).decode())

    def _page(self, attrs):
        return f'<html><body><script src="{SCRIPT.url}" {attrs}></script></body></html>'

    def test_a_trusted_pin_with_crossorigin_passes(self):
        html = self._page(f'integrity="{sri_value(GOOD_SHA384)}" crossorigin="anonymous"')
        evidence = confirm_sri_pinned(SCRIPT, html, NOW, now=NOW)
        self.assertEqual(evidence.assertion, SRI_PINNED)
        self.assertTrue(evidence.observed_pass)

    def test_a_pin_without_crossorigin_does_not_pass(self):
        html = self._page(f'integrity="{sri_value(GOOD_SHA384)}"')
        self.assertFalse(confirm_sri_pinned(SCRIPT, html, NOW, now=NOW).observed_pass)

    def test_a_pin_to_an_untrusted_hash_does_not_pass(self):
        html = self._page(f'integrity="{sri_value(BAD_SHA384)}" crossorigin="anonymous"')
        self.assertFalse(confirm_sri_pinned(SCRIPT, html, NOW, now=NOW).observed_pass)

    def test_no_pin_at_all_does_not_pass(self):
        self.assertFalse(confirm_sri_pinned(SCRIPT, self._page(""), NOW, now=NOW).observed_pass)


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


def capture(*, completed=("cdn.vendor.example",), blocked=(), canary=True, exercised=True):
    return BrowserBehaviorCapture(sent_hosts=tuple(completed), blocked_hosts=tuple(blocked),
                                  canary_observed=canary, exposure_exercised=exercised)


class BehavioralAssertionTests(unittest.TestCase):
    def test_no_prohibited_destination_reached_passes(self):
        evidence = confirm_no_prohibited_network_behavior(SITE, capture(), NOW, now=NOW)
        self.assertTrue(evidence.observed_pass)

    def test_a_prohibited_destination_actually_reached_fails_even_with_a_clean_hash(self):
        # The point of this assertion: an allowlisted-domain script can
        # still cause the browser to reach a prohibited sink. A hash
        # match (tested separately above) says nothing about this.
        evidence = confirm_no_prohibited_network_behavior(
            SITE, capture(completed=("cdn.vendor.example", "attacker.example")), NOW, now=NOW)
        self.assertFalse(evidence.observed_pass)

    def test_an_attempt_the_browser_blocked_counts_as_contained(self):
        evidence = confirm_no_prohibited_network_behavior(
            SITE, capture(blocked=("attacker.example",)), NOW, now=NOW)
        self.assertTrue(evidence.observed_pass)

    def test_an_empty_capture_without_a_canary_is_not_a_pass(self):
        # Instrumentation that recorded nothing must not look like containment.
        evidence = confirm_no_prohibited_network_behavior(
            SITE, capture(completed=(), canary=False), NOW, now=NOW)
        self.assertIsNone(evidence.observed_pass)
        self.assertFalse(evidence.integrity_ok)
        result = assess(evidence.asset, evidence.assertion, [evidence], now=NOW)
        self.assertEqual(result.outcome, Outcome.INDETERMINATE)

    def test_a_trial_that_never_exercised_the_compromised_script_is_not_a_pass(self):
        evidence = confirm_no_prohibited_network_behavior(SITE, capture(exercised=False), NOW, now=NOW)
        result = assess(evidence.asset, evidence.assertion, [evidence], now=NOW)
        self.assertEqual(result.outcome, Outcome.INDETERMINATE)

    def test_sink_log_and_browser_capture_are_two_independent_sources(self):
        browser = confirm_no_prohibited_network_behavior(SITE, capture(), NOW, now=NOW)
        sink = confirm_controlled_sink_log(SITE, 0, NOW, now=NOW)
        result = assess(SITE.site_id, NO_PROHIBITED_NETWORK_BEHAVIOR, [browser, sink],
                        required_independent_checks=2, now=NOW)
        self.assertEqual(result.outcome, Outcome.VERIFIED)

    def test_a_sink_hit_the_browser_capture_missed_still_refutes_containment(self):
        browser = confirm_no_prohibited_network_behavior(SITE, capture(), NOW, now=NOW)
        sink = confirm_controlled_sink_log(SITE, 1, NOW, now=NOW)
        result = assess(SITE.site_id, NO_PROHIBITED_NETWORK_BEHAVIOR, [browser, sink],
                        required_independent_checks=2, now=NOW)
        self.assertEqual(result.outcome, Outcome.NOT_VERIFIED)

    def test_dead_instrumentation_leaves_only_one_source_so_two_required_is_indeterminate(self):
        browser = confirm_no_prohibited_network_behavior(SITE, capture(canary=False), NOW, now=NOW)
        sink = confirm_controlled_sink_log(SITE, 0, NOW, now=NOW)
        result = assess(SITE.site_id, NO_PROHIBITED_NETWORK_BEHAVIOR, [browser, sink],
                        required_independent_checks=2, now=NOW)
        self.assertEqual(result.outcome, Outcome.INDETERMINATE)


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
        behavior_ev = confirm_no_prohibited_network_behavior(SITE, capture(completed=reached), NOW, now=NOW)
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
