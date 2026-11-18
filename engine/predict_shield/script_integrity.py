"""Verifying the integrity of a third-party script a site embeds, and
whether a containment action actually stops it from doing something
prohibited -- not verifying the vendor's source code, which this
pipeline never has access to.

A browser visiting a site downloads whatever the vendor serves at the
registered script URL. That fetch is public by construction: no
credential or access to the vendor's repository is needed to observe
it, only the same unauthenticated HTTP request the visitor's own
browser already makes. This module's checks follow from that fact and
nothing more:

    * fetch the script the operator's own page actually loads, hash it,
      and compare the hash to what was registered as trusted
      (HASH_MATCHES_TRUSTED);
    * compare the set of network destinations a real page load actually
      contacts against a registered allowlist, catching scripts that
      load further script from an undeclared origin or exfiltrate data
      through a request rather than a `<script src>` tag
      (NO_UNREGISTERED_DOMAIN);
    * check whether the site's own Content-Security-Policy response
      header actually restricts script-src, not merely whether one is
      configured somewhere (CSP_ENFORCED);
    * and, the assertion a hash comparison cannot stand in for: whether
      a real browser load, after a containment action is applied, can
      still be made to contact a registered-prohibited destination
      (NO_PROHIBITED_NETWORK_BEHAVIOR). An allowlisted vendor domain can
      itself serve malicious code, and a CSP permitting that domain does
      not by itself stop the script executing with the page's own
      privileges (the browser gives any loaded script the embedding
      page's own origin privileges unless CSP or SRI narrows that). A
      hash returning to a previously-seen value is not evidence the
      prohibited behavior cannot still occur through another path; only
      a real, independently instrumented browser load is.

This module does not perform the network capture or page load itself.
Exactly as `sdn_topology_discovery.py` reads an existing Open vSwitch
report rather than running Mininet, and `regression_check.py` runs a
registered command rather than embedding a test runner, the real
browser instrumentation (Playwright) lives in the pilot
(`experiment-b/real-script-integrity-pilot/`) and in a future live
adapter; this module only defines the evidence shape a real network
capture must have and the checks run against it.

Fail-closed rules carried over from every other check in this pipeline:

    * A script or site is only ever evaluated once registered by the
      operator ahead of time, pinned to an explicit host allowlist. An
      unregistered host is rejected before any fetch is attempted --
      see `_validate_fetch_target` and `_pinned_get` below, which are
      this module's SSRF defense: the fetch target's scheme and
      hostname must exactly match a registered entry; the hostname is
      resolved exactly once, every resolved address is checked, and the
      connection is made to that pinned address, so a DNS answer that
      changes between the check and the fetch (DNS rebinding) cannot
      move the request somewhere else; private, loopback, link-local and
      other non-public addresses are refused unless the registration
      explicitly opts in; and a redirect response is a hard failure
      rather than followed, so an unregistered host can never be reached
      by having the registered one redirect to it.
    * A stale observation (older than `max_age_seconds`) is rejected:
      a past-tense clean hash is not evidence the script is clean now.
    * `evaluate()` adds no new trust and runs no checks itself. It asks
      the existing `assessment.assess()` gate the four required
      questions and combines them with the same all-four-or-nothing
      rule used everywhere else in this pipeline.

What this module does NOT yet do, honestly:

    * Applying a CSP header or an SRI attribute to a real site is a
      containment action gated and applied elsewhere, not by this
      module. This module computes the SRI value for a trusted hash
      (`sri_value`) and checks whether a page actually carries it
      (`confirm_sri_pinned`), and checks whether a CSP already in place
      restricts script-src; the pilot verifies in a real browser what
      each containment does and does not stop.
    * Nothing here crawls a live production site to discover what it
      embeds. `RegisteredSite`/`RegisteredScript` are what the operator
      declares ahead of time, the same registration discipline
      `detection_intake.py` and `sast_findings.py` already require of
      their own sources.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from html.parser import HTMLParser
from datetime import datetime, timezone
from urllib.parse import urlparse

from .assessment import Evidence, Outcome, assess

SOURCE_PREFIX = "script-integrity:"

HASH_MATCHES_TRUSTED = "hash_matches_trusted"
NO_UNREGISTERED_DOMAIN = "no_unregistered_domain"
CSP_ENFORCED = "csp_enforced"
NO_PROHIBITED_NETWORK_BEHAVIOR = "no_prohibited_network_behavior"
# Optional, not part of REQUIRED_ASSERTIONS: SRI is only viable for a
# script that is stable enough to pin and served with CORS (a browser
# refuses a cross-origin SRI check without it), so it is a containment
# option the operator chooses, not a condition every script must meet.
SRI_PINNED = "sri_pinned"

# Every registered third-party script this module evaluates must clear all
# four of these assertions. The fourth is a real, instrumented-browser
# behavioral check, not a second hash comparison: see the module docstring
# for why a hash match cannot stand in for it.
REQUIRED_ASSERTIONS = (
    HASH_MATCHES_TRUSTED,
    NO_UNREGISTERED_DOMAIN,
    CSP_ENFORCED,
    NO_PROHIBITED_NETWORK_BEHAVIOR,
)


class FetchRejected(ValueError):
    """Raised instead of performing a fetch outside the registered target."""


@dataclass(frozen=True)
class RegisteredScript(object):
    """A third-party script URL an operator's own page embeds, registered
    ahead of time. `trusted_sha384` is a tuple, not a single hash, so a
    deliberate, reviewed vendor update can be rolled forward by adding a
    new hash without first having to treat the rollover itself as an
    incident; an unreviewed change is still anything not in this set."""

    script_id: str
    url: str
    trusted_sha384: tuple[str, ...]
    trusted: bool = True

    def validate(self) -> None:
        if not self.script_id or not self.url:
            raise ValueError("script_id and url required")
        parsed = urlparse(self.url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("url must be an absolute http(s) URL")
        if not self.trusted_sha384:
            raise ValueError("trusted_sha384 required: an unpinned script is not reproducible evidence")
        for digest in self.trusted_sha384:
            if len(digest) != 96 or any(c not in "0123456789abcdef" for c in digest.lower()):
                raise ValueError(f"not a sha384 hex digest: {digest!r}")


@dataclass(frozen=True)
class RegisteredSite(object):
    """What an operator's own page is declared to embed and permit.
    `allowed_script_domains` and `prohibited_sinks` are both hostnames,
    never wildcards: an allowlist that accepts a wildcard subdomain is not
    meaningfully different from accepting everything a compromised script
    chooses to register."""

    site_id: str
    allowed_script_domains: tuple[str, ...]
    prohibited_sinks: tuple[str, ...] = ()
    trusted: bool = True

    def validate(self) -> None:
        if not self.site_id:
            raise ValueError("site_id required")
        for domain in self.allowed_script_domains:
            if "*" in domain:
                raise ValueError("allowed_script_domains must be exact hostnames, not wildcards")


@dataclass(frozen=True)
class ScriptObservation(object):
    """One independent fetch of a registered script, at one point in time."""

    script_id: str
    sha384: str
    status_code: int
    fetched_at: datetime


MAX_FETCH_BYTES = 10 * 1024 * 1024


def _validate_fetch_target(url: str, allowed_hosts: tuple[str, ...]) -> None:
    """First half of the SSRF defense: the fetch target's scheme and
    hostname must exactly match a registration the operator supplied
    ahead of time. The second half, in `_pinned_get`, vets the resolved
    address and connects only to it."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise FetchRejected(f"refusing to fetch non-http(s) scheme: {parsed.scheme!r}")
    if parsed.hostname not in allowed_hosts:
        raise FetchRejected(f"refusing to fetch unregistered host: {parsed.hostname!r}")


def _address_is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
                or ip.is_reserved or ip.is_unspecified)


def _resolve_once(hostname: str, port: int, *, allow_private_addresses: bool, resolver) -> str:
    """Resolve the hostname exactly once and return the single address the
    fetch will connect to. Every address in the answer is checked, not
    only the first: an answer that mixes a public and a private address
    is refused outright rather than trusted to pick the public one."""
    try:
        answers = resolver(hostname, port, type=socket.SOCK_STREAM)
    except OSError as error:
        raise FetchRejected(f"could not resolve {hostname!r}: {error}") from error
    addresses = [info[4][0] for info in answers]
    if not addresses:
        raise FetchRejected(f"no address for {hostname!r}")
    if not allow_private_addresses:
        refused = [a for a in addresses if not _address_is_public(a)]
        if refused:
            raise FetchRejected(f"refusing non-public address for {hostname!r}: {refused}")
    return addresses[0]


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, pinned_address, port, timeout):
        super().__init__(host, port, timeout=timeout)
        self._pinned_address = pinned_address

    def connect(self):
        self.sock = socket.create_connection((self._pinned_address, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connects to the pinned address but still verifies the certificate
    against the registered hostname (SNI and hostname check use `host`)."""

    def __init__(self, host, pinned_address, port, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned_address = pinned_address
        self._pinned_context = context

    def connect(self):
        raw = socket.create_connection((self._pinned_address, self.port), self.timeout)
        self.sock = self._pinned_context.wrap_socket(raw, server_hostname=self.host)


def _pinned_get(url: str, allowed_hosts: tuple[str, ...], *, timeout: float,
                allow_private_addresses: bool, resolver=socket.getaddrinfo,
                ssl_context: ssl.SSLContext | None = None) -> tuple[int, dict[str, str], bytes]:
    _validate_fetch_target(url, allowed_hosts)
    parsed = urlparse(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    address = _resolve_once(parsed.hostname, port, allow_private_addresses=allow_private_addresses,
                            resolver=resolver)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    if parsed.scheme == "https":
        connection = _PinnedHTTPSConnection(parsed.hostname, address, port, timeout,
                                            ssl_context or ssl.create_default_context())
    else:
        connection = _PinnedHTTPConnection(parsed.hostname, address, port, timeout)
    try:
        connection.request("GET", path, headers={"User-Agent": "predict-shield-script-integrity/1"})
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise FetchRejected(
                f"refusing to follow redirect ({response.status}) to {response.getheader('Location')!r}")
        body = response.read(MAX_FETCH_BYTES + 1)
        if len(body) > MAX_FETCH_BYTES:
            raise FetchRejected("response exceeds the maximum fetch size")
        headers = {k.lower(): v for k, v in response.getheaders()}
        return response.status, headers, body
    except (OSError, http.client.HTTPException) as error:
        raise FetchRejected(f"fetch failed: {error}") from error
    finally:
        connection.close()


def fetch_script_observation(
    script: RegisteredScript, allowed_hosts: tuple[str, ...], *,
    timeout: float = 10.0, now: datetime | None = None,
    allow_private_addresses: bool = False, resolver=socket.getaddrinfo,
    ssl_context: ssl.SSLContext | None = None,
) -> ScriptObservation:
    """Fetch the registered script for real and hash what was actually
    served. This is the same unauthenticated request a visiting browser
    already makes; no vendor access or credential is used or required.

    `allow_private_addresses` must be set explicitly to fetch a script
    hosted on a private or loopback address, as the pilot's own lab
    servers are; it is off by default so a public registration that
    starts resolving to an internal address is refused, not fetched."""
    if now is None:
        now = datetime.now(timezone.utc)
    script.validate()
    status, _, body = _pinned_get(script.url, allowed_hosts, timeout=timeout,
                                  allow_private_addresses=allow_private_addresses, resolver=resolver,
                                  ssl_context=ssl_context)
    if status != 200:
        raise FetchRejected(f"script fetch returned HTTP {status}")
    digest = hashlib.sha384(body).hexdigest()
    return ScriptObservation(script_id=script.script_id, sha384=digest, status_code=status, fetched_at=now)


def fetch_response_headers(
    url: str, allowed_hosts: tuple[str, ...], *, timeout: float = 10.0,
    allow_private_addresses: bool = False, resolver=socket.getaddrinfo,
) -> dict[str, str]:
    """Fetch a page's own response headers for real, for the CSP check.
    Same SSRF defense as `fetch_script_observation`."""
    status, headers, _ = _pinned_get(url, allowed_hosts, timeout=timeout,
                                     allow_private_addresses=allow_private_addresses, resolver=resolver)
    if status != 200:
        raise FetchRejected(f"page fetch returned HTTP {status}")
    return headers


def fetch_page(
    url: str, allowed_hosts: tuple[str, ...], *, timeout: float = 10.0,
    allow_private_addresses: bool = False, resolver=socket.getaddrinfo,
) -> tuple[dict[str, str], str]:
    """Fetch a page's headers and HTML for real, for the CSP and SRI checks."""
    status, headers, body = _pinned_get(url, allowed_hosts, timeout=timeout,
                                        allow_private_addresses=allow_private_addresses, resolver=resolver)
    if status != 200:
        raise FetchRejected(f"page fetch returned HTTP {status}")
    return headers, body.decode("utf-8", errors="replace")


def _csp_restricts_script_src(header_value: str | None, allowed_domains: tuple[str, ...]) -> bool:
    """A CSP is only "enforced" here if it actually names a script-src (or
    falls back to default-src) directive, contains no bare wildcard, and
    every host it names is one the operator registered. A header that
    merely exists but still allows '*' or an unregistered host is not
    a pass: that would be checking for the header's presence, not its
    effect."""
    if not header_value:
        return False
    directives = {}
    for part in header_value.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives[tokens[0].lower()] = tokens[1:]
    script_src = directives.get("script-src", directives.get("default-src"))
    if not script_src:
        return False
    for token in script_src:
        token = token.strip("'\"")
        if token in ("*", "unsafe-inline", "unsafe-eval", "data:"):
            return False
        if token == "self":
            continue
        # A CSP source may carry an explicit port (meaningful for a lab
        # target running on a non-default port); registration is by
        # hostname only, so match on the host part and require an exact
        # hostname match, never a suffix or wildcard match.
        host = token.rsplit(":", 1)[0] if token.count(":") == 1 else token
        if host not in allowed_domains:
            return False
    return True


def confirm_hash_matches_trusted(
    script: RegisteredScript, observation: ScriptObservation, *,
    now: datetime | None = None, max_age_seconds: float = 900.0,
) -> Evidence:
    if now is None:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    script.validate()
    if not script.trusted:
        raise ValueError("script is not a registered, trusted source")
    if observation.script_id != script.script_id:
        raise ValueError("observation does not match the registered script")
    if observation.fetched_at.tzinfo is None:
        raise ValueError("observation timestamp must be timezone-aware")
    age = (now - observation.fetched_at).total_seconds()
    if age < 0 or age > max_age_seconds:
        raise ValueError("observation is stale or from the future")
    return Evidence(
        asset=script.script_id, assertion=HASH_MATCHES_TRUSTED,
        observed_pass=observation.sha384.lower() in {h.lower() for h in script.trusted_sha384},
        observed_at=observation.fetched_at, source=SOURCE_PREFIX + "fetch-probe", independent=True,
    )


def confirm_no_unregistered_domain(
    site: RegisteredSite, observed_domains: tuple[str, ...], observed_at: datetime, *,
    now: datetime | None = None, max_age_seconds: float = 900.0,
) -> Evidence:
    """`observed_domains` is the set of network destinations a real,
    instrumented browser load actually contacted while rendering the
    site -- every request, fetch/XHR/sendBeacon call and dynamically
    injected script included, not only the domains named in the page's
    static `<script src>` tags, which a compromised script can trivially
    bypass by loading or exfiltrating through a request instead."""
    if now is None:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    site.validate()
    if not site.trusted:
        raise ValueError("site is not a registered, trusted source")
    if observed_at.tzinfo is None:
        raise ValueError("observed_at must be timezone-aware")
    age = (now - observed_at).total_seconds()
    if age < 0 or age > max_age_seconds:
        raise ValueError("domain observation is stale or from the future")
    allowed = set(site.allowed_script_domains)
    unregistered = tuple(sorted(set(observed_domains) - allowed))
    return Evidence(
        asset=site.site_id, assertion=NO_UNREGISTERED_DOMAIN,
        observed_pass=not unregistered,
        observed_at=observed_at, source=SOURCE_PREFIX + "network-capture", independent=True,
    )


def confirm_csp_enforced(
    site: RegisteredSite, header_value: str | None, observed_at: datetime, *,
    now: datetime | None = None, max_age_seconds: float = 900.0,
) -> Evidence:
    if now is None:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    site.validate()
    if observed_at.tzinfo is None:
        raise ValueError("observed_at must be timezone-aware")
    age = (now - observed_at).total_seconds()
    if age < 0 or age > max_age_seconds:
        raise ValueError("header observation is stale or from the future")
    return Evidence(
        asset=site.site_id, assertion=CSP_ENFORCED,
        observed_pass=_csp_restricts_script_src(header_value, site.allowed_script_domains),
        observed_at=observed_at, source=SOURCE_PREFIX + "header-probe", independent=True,
    )


def sri_value(trusted_sha384_hex: str) -> str:
    """The Subresource Integrity attribute value for a trusted SHA-384
    digest, in the form a browser checks: "sha384-" plus the base64 of
    the raw digest."""
    raw = bytes.fromhex(trusted_sha384_hex)
    if len(raw) != 48:
        raise ValueError("not a sha384 digest")
    return "sha384-" + base64.b64encode(raw).decode("ascii")


class _ScriptTagParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags: list[dict] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script":
            self.tags.append({k.lower(): (v or "") for k, v in attrs})


def confirm_sri_pinned(
    script: RegisteredScript, page_html: str, observed_at: datetime, *,
    now: datetime | None = None, max_age_seconds: float = 900.0,
) -> Evidence:
    """Whether the operator's own page actually embeds the registered
    script with an `integrity` attribute naming a trusted hash, and with
    `crossorigin` set, without which a browser does not perform the
    check for a cross-origin script. A tag missing either attribute, or
    pinned only to a hash outside the trusted set, does not pass. This
    checks that the pin is present; whether the browser then refuses a
    tampered script is a separate, behavioral question the pilot answers
    in a real browser."""
    now = _check_age(observed_at, now, max_age_seconds, "page observation")
    script.validate()
    parser = _ScriptTagParser()
    parser.feed(page_html)
    trusted = {sri_value(h.lower()) for h in script.trusted_sha384}
    pinned = False
    for tag in parser.tags:
        if tag.get("src") != script.url:
            continue
        values = set(tag.get("integrity", "").split())
        pinned = bool(values) and values <= trusted and "crossorigin" in tag
        if not pinned:
            break
    return Evidence(
        asset=script.script_id, assertion=SRI_PINNED, observed_pass=pinned,
        observed_at=observed_at, source=SOURCE_PREFIX + "page-markup-probe", independent=True,
    )


@dataclass(frozen=True)
class BrowserBehaviorCapture(object):
    """What one real, instrumented browser trial observed.

    `sent_hosts` are destinations a request actually left the browser
    for, whether or not a usable response came back; `blocked_hosts` are
    destinations the browser refused to send a request to at all (for
    example a Content-Security-Policy block). The distinction matters: a
    request that failed after it was sent (an aborted or opaque-response
    failure) has still delivered whatever it carried, so it belongs in
    `sent_hosts`, never in `blocked_hosts`. The pilot found exactly this
    case -- an exfiltration request the browser reported as failed while
    the destination server logged it as received.

    The two liveness fields exist because an empty capture is not
    evidence of anything:

        * `canary_observed`: a page-owned, known-benign request was
          captured during this same trial. Without it, "no prohibited
          request was seen" could simply mean the instrumentation was not
          recording.
        * `exposure_exercised`: the script under test (for a containment
          trial, the compromised version) was actually live at the
          registered URL during this trial, confirmed independently of the
          browser (for example by the fetch probe's own hash), and the
          browser attempted to load it. Without it, "no prohibited request
          was seen" could simply mean the malicious code was never present
          to try. A load the browser attempted and the containment then
          blocked still counts as exercised: that is the containment
          working, not the test failing to run.

    Either one missing makes the trial uninformative, not a pass.
    """

    sent_hosts: tuple[str, ...]
    blocked_hosts: tuple[str, ...]
    canary_observed: bool
    exposure_exercised: bool


def _check_age(observed_at: datetime, now: datetime | None, max_age_seconds: float, what: str) -> datetime:
    if now is None:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if observed_at.tzinfo is None:
        raise ValueError("observed_at must be timezone-aware")
    age = (now - observed_at).total_seconds()
    if age < 0 or age > max_age_seconds:
        raise ValueError(f"{what} is stale or from the future")
    return now


def confirm_no_prohibited_network_behavior(
    site: RegisteredSite, capture: BrowserBehaviorCapture, observed_at: datetime, *,
    now: datetime | None = None, max_age_seconds: float = 900.0,
) -> Evidence:
    """The behavioral check a hash comparison cannot replace: in a real,
    instrumented browser trial, after whatever containment action was
    applied, did the page still reach a registered-prohibited destination.

    Three outcomes, never two:

        * reached a prohibited destination -> observed_pass False;
        * instrumentation not shown live (no canary) or the compromised
          script never exercised -> no pass/fail at all
          (`observed_pass=None`, `integrity_ok=False`), which
          `assessment.assess()` can only ever report as INDETERMINATE;
        * live instrumentation, exercised exposure, and no prohibited
          destination reached (an attempt the browser blocked counts as
          contained, not reached) -> observed_pass True.

    `capture` must come from an actual page load with network capture
    (the pilot's Playwright instrumentation, or a future live adapter),
    never from re-deriving the answer from the script's hash or text."""
    now = _check_age(observed_at, now, max_age_seconds, "behavioral observation")
    site.validate()
    uninformative = not capture.canary_observed or not capture.exposure_exercised
    if uninformative:
        return Evidence(
            asset=site.site_id, assertion=NO_PROHIBITED_NETWORK_BEHAVIOR,
            observed_pass=None, observed_at=observed_at,
            source=SOURCE_PREFIX + "browser-behavior-probe", independent=True, integrity_ok=False,
        )
    reached = set(site.prohibited_sinks) & set(capture.sent_hosts)
    return Evidence(
        asset=site.site_id, assertion=NO_PROHIBITED_NETWORK_BEHAVIOR,
        observed_pass=not reached, observed_at=observed_at,
        source=SOURCE_PREFIX + "browser-behavior-probe", independent=True,
    )


def confirm_controlled_sink_log(
    site: RegisteredSite, sink_hit_count: int, observed_at: datetime, *,
    now: datetime | None = None, max_age_seconds: float = 900.0,
) -> Evidence:
    """A second, independent source for the same behavioral assertion,
    available only in a controlled adversary simulation where the
    prohibited destination is a server the operator runs: that server's
    own record of whether anything reached it. It does not depend on the
    browser's instrumentation at all, so it catches a capture that missed
    a request, and the browser capture catches a sink log that was not
    recording. In a live deployment the attacker's server is not
    observable and this source does not exist; the browser capture
    stands alone there."""
    now = _check_age(observed_at, now, max_age_seconds, "sink log observation")
    site.validate()
    if sink_hit_count < 0:
        raise ValueError("sink_hit_count cannot be negative")
    return Evidence(
        asset=site.site_id, assertion=NO_PROHIBITED_NETWORK_BEHAVIOR,
        observed_pass=sink_hit_count == 0, observed_at=observed_at,
        source=SOURCE_PREFIX + "controlled-sink-log", independent=True,
    )


@dataclass(frozen=True)
class ScriptIntegrityVerdict(object):
    accepted: bool
    assessments: dict

    @property
    def blocking_reasons(self) -> tuple[str, ...]:
        return tuple(
            f"{name}: {assessment.outcome.value} -- {assessment.reason}"
            for name, assessment in self.assessments.items()
            if assessment.outcome is not Outcome.VERIFIED
        )


def evaluate(scope: dict, evidence: list, **assess_kwargs) -> ScriptIntegrityVerdict:
    """Evaluate all four required assertions for one third-party script
    and report whether it is accepted as a whole, following the same
    all-four-or-nothing rule `sast_findings.evaluate_fix()` and
    `remediation_verification.evaluate()` use."""
    missing = [name for name in REQUIRED_ASSERTIONS if name not in scope]
    if missing:
        raise ValueError("Missing required assertion scope for: " + ", ".join(missing))
    assessments = {
        name: assess(*scope[name], evidence, **assess_kwargs)
        for name in REQUIRED_ASSERTIONS
    }
    accepted = all(a.outcome is Outcome.VERIFIED for a in assessments.values())
    return ScriptIntegrityVerdict(accepted, assessments)
