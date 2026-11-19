"""OSV.dev as a live advisory source for the post-fix vulnerability scan.

`post_patch_vulnerability_scan.scan()` asks whether the version a fix
moves *to* is inside any known advisory's affected range. Until now those
ranges were registered by hand. This adapter takes them from OSV.dev, the
open, aggregated vulnerability database (GitHub Advisory Database, npm,
PyPI, Go and others), and adds a second, independent answer: OSV's own
response when asked about that exact version.

`scan_with_osv()` returns:

    VERIFIED-shaped evidence (observed_pass=True)    no advisory covers the
        version by either method;
    NOT VERIFIED-shaped evidence (observed_pass=False) an advisory covers it;
    a failed probe (integrity_ok=False)               the two methods disagree,
        or a range could not be represented exactly, or OSV could not be
        reached. A scan that could not be completed is never a clean result.

Only SEMVER and ECOSYSTEM ranges with introduced/fixed events convert to
`VersionRange`. A `last_affected` or `limit` event, or a GIT range, is
reported as not representable, which fails the scan closed.
"""
from __future__ import annotations

import hashlib
import json
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

from .assessment import Evidence
from .post_patch_vulnerability_scan import ASSERTION, SOURCE, KnownAdvisory, scan
from .versions import UnsupportedVersion, VersionRange

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class NotRepresentable(ValueError):
    pass


def _post(body: dict, opener=urllib.request.urlopen) -> tuple[dict, str]:
    request = urllib.request.Request(OSV_QUERY_URL, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json",
                                              "User-Agent": "predict-shield-osv"})
    with opener(request, timeout=60) as response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("OSV response larger than the registered limit")
    return json.loads(raw or b"{}"), hashlib.sha256(raw).hexdigest()


def query(package: str, ecosystem: str, version: str | None = None, *,
          opener=urllib.request.urlopen) -> tuple[list[dict], str]:
    """All OSV records for the package, or for one exact version. Follows
    OSV's next_page_token. Returns (vulns, sha256 of the first page)."""
    body = {"package": {"name": package, "ecosystem": ecosystem}}
    if version is not None:
        body["version"] = version
    vulns, first_digest = [], None
    while True:
        page, digest = _post(body, opener)
        first_digest = first_digest or digest
        vulns.extend(page.get("vulns") or [])
        token = page.get("next_page_token")
        if not token:
            return vulns, first_digest
        body = dict(body, page_token=token)


def ranges_for(vuln: dict, package: str, ecosystem: str) -> tuple[VersionRange, ...]:
    out = []
    for affected in vuln.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("name") != package or pkg.get("ecosystem") != ecosystem:
            continue
        for r in affected.get("ranges") or []:
            if r.get("type") not in ("SEMVER", "ECOSYSTEM"):
                raise NotRepresentable(f"{vuln.get('id')}: {r.get('type')} range")
            introduced = None
            for event in r.get("events") or []:
                if "introduced" in event:
                    introduced = None if event["introduced"] == "0" else event["introduced"]
                elif "fixed" in event:
                    out.append(VersionRange(introduced, event["fixed"]))
                    introduced = "__closed__"
                else:
                    raise NotRepresentable(f"{vuln.get('id')}: {sorted(event)} event")
            if introduced != "__closed__":
                # an introduced event with no fix: affected from there on
                out.append(VersionRange(introduced if introduced is not None else "0", None))
    return tuple(out)


def known_advisories(vulns: list[dict], package: str, ecosystem: str) -> list[KnownAdvisory]:
    return [KnownAdvisory(advisory_id=v["id"], package=package, ranges=ranges_for(v, package, ecosystem))
            for v in vulns if ranges_for(v, package, ecosystem)]


@dataclass(frozen=True)
class OsvScan:
    evidence: Evidence
    advisories_considered: tuple[str, ...]
    advisories_covering_version: tuple[str, ...]
    osv_version_query_ids: tuple[str, ...]
    response_sha256: str
    reason: str


def scan_with_osv(package: str, ecosystem: str, new_version: str, *, opener=urllib.request.urlopen,
                  now: datetime | None = None) -> OsvScan:
    now = now or datetime.now(timezone.utc)
    asset = package + "@" + new_version

    def failed(reason, considered=(), covering=(), direct=(), digest=""):
        return OsvScan(Evidence(asset=asset, assertion=ASSERTION, observed_pass=None, observed_at=now,
                                source=SOURCE + ":osv", independent=True, integrity_ok=False),
                       tuple(considered), tuple(covering), tuple(direct), digest, reason)

    try:
        all_vulns, digest = query(package, ecosystem, opener=opener)
        direct, _ = query(package, ecosystem, new_version, opener=opener)
    except Exception as exc:  # network or parse failure: not a clean result
        return failed(f"OSV could not be queried: {exc}")
    try:
        advisories = known_advisories(all_vulns, package, ecosystem)
        covering = [a.advisory_id for a in advisories if any(r.contains(new_version) for r in a.ranges)]
    except (NotRepresentable, UnsupportedVersion, ValueError) as exc:
        return failed(f"a range could not be represented exactly: {exc}",
                      [v["id"] for v in all_vulns], digest=digest)
    direct_ids = sorted({v["id"] for v in direct})
    considered = [a.advisory_id for a in advisories]
    if sorted(covering) != direct_ids:
        return failed("range evaluation and OSV's own version query disagree",
                      considered, covering, direct_ids, digest)
    evidence = scan(package, new_version, advisories, now=now)
    return OsvScan(evidence, tuple(considered), tuple(sorted(covering)), tuple(direct_ids), digest,
                   "both methods agree")
