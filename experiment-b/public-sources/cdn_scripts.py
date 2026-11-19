"""Real public CDN files as registered third-party scripts.

Onboarding (attestation). A CDN file becomes a registered script only when
its live bytes match two independent publishers:

    cdnjs     the SRI value cdnjs publishes for that file (api.cdnjs.com)
    jsDelivr  the SHA-256 jsDelivr publishes for the same file in the npm
              package (data.jsdelivr.com)

Both CDNs are fetched; both files must hash to their publisher's value,
and the two files must be byte-identical. Only then is the SHA-384 of
those bytes registered as trusted. Any disagreement refuses registration.

Monitoring. After registration, the existing `fetch_script_observation`
probe runs against the real CDN URL with every default intact: real TLS,
the resolved address pinned, private addresses refused, no redirects.

Browser. A page served on loopback embeds the real cdnjs URL with the
published SRI value; Chromium must run the library. The same page with a
different version's SRI value must be refused by the browser.

Fetching a published library file is the same request every visitor's
browser makes; no site is scanned.
"""
from __future__ import annotations

import base64
import hashlib
import json
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

from predict_shield.script_integrity import (
    RegisteredScript, confirm_hash_matches_trusted, fetch_script_observation, sri_value,
)
from predict_shield.assessment import assess

PUBLISHER_HOSTS = ("api.cdnjs.com", "data.jsdelivr.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net")
MAX_BYTES = 5 * 1024 * 1024


@dataclass(frozen=True)
class CdnFile:
    library: str
    version: str
    cdnjs_file: str
    npm_package: str
    npm_path: str
    browser_global: str

    @property
    def cdnjs_url(self) -> str:
        return f"https://cdnjs.cloudflare.com/ajax/libs/{self.library}/{self.version}/{self.cdnjs_file}"

    @property
    def jsdelivr_url(self) -> str:
        return f"https://cdn.jsdelivr.net/npm/{self.npm_package}@{self.version}{self.npm_path}"


def _get(url: str, opener=urllib.request.urlopen) -> bytes:
    if urlparse(url).hostname not in PUBLISHER_HOSTS or not url.startswith("https://"):
        raise ValueError("not a registered publisher URL: " + url)
    request = urllib.request.Request(url, headers={"User-Agent": "predict-shield-public-sources"})
    with opener(request, timeout=60) as response:
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("response larger than the registered limit")
    return data


def cdnjs_published_sri(entry: CdnFile, opener=urllib.request.urlopen) -> str:
    data = json.loads(_get(f"https://api.cdnjs.com/libraries/{entry.library}/{entry.version}?fields=sri", opener))
    value = (data.get("sri") or {}).get(entry.cdnjs_file)
    if not isinstance(value, str) or "-" not in value:
        raise ValueError("cdnjs publishes no SRI value for " + entry.cdnjs_file)
    return value


def jsdelivr_published_sha256(entry: CdnFile, opener=urllib.request.urlopen) -> str:
    """Base64 SHA-256 jsDelivr publishes for one file. Accepts the flat
    listing ({"files": [{"name", "hash"}]}) and the nested tree listing."""
    data = json.loads(_get(
        f"https://data.jsdelivr.com/v1/packages/npm/{entry.npm_package}@{entry.version}?structure=flat", opener))

    def walk(nodes, prefix=""):
        for node in nodes or []:
            name = node.get("name", "")
            path = name if name.startswith("/") else prefix + "/" + name
            if node.get("type") == "directory" or "files" in node:
                yield from walk(node.get("files"), path)
            else:
                yield path, node.get("hash")

    for path, digest in walk(data.get("files")):
        if path == entry.npm_path and isinstance(digest, str):
            return digest
    raise ValueError("jsDelivr publishes no hash for " + entry.npm_path)


def _sri_matches(sri: str, body: bytes) -> bool:
    algorithm, _, expected = sri.partition("-")
    if algorithm not in ("sha256", "sha384", "sha512"):
        return False
    return base64.b64encode(hashlib.new(algorithm, body).digest()).decode() == expected


@dataclass(frozen=True)
class Attestation:
    entry: CdnFile
    cdnjs_sri: str
    jsdelivr_sha256_b64: str
    cdnjs_bytes_match_cdnjs_sri: bool
    jsdelivr_bytes_match_jsdelivr_hash: bool
    files_identical: bool
    sha384: str

    @property
    def accepted(self) -> bool:
        return self.cdnjs_bytes_match_cdnjs_sri and self.jsdelivr_bytes_match_jsdelivr_hash and self.files_identical


def attest(entry: CdnFile, opener=urllib.request.urlopen) -> Attestation:
    cdnjs_sri = cdnjs_published_sri(entry, opener)
    jsdelivr_hash = jsdelivr_published_sha256(entry, opener)
    cdnjs_body = _get(entry.cdnjs_url, opener)
    jsdelivr_body = _get(entry.jsdelivr_url, opener)
    return Attestation(
        entry=entry, cdnjs_sri=cdnjs_sri, jsdelivr_sha256_b64=jsdelivr_hash,
        cdnjs_bytes_match_cdnjs_sri=_sri_matches(cdnjs_sri, cdnjs_body),
        jsdelivr_bytes_match_jsdelivr_hash=_sri_matches("sha256-" + jsdelivr_hash, jsdelivr_body),
        files_identical=cdnjs_body == jsdelivr_body,
        sha384=hashlib.sha384(cdnjs_body).hexdigest(),
    )


def register(attestation: Attestation) -> RegisteredScript:
    if not attestation.accepted:
        raise ValueError("the two publishers and the live bytes do not agree; not registered")
    e = attestation.entry
    return RegisteredScript(script_id=f"cdnjs:{e.library}@{e.version}/{e.cdnjs_file}",
                            url=e.cdnjs_url, trusted_sha384=(attestation.sha384,))


def monitor(script: RegisteredScript) -> dict:
    """The production probe, defaults intact, against the real CDN."""
    now = datetime.now(timezone.utc)
    observation = fetch_script_observation(script, (urlparse(script.url).hostname,), now=now)
    evidence = confirm_hash_matches_trusted(script, observation, now=now)
    verdict = assess(script.script_id, evidence.assertion, [evidence], now=now)
    return {"script_id": script.script_id, "url": script.url, "outcome": verdict.outcome.value,
            "observed_sha384": observation.sha384}


__all__ = ["CdnFile", "Attestation", "attest", "register", "monitor", "sri_value"]
