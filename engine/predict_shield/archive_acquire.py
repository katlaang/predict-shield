"""Acquire pinned official EPSS and KEV archive blobs as dated inputs.

No discovery of arbitrary URLs, branch refs, or credentials. Immutable Git SHAs
and dated source metadata must come from a reviewed manifest. The files are
local inputs; downloading them makes no prediction.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import urllib.request
from datetime import date, timedelta
from pathlib import Path

from .threat_intel import read_epss, read_kev

ALLOWED = {"empiricalsec/epss_scores", "cisagov/kev-data"}
MAX_DOWNLOAD = 25 * 1024 * 1024
FIELDS = ("epss", "kev_before", "kev_after")


def _download(url: str) -> bytes:
    request = urllib.request.Request(url, headers={
        "User-Agent": "predict-shield-archive/1",
        "Accept": "application/octet-stream"})
    with urllib.request.urlopen(request, timeout=60) as response:
        raw = response.read(MAX_DOWNLOAD + 1)
    if len(raw) > MAX_DOWNLOAD:
        raise ValueError("Source download larger than registered maximum")
    return raw


def source_url(source: dict) -> str:
    repo = source["repository"]
    commit = source["commit"]
    path = source["path"]
    if repo not in ALLOWED or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Source must use official allowlisted repo and immutable commit SHA")
    if (path.startswith("/") or ".." in Path(path).parts or
            not re.fullmatch(r"[A-Za-z0-9_./-]+", path)):
        raise ValueError("Unsafe source path")
    if repo == "empiricalsec/epss_scores" and not re.fullmatch(
            r"20[0-9]{2}/epss_scores-20[0-9]{2}-[0-9]{2}-[0-9]{2}\.csv\.gz", path):
        raise ValueError("Unexpected official EPSS archive path")
    if repo == "cisagov/kev-data" and path != "known_exploited_vulnerabilities.json":
        raise ValueError("Unexpected CISA KEV archive path")
    return "https://raw.githubusercontent.com/" + repo + "/" + commit + "/" + path


def acquire(manifest: dict, directory: Path, fetcher=None) -> dict:
    if manifest.get("schema") != "predict-shield/dated-threat-archive/1":
        raise ValueError("Unrecognized archival manifest schema")
    fetcher = fetcher or _download
    cutoff = date.fromisoformat(manifest["as_of"])
    horizon_end = cutoff + timedelta(days=int(manifest["horizon_days"]))
    if int(manifest["horizon_days"]) < 1:
        raise ValueError("Horizon must be positive")
    if directory.exists() and any(directory.iterdir()):
        raise FileExistsError("Acquisition destination must be empty")
    directory.mkdir(parents=True, exist_ok=True)
    artifacts = {}
    written = []
    try:
        return _acquire_to_empty_directory(manifest, directory, fetcher, cutoff, horizon_end, artifacts, written)
    except Exception:
        for file in written:
            file.unlink(missing_ok=True)
        raise


def _acquire_to_empty_directory(manifest: dict, directory: Path, fetcher,
                                cutoff: date, horizon_end: date,
                                artifacts: dict, written: list[Path]) -> dict:
    for key in FIELDS:
        source = manifest[key]
        date_value = date.fromisoformat(source["snapshot_date"])
        observed_commit = date.fromisoformat(source["commit_observed_date"])
        if (key != "kev_after" and (date_value > cutoff or observed_commit > cutoff)):
            raise ValueError("Pre-action source or commit is after the as_of date")
        if key == "kev_after" and date_value < horizon_end:
            raise ValueError("Outcome snapshot predates declared horizon end")
        url = source_url(source)
        raw = fetcher(url)
        if not isinstance(raw, bytes) or not raw or len(raw) > MAX_DOWNLOAD:
            raise ValueError("Empty or oversized archive content")
        filename = {"epss": "epss.csv.gz", "kev_before": "kev-before.json",
                    "kev_after": "kev-after.json"}[key]
        path = directory / filename
        if path.exists():
            raise FileExistsError("Archive already exists: refusing overwrite")
        path.write_bytes(raw)
        written.append(path)
        try:
            if key == "epss":
                _, details = read_epss(path, source["snapshot_date"], manifest["as_of"])
            else:
                # Future label snapshot is intentionally not a model feature.
                _, details = read_kev(path, source["snapshot_date"],
                                      source["snapshot_date"])
                decoded = json.loads(raw)
                released = decoded.get("dateReleased")
                if released and date.fromisoformat(released[:10]) > date_value:
                    raise ValueError("KEV embedded release date is newer than declared snapshot")
            artifacts[key] = {"filename": filename, "source_url": url,
                              "source_commit": source["commit"],
                              "sha256": hashlib.sha256(raw).hexdigest(),
                              "record_count": details.get("record_count",
                                      details.get("record_count_as_of"))}
        except Exception:
            path.unlink(missing_ok=True)
            raise
    result = {"schema": "predict-shield/source-acquisition/1",
              "as_of": cutoff.isoformat(), "horizon_end": horizon_end.isoformat(),
              "artifacts": artifacts,
              "note": "Source commits must be independently audited for historical availability; no prediction results."}
    provenance = directory / "acquisition.json"
    if provenance.exists():
        raise FileExistsError("Existing provenance report would be overwritten")
    provenance.write_text(json.dumps(result, indent=2) + "\n")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    manifest = json.loads(Path(args.manifest).read_text())
    summary = acquire(manifest, Path(args.output_dir))
    print(json.dumps({"as_of": summary["as_of"],
                      "sources": list(summary["artifacts"])}))


if __name__ == "__main__":
    main()
