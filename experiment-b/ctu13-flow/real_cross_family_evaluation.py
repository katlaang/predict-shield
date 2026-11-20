"""Acquire ONLY preregistered publisher CTU-13 text flow files and measure.

First acquisition is exploratory because original file SHA-256 values were
not registered in advance. Freeze their measured hashes in a separate
reviewed commit before claiming a subsequent hash-locked evaluation.
No binary malware, pcap replay, target scans, or live network actuation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

from unsupervised_detector import fit_and_evaluate

HERE = pathlib.Path(__file__).resolve().parent
PROTOCOL = HERE / "cross_family_protocol.json"
MAX_FILE = 900_000_000
ALLOWED_HOST = "mcfp.felk.cvut.cz"
ALLOWED_PREFIX = "/publicDatasets/CTU-Malware-Capture-Botnet-"
CHUNK = 1024 * 1024


def registered_sources(protocol: dict) -> list[dict]:
    if protocol.get("schema") != "predict-shield/ctu13-published-cross-family-source-registration/1":
        raise ValueError("Wrong frozen source registration")
    sources = protocol.get("sources")
    if not isinstance(sources, list) or len(sources) != 3:
        raise ValueError("Exactly three preregistered scenarios required")
    if {(r["scenario_id"], r["split"], r["family"]) for r in sources} != {
            ("CTU-45", "train", "Rbot"), ("CTU-52", "calibration", "Rbot"),
            ("CTU-53", "test", "NSIS.ay")}:
        raise ValueError("Registered family-separated experiment changed")
    paths = set()
    for src in sources:
        parsed = urlparse(src["url"])
        if (parsed.scheme != "https" or parsed.hostname != ALLOWED_HOST or
                parsed.port is not None or parsed.query or parsed.fragment or
                not parsed.path.startswith(ALLOWED_PREFIX) or
                not parsed.path.endswith(".binetflow")):
            raise ValueError("Nonpublisher or executable download URL rejected")
        basename = src["file"]
        if not isinstance(basename, str) or pathlib.Path(basename).name != basename or (
                not basename.endswith(".binetflow") or basename in paths):
            raise ValueError("Unsafe or duplicate output file")
        paths.add(basename)
    if protocol.get("sample_cap_per_label_per_scenario") != 2000 or (
            protocol.get("max_calibration_sample_false_positive_rate") != 0.05):
        raise ValueError("Frozen sampling or threshold budget changed")
    return sources


def download(url: str, target: pathlib.Path, *, max_bytes: int = MAX_FILE) -> dict:
    """Digest stream before any CSV parsing. No redirect to unapproved host."""
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(
        context=ssl.create_default_context()))
    class RefuseExternalRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            p = urlparse(newurl)
            if p.scheme != "https" or p.hostname != ALLOWED_HOST:
                raise ValueError("Redirect to unregistered source rejected")
            return super().redirect_request(request, fp, code, msg, headers, newurl)
    opener.add_handler(RefuseExternalRedirect())
    part = target.with_suffix(".partial")
    digest = hashlib.sha256()
    count = 0
    try:
        with opener.open(urllib.request.Request(
                url, headers={"User-Agent": "PREDICT-SHIELD-research/1.0"}),
                timeout=90) as src, part.open("xb") as dst:
            if src.status != 200:
                raise ValueError("Publisher file unavailable")
            if urlparse(src.geturl()).hostname != ALLOWED_HOST:
                raise ValueError("Source host changed")
            while True:
                block = src.read(CHUNK)
                if not block:
                    break
                count += len(block)
                if count > max_bytes:
                    raise ValueError("Source exceeds permitted bound")
                digest.update(block)
                dst.write(block)
        if count < 1024:
            raise ValueError("Truncated or empty source")
        os.replace(part, target)
        return {"bytes": count, "sha256": digest.hexdigest(), "url": url}
    finally:
        part.unlink(missing_ok=True)


def evaluate(protocol: dict, protocol_raw: bytes, data_root: pathlib.Path) -> dict:
    registered = registered_sources(protocol)
    data_root.mkdir(parents=True, exist_ok=False)
    records = []
    entries = []
    for row in registered:
        path = data_root / row["file"]
        measured = download(row["url"], path)
        records.append({**measured, "scenario_id": row["scenario_id"],
                        "split": row["split"], "family": row["family"],
                        "file": row["file"]})
        entries.append({"scenario_id": row["scenario_id"], "split": row["split"],
                        "file": row["file"], "sha256": measured["sha256"]})
    manifest = {
        "schema": "predict-shield/ctu13-flow-protocol/2",
        "sample_cap_per_label_per_scenario": protocol["sample_cap_per_label_per_scenario"],
        "max_calibration_sample_false_positive_rate":
            protocol["max_calibration_sample_false_positive_rate"],
        "scenarios": entries,
    }
    manifest_raw = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    _, bundle, report = fit_and_evaluate(manifest, manifest_raw, data_root)
    # Recheck exact downloaded source bytes after model execution.
    for row in records:
        digest = hashlib.file_digest((data_root / row["file"]).open("rb"), "sha256").hexdigest()
        if digest != row["sha256"]:
            raise ValueError("Local source changed during evaluation")
    return {
        "schema": "predict-shield/real-publisher-ctu13-exploratory/1",
        "protocol_sha256": hashlib.sha256(protocol_raw).hexdigest(),
        "registration_source": "repository_predeclared_split",
        "source_digests_were_precommitted_before_download": False,
        "source_sha256_values_computed_at_first_download": True,
        "publisher_original_files_independently_authenticated": False,
        "measurement_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_license_to_confirm_before_redistribution": True,
        "publisher_files": records,
        "run_time_source_manifest": manifest,
        "model_configuration": bundle,
        "evaluation": report,
        "genuine_external_bytes_downloaded_and_hashed": True,
        "held_out_family": "NSIS.ay",
        "held_out_family_absent_from_fit_and_threshold_calibration": True,
        "previously_unseen_zero_day_attack_established": False,
        "independent_operational_field_effectiveness_established": False,
        "accuracy_claim_status": "EXPLORATORY_PUBLISHER_LABELED_EXTERNAL_BENCHMARK_ONLY",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol", type=pathlib.Path, default=PROTOCOL)
    parser.add_argument("--download-dir", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    raw = args.protocol.read_bytes()
    protocol = json.loads(raw)
    result = evaluate(protocol, raw, args.download_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as f:
        json.dump(result, f, indent=2, sort_keys=True, allow_nan=False)
        f.write("\n")
    print(json.dumps({
        "status": result["accuracy_claim_status"],
        "source_files": len(result["publisher_files"]),
        "test_flows": result["evaluation"]["test_flows"],
        "TP": result["evaluation"]["TP"],
        "FP": result["evaluation"]["FP"],
        "FN": result["evaluation"]["FN"],
        "TN": result["evaluation"]["TN"],
        "sample_recall": result["evaluation"]["test_sample_recall"],
        "sample_fpr": result["evaluation"]["test_sample_false_positive_rate"],
        "no_field_validation_claim": True,
    }))


if __name__ == "__main__":
    main()
