"""Replay public attack telemetry through the signed detection intake.

Source: OTRF Security-Datasets, pinned to one repository commit, each
archive pinned by SHA-256 (sources.json). The datasets are recordings of
real attack tools run in a lab against Windows hosts, published for
detection testing, each labelled with the ATT&CK technique it exercises.

For each dataset:

    1. fetch the archive from the commit-pinned URL and refuse it unless
       its SHA-256 matches the pin;
    2. parse it in memory (no extraction to disk), one JSON event per line;
    3. run the registered rules in `endpoint_telemetry`;
    4. map each hit's host to a registered asset (unmapped hosts are
       dropped and counted);
    5. sign each detection with the replay source's own Ed25519 key and
       post it to `intake_server` over TLS;
    6. hand each admitted detection to the re-verification scheduler, which
       must mark that asset due at once (`change_event`).

The recordings are years old, so a replayed detection carries the replay
time as `observed_at` (the intake rejects stale signals by design) and
keeps the original record's digest in its detection ID. The report says so.
"""
from __future__ import annotations

import hashlib
import io
import json
import secrets
import tarfile
import time
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from predict_shield.detection_intake import DetectionEvent, sign_detection, to_reverification_subject_update
from predict_shield.endpoint_telemetry import RULES, detect, technique_matches_label
from predict_shield.verification_cycle import TrackedControl, select_probes

MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 256 * 1024 * 1024
ALLOWED_HOST = "raw.githubusercontent.com"


def fetch_pinned(url: str, sha256: str, *, opener=urllib.request.urlopen) -> bytes:
    if not url.startswith("https://" + ALLOWED_HOST + "/"):
        raise ValueError("dataset URL must be a commit-pinned raw GitHub URL")
    with opener(url, timeout=120) as response:
        data = response.read(MAX_ARCHIVE_BYTES + 1)
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ValueError("archive larger than the registered limit")
    digest = hashlib.sha256(data).hexdigest()
    if digest != sha256:
        raise ValueError(f"archive hash {digest} does not match the pinned {sha256}")
    return data


def archive_format(data: bytes) -> str:
    """From the bytes themselves, never the file name."""
    if data[:4] == b"PK\x03\x04":
        return "zip"
    if data[:2] == b"\x1f\x8b":
        return "tar.gz"
    raise ValueError("archive is neither zip nor gzip")


def events_from_archive(data: bytes, fmt: str | None = None):
    """Yield JSON events from every .json member, read in memory only."""
    fmt = archive_format(data) if fmt is None else fmt
    if fmt == "zip":
        archive = zipfile.ZipFile(io.BytesIO(data))
        members = [(i.filename, i.file_size) for i in archive.infolist() if i.filename.endswith(".json")]
        for name, size in members:
            if size > MAX_MEMBER_BYTES:
                raise ValueError("archive member larger than the registered limit")
            with archive.open(name) as handle:
                for line in io.TextIOWrapper(handle, encoding="utf-8", errors="replace"):
                    if line.strip():
                        yield json.loads(line)
    elif fmt == "tar.gz":
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for member in archive.getmembers():
                if not member.isfile() or not member.name.endswith(".json"):
                    continue
                if member.size > MAX_MEMBER_BYTES:
                    raise ValueError("archive member larger than the registered limit")
                handle = archive.extractfile(member)
                for line in io.TextIOWrapper(handle, encoding="utf-8", errors="replace"):
                    if line.strip():
                        yield json.loads(line)
    else:
        raise ValueError("unsupported archive format " + fmt)


def replay(manifest: dict, *, post, private_key, admitted: list,
           now=lambda: datetime.now(timezone.utc), opener=urllib.request.urlopen) -> dict:
    """`post(envelope) -> int` sends one signed envelope to the intake and
    returns the HTTP status; `admitted` is the list the intake appends to."""
    source = manifest["otrf_security_datasets"]
    host_to_asset = source["host_to_asset"]
    report = {"repository": source["repository"], "commit": source["commit"], "datasets": [],
              "rules": [{"rule_id": r.rule_id, "technique": r.technique, "title": r.title, "reads": list(r.reads)}
                        for r in RULES],
              "observed_at_note": "replay time; the original record digest is in each detection_id"}
    controls = {}
    for dataset in source["datasets"]:
        data = fetch_pinned(dataset["url"], dataset["sha256"], opener=opener)
        events = list(events_from_archive(data, dataset["format"]))
        hits = detect(events)
        agreeing = [h for h in hits if technique_matches_label(h.technique, dataset["labels"])]
        posted, dropped = [], 0
        before = len(admitted)
        for hit in hits:
            asset = host_to_asset.get(hit.host or "")
            if asset is None:
                dropped += 1
                continue
            event = DetectionEvent(
                detection_id=f"otrf:{dataset['id']}:{hit.rule_id}:{hit.event_digest}", asset=asset,
                source_id="otrf-replay", technique=hit.technique,
                confidence=next(r.confidence for r in RULES if r.rule_id == hit.rule_id), observed_at=now())
            posted.append(post(sign_detection(event, secrets.token_hex(16), private_key)))
        newly = admitted[before:]
        due = []
        for item in newly:
            control = controls.get(item.asset) or TrackedControl(
                subject_id=item.asset, asset=item.asset, assertion="endpoint_clean",
                last_verified_at=int(time.time()), risk=0.2)
            subject = to_reverification_subject_update(item, control.subject(), now_seconds=int(time.time()) + 1)
            control = TrackedControl(subject_id=control.subject_id, asset=control.asset, assertion=control.assertion,
                                     last_verified_at=control.last_verified_at, risk=subject.risk,
                                     changed_at=subject.changed_at)
            controls[item.asset] = control
        for asset in {item.asset for item in newly}:
            control = controls[asset]
            for request in select_probes([control], now=int(time.time()) + 1, budget=1, policy="change", interval=3600):
                due.append({"asset": asset, "due_to": request.due_to})
        report["datasets"].append({
            "id": dataset["id"], "title": dataset["title"], "labels": dataset["labels"],
            "archive_sha256_verified": True, "events": len(events), "rule_hits": len(hits),
            "hits_agreeing_with_published_label": len(agreeing),
            "hits_by_rule": {r.rule_id: sum(1 for h in hits if h.rule_id == r.rule_id) for r in RULES},
            "label_detected": bool(agreeing), "dropped_unmapped_host": dropped,
            "post_statuses": posted, "admitted": len(newly),
            "scheduler_due_after_admission": due,
        })
    totals = report["datasets"]
    report["summary"] = {
        "events": sum(d["events"] for d in totals),
        "rule_hits": sum(d["rule_hits"] for d in totals),
        "hits_agreeing_with_label": sum(d["hits_agreeing_with_published_label"] for d in totals),
        "datasets_with_label_detected": sum(1 for d in totals if d["label_detected"]),
        "datasets": len(totals),
        "admitted": sum(d["admitted"] for d in totals),
    }
    return report
