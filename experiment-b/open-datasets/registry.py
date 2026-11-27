"""Pin, gate, inspect, and correlate independently sourced security archives.

No dataset may be counted as a completed experiment merely because the
publisher made a file downloadable. Raw records never enter this repository.
"""
from __future__ import annotations

import argparse
import bisect
import datetime as dt
import hashlib
import json
import os
import re
import tempfile
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_REGISTRY = HERE / "registry.json"
APPROVED_LICENSES = {"CC-BY-4.0", "MIT"}
# Research-only licenses, allowed per named dataset. Such data is analysed locally by the owner's copy,
# never downloaded in CI, never committed and never redistributed in any form; only aggregate results leave it.
RESEARCH_ONLY = {"CC-BY-NC-ND-4.0": {"biblio-us17"}}
MAX_READ_MEMBER = 64 * 1024 * 1024
MAX_EVENTS = 10_000
MAX_PAIRS = 10_000


def validate_registry(reg: dict) -> None:
    if reg.get("schema") != "predict-shield/dataset-registry/1":
        raise ValueError("unknown registry schema")
    ids = set()
    for entry in reg.get("datasets", []):
        ident = entry["id"]
        if ident in ids:
            raise ValueError("duplicate dataset id")
        ids.add(ident)
        if not entry.get("collection_environment") or not entry.get("url"):
            raise ValueError("missing provenance")
        lic = entry.get("license")
        if lic in RESEARCH_ONLY and (ident not in RESEARCH_ONLY[lic] or entry.get("redistribution") != "never"
                                     or any(f.get("ci_default") for f in entry.get("files", []))):
            raise ValueError("research-only license outside its named dataset or terms")
        for file in entry.get("files", []):
            if Path(file["name"]).name != file["name"] or not file["name"]:
                raise ValueError("unsafe dataset file name")
            digests = [file[k] for k in ("md5", "sha256") if k in file]
            if len(digests) != 1:
                raise ValueError("exactly one published digest per file required")
            digest = digests[0]
            if not re.fullmatch(r"[a-f0-9]{32}" if "md5" in file else r"[a-f0-9]{64}", digest):
                raise ValueError("invalid publisher digest")
            if file.get("ci_default") and (
                entry.get("license") not in APPROVED_LICENSES or
                file.get("approx_mb") is None or file["approx_mb"] > reg["policy"]["max_automatic_download_mb"]
            ):
                raise ValueError("unlicensed or oversized default CI source")
    if not ids:
        raise ValueError("empty registry")


def get_registry(path: Path = DEFAULT_REGISTRY) -> dict:
    registry = json.loads(path.read_text(encoding="utf-8"))
    validate_registry(registry)
    return registry


def lookup(reg: dict, dataset_id: str, filename: str) -> tuple[dict, dict]:
    dataset = next((d for d in reg["datasets"] if d["id"] == dataset_id), None)
    if dataset is None:
        raise ValueError("dataset not registered")
    if dataset.get("license") not in APPROVED_LICENSES:
        raise ValueError("dataset license or reuse rights unresolved")
    if not dataset.get("zenodo_record"):
        raise ValueError("no publisher download record")
    file = next((f for f in dataset["files"] if f["name"] == filename), None)
    if file is None:
        raise ValueError("file or pinned hash not registered")
    return dataset, file


def digest_file(path: Path, name: str) -> str:
    h = hashlib.new(name)
    with open(path, "rb") as src:
        for chunk in iter(lambda: src.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_file(path: Path, entry: dict) -> dict:
    typ = "sha256" if "sha256" in entry else "md5"
    actual = digest_file(path, typ)
    if actual != entry[typ]:
        raise ValueError("archive digest differs from publisher pin")
    return {"file": path.name, "algorithm": typ, "expected": entry[typ],
            "actual": actual, "sha256": digest_file(path, "sha256"),
            "bytes": path.stat().st_size, "verified": True}


def download(reg: dict, dataset_id: str, filename: str, output: Path,
             max_mb: int = 25, opener=None) -> dict:
    dataset, pinned = lookup(reg, dataset_id, filename)
    if max_mb < 1 or max_mb > 4096:
        raise ValueError("max download must be between 1 and 4096 MB")
    cap = max_mb * 1024 * 1024
    if pinned.get("approx_mb") is not None and pinned["approx_mb"] > max_mb:
        raise ValueError("file exceeds explicitly authorized download size")
    if output.exists():
        raise ValueError("will not overwrite a preexisting artifact")
    output.parent.mkdir(parents=True, exist_ok=True)
    url = (f"https://zenodo.org/api/records/{dataset['zenodo_record']}/files/"
           f"{urllib_parse_quote(filename)}/content")
    requester = opener or urllib.request.urlopen
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix=".dataset-", delete=False) as dest:
            tmp = Path(dest.name)
            with requester(urllib.request.Request(url, headers={"User-Agent": "predict-shield-dataset-verifier/1"}),
                           timeout=45) as source:
                amount = 0
                while chunk := source.read(1024 * 1024):
                    amount += len(chunk)
                    if amount > cap:
                        raise ValueError("publisher download exceeded authorized byte budget")
                    dest.write(chunk)
        evidence = verify_file(tmp, pinned)
        os.replace(tmp, output)
        return {**evidence, "file": str(output), "dataset": dataset_id,
                "environment": dataset["collection_environment"], "publisher_url": dataset["url"]}
    finally:
        if tmp is not None and tmp.exists():
            tmp.unlink()


def urllib_parse_quote(value: str) -> str:
    from urllib.parse import quote
    return quote(value, safe="")


def safe_zip_member(z: zipfile.ZipFile, name: str):
    if name not in z.namelist():
        raise ValueError("archive does not contain the explicitly selected member")
    member = z.getinfo(name)
    parts = Path(name).parts
    if name.startswith("/") or ".." in parts or member.is_dir():
        raise ValueError("unsafe or nonfile archive member")
    if member.file_size > MAX_READ_MEMBER:
        raise ValueError("member too large for bounded inspection")
    return member


def archive_index(archive: Path) -> dict:
    with zipfile.ZipFile(archive) as z:
        entries = []
        for info in z.infolist():
            if info.is_dir():
                continue
            n = info.filename.lower()
            if "attackmate" in n:
                role = "attack_timeline"
            elif "eve.json" in n or "suricata" in n:
                role = "network"
            elif "wazuh" in n:
                role = "host"
            else:
                continue
            entries.append({"member": info.filename, "bytes": info.file_size, "candidate_role": role})
    return {"sha256": digest_file(archive, "sha256"), "candidates": entries,
            "warning": "Filename classification only; verify schema before use."}


def time_value(value: str) -> float:
    if isinstance(value, (float, int)):
        return float(value)
    if not isinstance(value, str) or not value:
        raise ValueError("missing timestamp")
    stamp = value.replace("Z", "+00:00")
    parsed = dt.datetime.fromisoformat(stamp)
    if parsed.tzinfo is None:
        raise ValueError("naive timestamps are not admissible")
    return parsed.timestamp()


def addresses(value: dict) -> set[str]:
    data = value.get("data") or {}
    if not isinstance(data, dict):
        data = {}
    values = (value.get("src_ip"), value.get("dest_ip"), value.get("srcip"),
              value.get("dstip"), data.get("srcip"), data.get("dstip"),
              data.get("src_ip"), data.get("dest_ip"))
    return {str(v) for v in values if isinstance(v, str) and v}


def read_json_lines(z: zipfile.ZipFile, member: str) -> list[dict]:
    safe_zip_member(z, member)
    events = []
    with z.open(member) as f:
        for raw in f:
            if not raw.strip():
                continue
            if len(events) >= MAX_EVENTS:
                raise ValueError("too many events; use smaller bounded scenario")
            try:
                item = json.loads(raw)
            except (ValueError, UnicodeDecodeError) as exc:
                raise ValueError("member is not JSONL telemetry") from exc
            if not isinstance(item, dict):
                raise ValueError("telemetry records must be objects")
            item_time = item.get("timestamp") or item.get("@timestamp")
            try:
                time_v = time_value(item_time)
            except ValueError:
                continue
            events.append({"time": time_v, "ips": addresses(item), "event": item})
    return events


def correlate(archive: Path, host_member: str, network_member: str,
              seconds: float = 5.0) -> dict:
    if seconds <= 0 or seconds > 120:
        raise ValueError("invalid correlation window")
    if host_member == network_member:
        raise ValueError("independent host and network members required")
    with zipfile.ZipFile(archive) as z:
        host = read_json_lines(z, host_member)
        network = read_json_lines(z, network_member)
    # Sort by time to avoid an unbounded all-to-all comparison. Refuse more
    # than MAX_PAIRS outputs rather than truncate or exhaust CI memory.
    indexed = sorted(enumerate(network), key=lambda item: item[1]["time"])
    net_times = [row["time"] for _, row in indexed]
    pairs = []
    for i, h in enumerate(host):
        if not h["ips"]:
            continue
        left = bisect.bisect_left(net_times, h["time"] - seconds)
        right = bisect.bisect_right(net_times, h["time"] + seconds)
        for j, n in indexed[left:right]:
            shared = sorted(h["ips"] & n["ips"])
            if shared:
                if len(pairs) >= MAX_PAIRS:
                    raise ValueError("correlation pair budget exceeded; narrow the window or sample by capture")
                pairs.append({"host_event": i, "network_event": j,
                              "time_delta_s": round(h["time"] - n["time"], 4),
                              "shared_ips": shared, "ground_truth": "UNKNOWN"})
    return {"schema": "predict-shield/cam-correlation-exploration/1",
            "source_archive_sha256": digest_file(archive, "sha256"),
            "collection_environment": "ait-attackbed-virtual-enterprise",
            "host_member": host_member, "network_member": network_member,
            "host_events": len(host), "network_events": len(network),
            "time_window_s": seconds, "cooccurring_pairs": len(pairs),
            "pairs": pairs, "ground_truth": "UNKNOWN",
            "detection_accuracy": None, "false_positive_rate": None,
            "warning": "Co-occurrence is NOT evidence of attack, causal linkage, or model superiority."}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate")
    sub.add_parser("list")
    down = sub.add_parser("download")
    down.add_argument("--dataset", required=True)
    down.add_argument("--file", required=True)
    down.add_argument("--output", required=True, type=Path)
    down.add_argument("--max-mb", type=int, default=25)
    insp = sub.add_parser("inspect")
    insp.add_argument("--archive", required=True, type=Path)
    cor = sub.add_parser("correlate")
    cor.add_argument("--archive", required=True, type=Path)
    cor.add_argument("--host-member", required=True)
    cor.add_argument("--network-member", required=True)
    cor.add_argument("--seconds", type=float, default=5.0)
    cor.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    reg = get_registry(args.registry)
    if args.command == "validate":
        result = {"valid": True, "datasets": len(reg["datasets"])}
    elif args.command == "list":
        result = [{k: d.get(k) for k in ("id", "license", "status", "collection_environment", "evaluation_role")}
                  for d in reg["datasets"]]
    elif args.command == "download":
        result = download(reg, args.dataset, args.file, args.output, args.max_mb)
    elif args.command == "inspect":
        result = archive_index(args.archive)
    else:
        result = correlate(args.archive, args.host_member, args.network_member, args.seconds)
        if args.output.exists():
            raise ValueError("will not overwrite previous investigation")
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
