"""Local-only operational telemetry normalization for PREDICT-SHIELD P1.

No network calls, active scanning, threat classification or model training.
It does not infer 'benign' from absence of a recorded attack.
Inputs must have an operator/publisher-authorized source and a pinned SHA256.
Outputs stay local; all source identifiers are keyed-pseudonymized.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import hmac
import json
import os
from pathlib import Path

LANL_AUTH = ("time", "source_user", "destination_user", "source_computer",
             "destination_computer", "authentication_type", "logon_type",
             "authentication_orientation", "result")
LANL_FLOW = ("time", "duration", "source_computer", "source_port", "destination_computer",
             "destination_port", "protocol", "packet_count", "byte_count")
LANL_DNS = ("time", "source_computer", "resolved_computer")
LANL_REDTEAM = ("time", "user", "source_computer", "destination_computer")
# From the publisher's described UGR'16 nfdump CSV projection.
UGR_FLOW = ("te", "td", "sa", "da", "sp", "dp", "pr", "flg", "fwd", "stos", "pkt", "byt")
DATASETS = {
    "lanl-auth": LANL_AUTH,
    "lanl-flow": LANL_FLOW,
    "lanl-dns": LANL_DNS,
    "lanl-redteam": LANL_REDTEAM,
    "ugr16-flow": UGR_FLOW,
}
SOURCE_URL = {
    "lanl-auth": "https://csr.lanl.gov/data/cyber1/",
    "lanl-flow": "https://csr.lanl.gov/data/cyber1/",
    "lanl-dns": "https://csr.lanl.gov/data/cyber1/",
    "lanl-redteam": "https://csr.lanl.gov/data/cyber1/",
    "ugr16-flow": "https://nesg.ugr.es/nesg-ugr16/",
}
HEX = frozenset("0123456789abcdef")
MAX_RAW_LINE = 1_000_000


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1_048_576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _secure_file(path: Path) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Source must be a regular non-symlink file")
    return path.resolve(strict=True)


def _pseudonym(key: bytes, value: str) -> str | None:
    if not value or value == "?":
        return None
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:32]


def _int(value: str, label: str) -> int | None:
    if value == "?":
        return None
    if not value or len(value) > 16 or not value.isascii() or not value.isdecimal():
        raise ValueError(f"Bad integer in {label}")
    out = int(value)
    if out > 2**63 - 1:
        raise ValueError(f"Integer overflow in {label}")
    return out


def _record(data: dict, *, dataset: str, key: bytes, source_digest: str,
            line_number: int, raw_digest: str) -> dict:
    # Keep raw event content OUT of committed evidence and normalizer output.
    common = {
        "schema": "predict-shield/p1-operational-event/1",
        "source": dataset,
        "source_sha256": source_digest,
        "source_line": line_number,
        "raw_line_sha256": raw_digest,
        "label": "unknown",
        "truth_basis": "unverified",
        "verified_attack": False,
    }
    if dataset == "lanl-auth":
        common.update(event_type="authentication",
            time_seconds=_int(data["time"], "time"),
            src_user_id=_pseudonym(key, data["source_user"]),
            dst_user_id=_pseudonym(key, data["destination_user"]),
            source_asset_id=_pseudonym(key, data["source_computer"]),
            destination_asset_id=_pseudonym(key, data["destination_computer"]),
            auth_type=data["authentication_type"][:64],
            logon_type=data["logon_type"][:64],
            auth_orientation=data["authentication_orientation"][:64],
            auth_result=data["result"][:32])
        if data["result"] not in ("Success", "Fail", "?"):
            raise ValueError("Unrecognized LANL authentication result")
    elif dataset == "lanl-flow":
        common.update(event_type="network_flow",
            time_seconds=_int(data["time"], "time"),
            duration_seconds=_int(data["duration"], "duration"),
            source_asset_id=_pseudonym(key, data["source_computer"]),
            destination_asset_id=_pseudonym(key, data["destination_computer"]),
            source_port_token=_pseudonym(key, data["source_port"]),
            destination_port_token=_pseudonym(key, data["destination_port"]),
            protocol_token=_pseudonym(key, data["protocol"]),
            packets=_int(data["packet_count"], "packets"),
            bytes=_int(data["byte_count"], "bytes"))
    elif dataset == "lanl-dns":
        common.update(event_type="dns",
            time_seconds=_int(data["time"], "time"),
            source_asset_id=_pseudonym(key, data["source_computer"]),
            destination_asset_id=_pseudonym(key, data["resolved_computer"]))
    elif dataset == "lanl-redteam":
        # These are known red-team indicator events only. They do not
        # establish that every non-redteam line elsewhere is benign.
        common.update(event_type="publisher_redteam_indicator",
            time_seconds=_int(data["time"], "time"),
            observed_user_id=_pseudonym(key, data["user"]),
            source_asset_id=_pseudonym(key, data["source_computer"]),
            destination_asset_id=_pseudonym(key, data["destination_computer"]),
            label="attack", truth_basis="publisher_scenario",
            verified_attack=False)
    elif dataset == "ugr16-flow":
        common.update(event_type="network_flow",
            time_string=data["te"][:48], duration_string=data["td"][:48],
            source_asset_id=_pseudonym(key, data["sa"]),
            destination_asset_id=_pseudonym(key, data["da"]),
            source_port_token=_pseudonym(key, data["sp"]),
            destination_port_token=_pseudonym(key, data["dp"]),
            protocol_token=_pseudonym(key, data["pr"]),
            flags=data["flg"][:48], forwarding=data["fwd"][:48],
            type_of_service=data["stos"][:48],
            packets=_int(data["pkt"], "pkt"), bytes=_int(data["byt"], "byt"))
    else:
        raise ValueError("Unsupported dataset")
    return common


def normalized_rows(source: Path, *, dataset: str, expected_sha256: str,
                    pseudonym_key: bytes, max_records: int) -> tuple[list[dict], str]:
    """Read a bounded sample, requiring exact SHA256 of WHOLE compressed file."""
    if dataset not in DATASETS:
        raise ValueError("Dataset not supported")
    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64 or any(
            ch not in HEX for ch in expected_sha256):
        raise ValueError("Pinned file SHA256 required")
    if len(pseudonym_key) < 24:
        raise ValueError("Key must contain at least 24 secret bytes")
    if type(max_records) is not int or not 1 <= max_records <= 1_000_000:
        raise ValueError("Bounded max-record count required")
    source = _secure_file(source)
    actual_digest = _sha256(source)
    if actual_digest != expected_sha256:
        raise ValueError("Source SHA256 mismatch, refused before parsing")
    # Publisher file names are known; gzip magic, not suffix, determines mode.
    with source.open("rb") as header:
        compressed = header.read(2) == b"\x1f\x8b"
    opener = gzip.open if compressed else open
    result = []
    with opener(source, "rt", encoding="utf-8", errors="strict", newline="") as inp:
        first = inp.readline(MAX_RAW_LINE + 1)
        if len(first) > MAX_RAW_LINE:
            raise ValueError("Input line too long")
        # UGR source CSV may contain a named header; LANL source does not.
        expected = DATASETS[dataset]
        header = tuple(x.strip().lstrip("#").strip().lower() for x in
                       next(csv.reader([first]))) if first else ()
        if dataset == "ugr16-flow" and header == expected:
            start_line = 2
        else:
            start_line = 1
            inp.seek(0) if not compressed else None
            if compressed:
                # GzipTextFile supports seek, but re-opening is unnecessary:
                # parse the already-read record and then iterate subsequent.
                pass
        def convert(raw_line: str, line_number: int) -> dict:
            if len(raw_line) > MAX_RAW_LINE:
                raise ValueError(f"Line too long at line {line_number}")
            columns = next(csv.reader([raw_line]))
            if len(columns) != len(expected):
                raise ValueError(f"Expected {len(expected)} columns at line {line_number}")
            row = dict(zip(expected, (col.strip() for col in columns)))
            return _record(row, dataset=dataset, key=pseudonym_key,
                           source_digest=actual_digest, line_number=line_number,
                           raw_digest=hashlib.sha256(raw_line.encode("utf-8")).hexdigest())
        if start_line == 1 and compressed and first:
            result.append(convert(first, 1))
        for line_no, line in enumerate(inp, start=start_line if compressed or start_line == 2 else 1):
            if len(result) >= max_records:
                break
            if not line.strip():
                continue
            result.append(convert(line, line_no))
        if len(result) > max_records:
            result = result[:max_records]
    if not result:
        raise ValueError("No valid source records")
    return result, actual_digest


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dataset", required=True, choices=sorted(DATASETS))
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--expected-sha256", required=True)
    p.add_argument("--authorization-record", required=True, type=Path,
                   help="Locally stored record of source terms and authorized purpose")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--max-records", type=int, default=10_000)
    p.add_argument("--secret-env", default="PREDICT_SHIELD_P1_HMAC_KEY")
    a = p.parse_args()
    authorization = _secure_file(a.authorization_record)
    # Mere existence of a note is not independently verified legal permission.
    rights = json.loads(authorization.read_text(encoding="utf-8"))
    if (rights.get("source") != a.dataset or rights.get("status") != "approved"
            or rights.get("official_url") != SOURCE_URL[a.dataset]
            or not rights.get("authorized_purpose") or not rights.get("reviewer")
            or not rights.get("reviewed_on")):
        p.error("Data use permission/admission record is incomplete or not approved")
    secret = os.environ.get(a.secret_env, "").encode()
    if a.output.exists() or a.output.is_symlink():
        p.error("Refusing to overwrite or follow an output symlink")
    rows, sha = normalized_rows(a.source, dataset=a.dataset,
                                expected_sha256=a.expected_sha256,
                                pseudonym_key=secret, max_records=a.max_records)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation ensures previous measured files remain immutable.
    with a.output.open("x", encoding="utf-8") as out:
        for row in rows:
            out.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    print(json.dumps({"status": "NORMALIZED_NOT_SCORED", "dataset": a.dataset,
                      "source_sha256": sha, "events": len(rows),
                      "output": str(a.output),
                      "rights_authority_not_cryptographically_verified": True,
                      "scientific_detection_accuracy": "NOT_ESTABLISHED"}))


if __name__ == "__main__":
    main()
