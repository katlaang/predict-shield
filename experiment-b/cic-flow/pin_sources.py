"""Download a source archive, record its SHA-256, size and members.

Development archive (CIC-IDS2017 improved): also prints each member's header
and label counts, because it is the development data.
Test archive (CSE-CIC-IDS2018 improved): prints only each member's header line
and row count. Labels are not read, so nothing about the test labels is seen
before the detector is frozen.
"""
from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import io
import json
import zipfile
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 22), b""):
            h.update(block)
    return h.hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--archive", type=Path, required=True)
    ap.add_argument("--role", choices=("development", "test"), required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    out = {"archive": args.archive.name, "bytes": args.archive.stat().st_size,
           "sha256": sha256_file(args.archive), "role": args.role, "members": []}
    with zipfile.ZipFile(args.archive) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            entry = {"name": info.filename, "compressed": info.compress_size, "size": info.file_size,
                     "crc32": f"{info.CRC:08x}"}
            if info.filename.lower().endswith(".csv"):
                with z.open(info) as raw:
                    text = io.TextIOWrapper(raw, encoding="utf-8", errors="replace", newline="")
                    reader = csv.reader(text)
                    header = next(reader)
                    entry["header"] = header
                    if args.role == "development":
                        li = header.index("Label")
                        ai = header.index("Attempted Category") if "Attempted Category" in header else None
                        labels, attempted, rows = collections.Counter(), collections.Counter(), 0
                        for row in reader:
                            rows += 1
                            labels[row[li]] += 1
                            if ai is not None:
                                attempted[row[ai]] += 1
                        entry.update(rows=rows, labels=dict(labels), attempted_category=dict(attempted))
                    else:
                        entry["rows"] = sum(1 for _ in reader)
            out["members"].append(entry)
    args.output.write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
