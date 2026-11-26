"""Describe the SOC-MLD archive's structure before any protocol is registered.

Prints file names, sizes, row counts, column names and the value counts of
label-like columns. It does not relate any feature to any label, so it can be
run before the detection protocol is fixed.
"""
from __future__ import annotations

import csv
import io
import json
import sys
import zipfile
from collections import Counter

LABEL_HINTS = ("label", "attack", "class", "category", "type", "scenario", "instance", "session", "split")


def main(path: str) -> None:
    out = {"members": []}
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            entry = {"name": info.filename, "bytes": info.file_size}
            raw = z.read(info)
            name = info.filename.lower()
            try:
                if name.endswith(".csv"):
                    rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8", errors="replace"))))
                elif name.endswith((".jsonl", ".ndjson")):
                    rows = [json.loads(l) for l in raw.decode("utf-8", errors="replace").splitlines() if l.strip()]
                elif name.endswith(".json"):
                    data = json.loads(raw)
                    rows = data if isinstance(data, list) else [data]
                else:
                    rows = None
            except Exception as e:  # report and continue
                entry["parse_error"] = str(e)[:200]
                rows = None
            if rows:
                cols = list(rows[0].keys()) if isinstance(rows[0], dict) else []
                entry["rows"] = len(rows)
                entry["columns"] = cols
                labels = {}
                for c in cols:
                    if any(h in c.lower() for h in LABEL_HINTS):
                        vals = Counter(str(r.get(c)) for r in rows if isinstance(r, dict))
                        labels[c] = dict(vals.most_common(40)) if len(vals) <= 200 else {"distinct": len(vals)}
                entry["label_like_columns"] = labels
            elif name.endswith((".md", ".txt", ".yaml", ".yml", ".cff")):
                entry["text_head"] = raw.decode("utf-8", errors="replace")[:3000]
            out["members"].append(entry)
    print(json.dumps(out, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main(sys.argv[1])
