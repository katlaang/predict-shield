"""Structure of Superviz25-SQL before the protocol is registered.

Counts rows by split and label (published figures), and shows the format of
user_inputs using training rows only (all benign by construction). Test-split
contents are not printed.
"""
from __future__ import annotations

import csv
import sys
from collections import Counter

csv.field_size_limit(1 << 30)


def main(path: str) -> None:
    by = Counter()
    templates = Counter()
    shown = 0
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        r = csv.DictReader(f)
        print("columns:", r.fieldnames)
        for row in r:
            by[(row["split"], row["label"])] += 1
            if row["split"] == "train":
                templates[row["query_template_id"]] += 1
                if shown < 8 and row["label"] == "0":
                    print("TRAIN example:", repr(row["query_template_id"]), "| inputs:", repr(row["user_inputs"])[:200],
                          "| type:", row["statement_type"])
                    shown += 1
    print("rows by (split,label):", dict(by))
    print("train templates:", len(templates), "min/max rows per template:", min(templates.values()), max(templates.values()))


if __name__ == "__main__":
    main(sys.argv[1])
