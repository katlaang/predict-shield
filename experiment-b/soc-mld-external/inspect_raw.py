"""Format of the raw SOC-MLD files, before any protocol is registered.

Prints the first lines of the label file and the access log, the label file's
time range and label counts, and how many access-log lines fall inside each
label's windows. It does not look at any request content beyond three lines.
"""
from __future__ import annotations

import csv
import io
import re
import sys
import zipfile
from collections import Counter
from datetime import datetime

ROOT = "SOC-MLD-v1.0/dataset/raw/"
TS = re.compile(r"\[([^\]]+)\]")


def main(path: str) -> None:
    with zipfile.ZipFile(path) as z:
        labels_txt = z.read(ROOT + "dataset_labels.csv").decode("utf-8", errors="replace")
        log = z.read(ROOT + "access.log").decode("utf-8", errors="replace").splitlines()
    print("LABEL HEAD:\n" + "\n".join(labels_txt.splitlines()[:12]))
    rows = list(csv.DictReader(io.StringIO(labels_txt)))
    print("label rows", len(rows), "first", rows[0]["timestamp"], "last", rows[-1]["timestamp"])
    print("layer", Counter(r["layer"] for r in rows))
    print("status", Counter(r["status"] for r in rows))
    print("target", Counter(r["target"] for r in rows).most_common(10))
    print("ACCESS LOG lines", len(log))
    print("ACCESS HEAD (3 lines, truncated to 300 chars):")
    for line in log[:3]:
        print("  " + line[:300])
    times = []
    for line in log:
        m = TS.search(line)
        if m:
            try:
                times.append(datetime.strptime(m.group(1).split()[0], "%d/%b/%Y:%H:%M:%S").timestamp())
            except ValueError:
                pass
    print("parsed log times", len(times), "range", min(times), max(times))


if __name__ == "__main__":
    main(sys.argv[1])
