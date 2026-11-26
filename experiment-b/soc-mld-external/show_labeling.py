"""Print the parts of the publisher's extract_features.py that assign labels (read only, not executed)."""
import re
import sys
import zipfile

src = zipfile.ZipFile(sys.argv[1]).read("SOC-MLD-v1.0/code/extract_features.py").decode("utf-8", errors="replace")
lines = src.splitlines()
keep = set()
for i, l in enumerate(lines):
    if re.search(r"label|window|instance|NORMAL|benign|def |REQ_|session", l, re.I):
        keep.update(range(max(0, i - 2), min(len(lines), i + 4)))
for i in sorted(keep):
    print(f"{i+1:5d}: {lines[i][:160]}")
