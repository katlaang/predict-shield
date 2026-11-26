"""Find the CSIC 2010 download links, download the three files and print their pins.

Prints link targets, byte sizes, SHA-256 and the number of request lines per
method. Request contents are not printed. Run before any protocol is registered.
"""
from __future__ import annotations

import hashlib
import re
import sys
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path

PAGE = "https://www.tic.itefi.csic.es/dataset/"
WANTED = ("normalTrafficTraining", "normalTrafficTest", "anomalousTrafficTest")


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    html = urllib.request.urlopen(PAGE, timeout=60).read().decode("utf-8", errors="replace")
    hrefs = sorted(set(re.findall(r'href="([^"]+)"', html, re.I)))
    print("ALL HREFS:")
    for h in hrefs:
        print("  ", h)
    for name in WANTED:
        cands = [h for h in hrefs if name.lower() in h.lower()]
        if not cands:
            print("NO LINK FOUND FOR", name)
            continue
        url = urllib.parse.urljoin(PAGE, cands[0])
        data = urllib.request.urlopen(url, timeout=300).read()
        (out / Path(urllib.parse.urlparse(url).path).name).write_bytes(data)
        text = data.decode("latin-1")
        methods = Counter(m.group(1) for m in re.finditer(r"(?m)^(GET|POST|PUT|DELETE|HEAD|OPTIONS) http", text))
        print(f"FILE {name}: url={url} bytes={len(data)} sha256={hashlib.sha256(data).hexdigest()} requests={dict(methods)}")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
