"""Structure only: members, sizes, line counts, date ranges, request shapes. Prints the publisher's YAML labeling rules.
No request path, query value or address is printed."""
import re
import sys
import zipfile
from collections import Counter

DATE = re.compile(r"\[(\d{2}/\w{3}/\d{4}):")
REQ = re.compile(r'"([A-Z]{3,8}) (\S+) HTTP/[\d.]+"')


def shape(line: str) -> str:
    return re.sub(r"[0-9]", "9", re.sub(r"[A-Za-z]", "a", line))[:160]


for path in sys.argv[1:]:
    print("ARCHIVE", path)
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            print("MEMBER", info.filename, info.file_size)
        for info in z.infolist():
            n = info.filename.lower()
            if n.endswith((".yaml", ".yml")):
                print("RULES", info.filename)
                print(z.read(info).decode("utf-8", "replace"))
        for info in z.infolist():
            if "access" not in info.filename.lower() or info.is_dir():
                continue
            data = z.read(info)
            if info.filename.endswith(".gz"):
                import gzip
                data = gzip.decompress(data)
            lines = data.decode("utf-8", "replace").splitlines()
            dates = [m.group(1) for l in lines if (m := DATE.search(l))]
            reqs = [m for l in lines if (m := REQ.search(l))]
            methods = Counter(m.group(1) for m in reqs)
            q = sum("?" in m.group(2) for m in reqs)
            print("ACCESS", info.filename, "lines", len(lines), "parsed", len(reqs), "with_query", q,
                  "first", dates[0] if dates else None, "last", dates[-1] if dates else None,
                  "methods", dict(methods.most_common(5)), "shape", shape(lines[0]) if lines else "")
