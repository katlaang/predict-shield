"""Show the shape of benign training inputs per domain and template (train split only)."""
import csv
import io
import sys
import zipfile
from collections import defaultdict

csv.field_size_limit(1 << 30)
with zipfile.ZipFile(sys.argv[1]) as z:
    for x in "abcd":
        seen = defaultdict(list)
        with z.open(f"superviz26-lodo/{x}-{x}.csv") as raw:
            for i, r in enumerate(csv.DictReader(io.TextIOWrapper(raw, encoding="utf-8", errors="replace", newline=""))):
                if r["split"] == "train" and len(seen[r["query_template_id"]]) < 4:
                    seen[r["query_template_id"]].append(r["user_inputs"])
                if i > 600_000:
                    break
        print("DOMAIN", x, "templates", len(seen))
        for t, v in sorted(seen.items())[:80]:
            print("  ", t, "|", " || ".join(repr(s)[:70] for s in v))
