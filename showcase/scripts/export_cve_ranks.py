"""Per-CVE exploitation ranks from the frozen model, for the showcase ranker.

Scores every CVE published from 2025-01-01 to the snapshot date with the
frozen model (after checking it against its freeze) and ranks each against
the 2025 reference distribution, exactly as engine/predict_shield/
exploit_scoring.py does. KEV is not read. One JSON file per publication year.

  python export_cve_ranks.py --records records.jsonl.gz --out-dir showcase/public/data
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import pickle
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODEL = ROOT / "experiment-b" / "exploit-likelihood"
sys.path.insert(0, str(MODEL))
sys.path.insert(0, str(ROOT / "engine"))

from predict_shield.exploit_scoring import top_share  # noqa: E402
from run_model import frame  # noqa: E402

START = "2025-01-01"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--records", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, required=True)
    a = ap.parse_args()
    frozen = MODEL / "frozen"
    freeze = json.loads((frozen / "freeze.json").read_text())
    blob = (frozen / "model.pkl").read_bytes()
    if hashlib.sha256(blob).hexdigest() != freeze["model_sha256"]:
        raise SystemExit("model does not match its freeze")
    ref = json.loads((frozen / "reference-scores.json").read_text())
    if ref["model_sha256"] != freeze["model_sha256"]:
        raise SystemExit("reference distribution is for another model")
    model = pickle.loads(blob)
    rows = []
    with gzip.open(a.records, "rt") as f:
        for line in f:
            r = json.loads(line)
            if r["published"] >= START:
                rows.append(r)
    rows.sort(key=lambda r: r["cve"])
    scores = model.predict_proba(frame(rows))[:, 1]
    by_year: dict[str, list] = {}
    for r, s in zip(rows, scores):
        vendor = (r["vendors"][0] if r["vendors"] else r["assigner"])[:40]
        product = (r["products"][0] if r["products"] else "")[:40]
        by_year.setdefault(r["published"][:4], []).append(
            [r["cve"], r["published"], round(float(s), 6), round(top_share(float(s), ref["quantiles"]), 5),
             vendor, product, r["cvss_score"], (r["cwes"][0] if r["cwes"] else "")])
    a.out_dir.mkdir(parents=True, exist_ok=True)
    meta = {"schema": "predict-shield/showcase-cve-ranks/1", "model_sha256": freeze["model_sha256"],
            "freeze_sha256": freeze["freeze_sha256"], "reference": ref["window_published"],
            "reference_cves": ref["cves"], "cutoffs": ref["cutoffs"],
            "columns": ["cve", "published", "score", "top_share", "vendor", "product", "cvss", "cwe"],
            "years": {}, "kev_read": False}
    for year, items in sorted(by_year.items()):
        (a.out_dir / f"cve-ranks-{year}.json").write_text(json.dumps(items, separators=(",", ":")) + "\n")
        meta["years"][year] = len(items)
    (a.out_dir / "cve-ranks-meta.json").write_text(json.dumps(meta, indent=1) + "\n")
    print(json.dumps(meta["years"]))


if __name__ == "__main__":
    main()
