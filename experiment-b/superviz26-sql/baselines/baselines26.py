"""Superviz26 baselines: extract one domain's test split, then reuse superviz25-sql/baselines.py unchanged.

  python baselines26.py extract --zip s26.zip --domain b --out b.csv
  python baselines26.py ours --zip s26.zip --domain b --data b.csv --frozen-dir ../frozen --models-dir M \
      --expected-freeze-sha256 H --out ours.npz
Other stages: python ../../superviz25-sql/baselines.py {sample,libinj,supervised,crs,report} --data b.csv ...
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import zipfile
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import model26 as m26  # noqa: E402

COLS = ("query_template_id", "user_inputs", "label", "attack_technique", "attack_stage", "attack_id", "split")


def extract(zpath: Path, domain: str, out: Path) -> None:
    m26.check_source(zpath)
    n = 0
    with zipfile.ZipFile(zpath) as z, open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, COLS)
        w.writeheader()
        for r in m26.rows(z, f"superviz26-lodo/{domain}-{domain}.csv", "test"):
            w.writerow({c: r.get(c, "") for c in COLS})
            n += 1
    print("extracted", domain, n, "test rows")


def ours(a) -> None:
    sys.path.insert(0, str(m26.S25))
    import baselines as b25
    freeze, bundles = m26.verify(a.frozen_dir, a.models_dir, a.expected_freeze_sha256)
    bundle = bundles[f"indomain-{a.domain}"]
    rows = b25.test_rows(a.data)
    raw = m26.s25.evidence([(r[0], r[1]) for r in rows], bundle["state"], bundle["model"])
    cal = np.asarray(bundle["state"]["calibration"])
    np.savez_compressed(a.out, score=m26.v3.fused(raw, cal, range(2)), threshold=bundle["state"]["thresholds"]["fused"])
    print("ours", a.domain, json.dumps({"rows": len(rows)}))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=("extract", "ours"))
    ap.add_argument("--zip", type=Path, required=True)
    ap.add_argument("--domain", choices=m26.PRIMARY, required=True)
    ap.add_argument("--data", type=Path)
    ap.add_argument("--frozen-dir", type=Path)
    ap.add_argument("--models-dir", type=Path)
    ap.add_argument("--expected-freeze-sha256")
    ap.add_argument("--out", type=Path)
    a = ap.parse_args()
    if a.cmd == "extract":
        extract(a.zip, a.domain, a.out)
    else:
        ours(a)


if __name__ == "__main__":
    main()
