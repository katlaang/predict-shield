"""CVE-level retrospective EPSS baseline for future KEV catalog additions.

A catalog addition is not exploitation. This module fits no ML model and
does not treat different CVEs or time windows as independent test evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import date, timedelta
from pathlib import Path

from .threat_intel import read_epss, read_kev


def evaluate(*, epss_path: str, epss_date: str,
             kev_before_path: str, kev_before_date: str,
             kev_after_path: str, kev_after_date: str,
             as_of: str, horizon_days: int = 30,
             ks: tuple[int, ...] = (10, 100, 1000)) -> dict:
    cutoff = date.fromisoformat(as_of)
    horizon = cutoff + timedelta(days=horizon_days)
    if horizon_days <= 0 or not ks or any(k <= 0 for k in ks):
        raise ValueError("Invalid preregistered horizon or K")
    if date.fromisoformat(kev_after_date) < horizon:
        raise ValueError("Future catalog snapshot does not cover horizon")
    probabilities, epss_meta = read_epss(epss_path, epss_date, as_of)
    before, before_meta = read_kev(kev_before_path, kev_before_date, as_of)
    after, after_meta = read_kev(kev_after_path, kev_after_date, kev_after_date)
    new_kev = {cve for cve, added in after.items()
               if cutoff < date.fromisoformat(added) <= horizon
               and cve not in before}
    known = set(before)
    eligible = sorted(((cve, score) for cve, score in probabilities.items()
                       if cve not in known), key=lambda row: (-row[1], row[0]))
    covered_new = new_kev.intersection({cve for cve, _ in eligible})
    hits = 0
    ap_numerator = 0.0
    precision = {}
    if not eligible:
        raise ValueError("No eligible CVE scores")
    for rank, (cve, _) in enumerate(eligible, 1):
        if cve in covered_new:
            hits += 1
            ap_numerator += hits / rank
        if rank in ks:
            precision[str(rank)] = hits / rank
    for k in ks:
        if k > len(eligible):
            precision[str(k)] = None
    return {
        "schema": "predict-shield/historical-kev-proxy-baseline/1",
        "prediction_cutoff": as_of,
        "horizon_end": horizon.isoformat(),
        "label_definition": "future KEV catalog addition; NOT verified exploitation",
        "scoring": "historical EPSS only; no model fit",
        "eligible_cves": len(eligible),
        "future_kev_additions_all": len(new_kev),
        "future_kev_additions_with_prior_epss": len(covered_new),
        "future_kev_additions_missing_prior_epss": len(new_kev) - len(covered_new),
        "average_precision": ap_numerator / hits if hits else None,
        "precision_at_k": precision,
        "provenance": [epss_meta, before_meta, after_meta],
        "trained_ai_model": False,
        "independent_validation": False,
    }


def main() -> None:
    p = argparse.ArgumentParser()
    for argument in ("epss-path", "epss-date", "kev-before-path",
                     "kev-before-date", "kev-after-path", "kev-after-date",
                     "as-of", "output"):
        p.add_argument("--" + argument, required=True)
    p.add_argument("--horizon-days", type=int, default=30)
    a = vars(p.parse_args())
    output = a.pop("output")
    result = evaluate(**{k.replace("-", "_"): v for k, v in a.items()})
    Path(output).write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
