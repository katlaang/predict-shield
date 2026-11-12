"""Offline, temporally bounded historical KEV-addition proxy evaluation.

KEV catalog additions are NOT exploitation events. The evaluator does not
train a model or claim predictive effectiveness on real infrastructure.
"""
from __future__ import annotations

import argparse
import json
from datetime import date, timedelta
from pathlib import Path

from .threat_intel import read_epss, read_kev, prioritize


def average_precision(labels: list[bool], scores: list[float]) -> float | None:
    """Average precision by descending score with deterministic index ties."""
    if len(labels) != len(scores):
        raise ValueError("mismatched labels/scores")
    positives = sum(labels)
    if positives == 0:
        return None
    ranked = sorted(range(len(labels)), key=lambda i: (-scores[i], i))
    hits, cumulative = 0, 0.0
    for rank, index in enumerate(ranked, 1):
        if labels[index]:
            hits += 1
            cumulative += hits / rank
    return cumulative / positives


def evaluate_proxy(*, epss_file: str, epss_date: str,
                   kev_before_file: str, kev_before_date: str,
                   kev_after_file: str, kev_after_date: str,
                   assets_file: str, as_of: str,
                   horizon_days: int = 30, top_k: int = 10) -> dict:
    cutoff = date.fromisoformat(as_of)
    horizon = cutoff + timedelta(days=horizon_days)
    if horizon_days < 1 or top_k < 1:
        raise ValueError("positive horizon and top_k required")
    before_day = date.fromisoformat(kev_before_date)
    after_day = date.fromisoformat(kev_after_date)
    if before_day > cutoff or after_day < horizon:
        raise ValueError("historical and outcome snapshots must bracket time window")
    ep, ep_meta = read_epss(epss_file, epss_date, as_of)
    before, before_meta = read_kev(kev_before_file, kev_before_date, as_of)
    # The *future* catalog must never be used for the feature snapshot.
    later, later_meta = read_kev(kev_after_file, kev_after_date, kev_after_date)
    raw_assets = Path(assets_file).read_bytes()
    assets = json.loads(raw_assets)
    if not isinstance(assets, list):
        raise ValueError("asset fixture must be list")
    ranked = prioritize(assets, ep, before, as_of)
    # Evaluate only baseline candidate CVEs not already known in KEV.
    eligible = [r for r in ranked
                if r["epss"] is not None and not r["kev_known_exploited"]]
    labels = [bool((d := later.get(r["cve"])) and
                   cutoff < date.fromisoformat(d) <= horizon)
              for r in eligible]
    if not eligible:
        raise ValueError("no eligible baseline asset-vulnerability pairs")
    scores = {
        "epss_only": [float(r["epss"]) for r in eligible],
        "contextual_heuristic": [float(r["heuristic_score"]) for r in eligible],
    }
    results = {}
    for name, values in scores.items():
        ordering = sorted(range(len(values)),
                          key=lambda i: (-values[i], eligible[i]["asset_id"], eligible[i]["cve"]))
        selected = ordering[:top_k]
        results[name] = {
            "average_precision": average_precision(labels, values),
            "precision_at_k": sum(labels[i] for i in selected) / len(selected),
            "retrieved_at_k": len(selected),
        }
    return {
        "status": "retrospective_proxy_evaluation_only",
        "as_of": as_of, "horizon_end": horizon.isoformat(),
        "horizon_days": horizon_days, "positive_definition": "future_KEV_catalog_addition_not_exploitation",
        "candidate_asset_cve_pairs": len(eligible),
        "positive_pairs": sum(labels),
        "unique_candidate_cves": len({r["cve"] for r in eligible}),
        "note": "Multiple assets sharing a CVE share the same label; do not treat these as independent samples.",
        "sources": [ep_meta, before_meta, later_meta],
        "results": results,
        "trained_ai_model": False,
    }


def main():
    p = argparse.ArgumentParser(description="Temporal KEV-addition proxy backtest")
    for name in ("epss-file", "epss-date", "kev-before-file", "kev-before-date",
                 "kev-after-file", "kev-after-date", "assets-file", "as-of", "output"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--horizon-days", type=int, default=30)
    p.add_argument("--top-k", type=int, default=10)
    a = vars(p.parse_args())
    output = a.pop("output")
    report = evaluate_proxy(**{k.replace("-", "_"): v for k, v in a.items()})
    Path(output).write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
