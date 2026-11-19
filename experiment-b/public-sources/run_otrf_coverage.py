"""Measure the endpoint rules on held-out public attack recordings.

The three rules in `endpoint_telemetry.py` were written while looking at
three OTRF datasets (the development set). This runner applies them,
unchanged, to twenty further OTRF datasets fetched only afterwards (the
held-out set, `coverage_datasets` in sources.json):

    covered     datasets labelled with a technique a rule targets
                (T1003.001, T1112): did any hit agree with the label?
                A dataset with no agreeing hit is a miss.
    uncovered   datasets labelled with other techniques: every hit there is
                listed with the exact fields it matched, for a reader to
                judge. A hit is not assumed false just because the label
                differs: an attack labelled one way can also perform
                another step (pass-the-hash, for example, opens LSASS).

What this cannot measure: OTRF labels datasets, not individual events, so
there is no per-event recall. Background events are everything a rule did
not match; their count is reported, not a false-alarm rate per event.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "engine"))

from otrf_replay import events_from_archive, fetch_pinned  # noqa: E402
from predict_shield.endpoint_telemetry import RULES, detect, technique_matches_label  # noqa: E402

RULE_TECHNIQUES = sorted({r.technique for r in RULES})


def covered(labels: list[str]) -> bool:
    return any(technique_matches_label(t, labels) or any(t == l for l in labels) for t in RULE_TECHNIQUES)


def measure(dataset: dict) -> dict:
    events = list(events_from_archive(fetch_pinned(dataset["url"], dataset["sha256"])))
    hits = detect(events)
    agreeing = [h for h in hits if technique_matches_label(h.technique, dataset["labels"])]
    return {
        "id": dataset["id"], "title": dataset["title"], "labels": dataset["labels"],
        "covered_by_a_rule": covered(dataset["labels"]), "events": len(events), "hits": len(hits),
        "hits_agreeing_with_label": len(agreeing), "detected": bool(agreeing),
        "hit_detail": [{"rule": h.rule_id, "technique": h.technique, "host": h.host,
                        "agrees_with_label": technique_matches_label(h.technique, dataset["labels"]),
                        "matched": dict(h.matched)} for h in hits],
    }


def summarize(rows: list[dict]) -> dict:
    cov = [r for r in rows if r["covered_by_a_rule"]]
    unc = [r for r in rows if not r["covered_by_a_rule"]]
    return {
        "datasets": len(rows), "events": sum(r["events"] for r in rows),
        "covered_datasets": len(cov), "covered_detected": sum(r["detected"] for r in cov),
        "covered_missed": [r["title"] for r in cov if not r["detected"]],
        "uncovered_datasets": len(unc),
        "uncovered_datasets_with_any_hit": [r["title"] for r in unc if r["hits"]],
        "hits_total": sum(r["hits"] for r in rows),
        "hits_disagreeing_with_label": sum(r["hits"] - r["hits_agreeing_with_label"] for r in rows),
        "events_without_any_hit": sum(r["events"] for r in rows) - sum(r["hits"] for r in rows),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = json.loads((HERE / "sources.json").read_text())["otrf_security_datasets"]
    development = [measure(d) for d in source["datasets"]]
    held_out = [measure(d) for d in source["coverage_datasets"]]
    report = {"schema": "predict-shield/otrf-rule-coverage/1", "commit": source["commit"],
              "rules": [{"rule_id": r.rule_id, "technique": r.technique, "title": r.title} for r in RULES],
              "note": source["coverage_note"],
              "development_set": {"summary": summarize(development), "datasets": development},
              "held_out_set": {"summary": summarize(held_out), "datasets": held_out}}
    args.output.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print(json.dumps({"development": report["development_set"]["summary"],
                      "held_out": report["held_out_set"]["summary"]}, indent=1, sort_keys=True))
    for r in held_out:
        print(("COVERED  " if r["covered_by_a_rule"] else "other    ") + f"{r['id']} {r['labels']} {r['title']}: "
              f"events {r['events']}, hits {r['hits']}, detected {r['detected']}")
        for h in r["hit_detail"]:
            print("     ", h["rule"], "agrees" if h["agrees_with_label"] else "DIFFERENT LABEL", h["matched"])


if __name__ == "__main__":
    main()
