"""Run the frozen endpoint rules v2 once on the pre-registered Splunk
attack_data held-out set (see `splunk_attack_data` in sources.json).

Reported per recording, never per event: Splunk labels recordings with
ATT&CK techniques, not individual events. A covered recording counts as
detected when at least one alert agrees with its label. Every alert on an
other-technique recording is listed with the fields it matched, for a
reader to judge. Recordings without any alert are counted, not called
benign.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from math import sqrt
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "engine"))

from predict_shield.endpoint_telemetry import RULES_V2, detect, iter_windows_events_xml, technique_matches_label  # noqa: E402

LIMIT = 64 * 1024 * 1024


def wilson(k: int, n: int, z: float = 1.959964) -> tuple[float, float] | None:
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return round(c - h, 3), round(c + h, 3)


def fetch(entry: dict) -> bytes:
    if not entry["url"].startswith("https://media.githubusercontent.com/media/splunk/attack_data/"):
        raise ValueError("not a pinned attack_data URL")
    with urllib.request.urlopen(entry["url"], timeout=180) as response:
        data = response.read(LIMIT + 1)
    if len(data) > LIMIT or hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise ValueError("file does not match its pin: " + entry["file"])
    return data


def measure(entry: dict) -> dict:
    events, unparsed = [], 0
    for event, error in iter_windows_events_xml(fetch(entry).decode("utf-8", errors="replace")):
        if event is None:
            unparsed += 1
        else:
            events.append(event)
    hits = detect(events, RULES_V2)
    agreeing = [h for h in hits if technique_matches_label(h.technique, entry["labels"])]
    return {"file": entry["file"], "labels": entry["labels"], "events": len(events), "unparsed_events": unparsed,
            "hits": len(hits), "hits_agreeing_with_label": len(agreeing), "detected": bool(agreeing),
            "hit_detail": [{"rule": h.rule_id, "technique": h.technique,
                            "agrees_with_label": technique_matches_label(h.technique, entry["labels"]),
                            "matched": dict(h.matched)} for h in hits][:25]}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = json.loads((HERE / "sources.json").read_text())["splunk_attack_data"]
    covered = [measure(e) for e in source["covered"]]
    other = [measure(e) for e in source["other"]]
    by_technique = {}
    for r in covered:
        t = r["labels"][0]
        row = by_technique.setdefault(t, {"recordings": 0, "detected": 0})
        row["recordings"] += 1
        row["detected"] += int(r["detected"])
    for row in by_technique.values():
        row["wilson_95"] = wilson(row["detected"], row["recordings"])
    detected = sum(r["detected"] for r in covered)
    summary = {
        "rules": "RULES_V2", "covered_recordings": len(covered), "covered_detected": detected,
        "covered_wilson_95": wilson(detected, len(covered)), "by_technique": by_technique,
        "covered_missed": [r["file"] for r in covered if not r["detected"]],
        "other_recordings": len(other), "other_with_any_alert": [r["file"] for r in other if r["hits"]],
        "events": sum(r["events"] for r in covered + other),
        "unparsed_events": sum(r["unparsed_events"] for r in covered + other),
        "skipped": source["skipped"],
    }
    report = {"schema": "predict-shield/splunk-heldout/1", "commit": source["commit"],
              "selection_protocol": source["selection_protocol"], "summary": summary,
              "covered": covered, "other": other}
    args.output.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=1, sort_keys=True))
    for r in covered + other:
        print(("COVERED " if r in covered else "other   ") + f"{r['labels']} {r['file'].split('attack_techniques/')[-1]}: "
              f"events {r['events']}, hits {r['hits']}, detected {r['detected']}")
        for h in r["hit_detail"][:4]:
            print("     ", h["rule"], "agrees" if h["agrees_with_label"] else "DIFFERENT LABEL",
                  {k: v[-90:] for k, v in h["matched"].items()})


if __name__ == "__main__":
    main()
