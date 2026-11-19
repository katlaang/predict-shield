"""Audit a completed, frozen AI detection-rule experiment report.

This auditor checks reporting completeness and measurement arithmetic only.
It does NOT infer event-level ground truth or treat an attack-labelled dataset
as a benign-only dataset. It does not attest model prompt provenance, network
capture authenticity, or operational detection accuracy.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

TARGET_SCHEMA = "predict-shield/ai-rule-suggestion/1"


def _canonical_sha(rules: list[dict]) -> str:
    return hashlib.sha256(json.dumps(
        rules, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()


def inspect(report: dict, registration: dict, registration_bytes: bytes) -> dict:
    issues = []
    def require(test: bool, reason: str) -> None:
        if not test:
            issues.append(reason)

    if not isinstance(report, dict) or not isinstance(registration, dict):
        raise ValueError("report and registration must be JSON objects")
    model = report.get("model")
    require(isinstance(model, str) and model not in ("", "stub-no-model"), "no demonstrated real model")
    require(report.get("schema") == TARGET_SCHEMA, "unrecognized experiment schema")
    require(report.get("split_commit") == registration.get("commit"), "wrong registered source commit")
    require(report.get("split_sha256") == hashlib.sha256(registration_bytes).hexdigest(),
            "registered split file fingerprint mismatch")
    targets = registration.get("targets")
    expected = registration.get("held_out")
    require(isinstance(targets, list) and len(targets) == len(set(targets)) and bool(targets),
            "invalid registered technique list")
    require(isinstance(expected, list) and bool(expected), "missing registered held-out population")
    expected_by_file = {r["file"]: r["technique"] for r in expected} if isinstance(expected, list) else {}
    require(len(expected_by_file) == len(expected or []), "registration contains duplicate held-out files")
    require(not set(r["file"] for r in registration.get("development", [])) & set(expected_by_file),
            "development overlaps held-out files")

    accepted = report.get("accepted_rules")
    if not isinstance(accepted, list):
        accepted = []
        require(False, "missing accepted rules list")
    require(report.get("accepted_set_sha256") == _canonical_sha(accepted),
            "frozen rule-set fingerprint mismatch")
    require(len({r.get("rule_id") for r in accepted if isinstance(r, dict)}) == len(accepted),
            "duplicate accepted rule ID")
    require(all(isinstance(r, dict) and r.get("technique") in (targets or [])
                for r in accepted), "unrecognized accepted-rule technique")
    techniques = report.get("techniques")
    require(isinstance(techniques, dict) and set(techniques) == set(targets or []),
            "incomplete development-technique report")
    if isinstance(techniques, dict):
        gated = []
        for target in (targets or []):
            for g in techniques.get(target, {}).get("gate", []):
                if g.get("accepted") is True:
                    if not isinstance(g.get("rule"), dict):
                        issues.append("accepted gate entry lacks rule")
                    else:
                        gated.append(g["rule"])
        require(sorted(json.dumps(x, sort_keys=True) for x in gated)
                == sorted(json.dumps(x, sort_keys=True) for x in accepted),
                "accepted rules do not match development gate")
    exchanges = report.get("model_exchanges")
    require(isinstance(exchanges, list) and len(exchanges) == len(targets or []),
            "model exchange not recorded for each target")

    rows = report.get("held_out")
    if not isinstance(rows, list):
        rows = []
        require(False, "held-out records missing")
    seen: set[str] = set()
    by_target: Counter = Counter()
    detected: Counter = Counter()
    event_count = 0
    wrong_technique_alerts = 0
    for row in rows:
        if not isinstance(row, dict):
            issues.append("non-object evaluation row")
            continue
        filename = row.get("file")
        if not isinstance(filename, str) or filename not in expected_by_file or filename in seen:
            issues.append("unregistered or duplicate evaluation file")
            continue
        seen.add(filename)
        technique = row.get("technique")
        require(technique == expected_by_file[filename], "held-out technique does not match registration")
        require(type(row.get("detected")) is bool, "missing Boolean scenario detection result")
        require(type(row.get("events")) is int and row["events"] >= 0,
                "missing valid telemetry-event denominator")
        require(type(row.get("own_rule_hits")) is int and row["own_rule_hits"] >= 0,
                "missing valid own-rule hit count")
        if type(row.get("detected")) is bool and type(row.get("own_rule_hits")) is int:
            require(row["detected"] == (row["own_rule_hits"] > 0),
                    "scenario detection flag disagrees with rule hits")
        other = row.get("other_technique_alerts")
        require(isinstance(other, list), "missing unrelated-technique alert evidence")
        if isinstance(other, list) and other:
            wrong_technique_alerts += 1
        if type(row.get("events")) is int:
            event_count += row["events"]
        by_target[technique] += 1
        detected[technique] += int(row.get("detected") is True)
    require(seen == set(expected_by_file), "not all frozen held-out recordings were evaluated")
    summary = report.get("summary") or {}
    require(isinstance(summary, dict), "missing summary")
    if not isinstance(summary, dict):
        summary = {}
    require(summary.get("held_out_recordings") == len(expected_by_file),
            "summary held-out denominator mismatch")
    require(summary.get("held_out_detected") == sum(detected.values()),
            "summary detected count mismatch")
    require(summary.get("held_out_events") == event_count,
            "summary telemetry event count mismatch")
    require(summary.get("accepted_rules") == len(accepted),
            "summary accepted-rule count mismatch")
    require(summary.get("accepted_set_sha256") == _canonical_sha(accepted),
            "summary rule fingerprint mismatch")
    require(summary.get("recordings_with_other_technique_alerts") == wrong_technique_alerts,
            "summary cross-technique-alert count mismatch")
    per = summary.get("by_technique", {})
    for target in (targets or []):
        info = per.get(target, {}) if isinstance(per, dict) else {}
        require(info.get("held_out_recordings") == by_target[target],
                "technique denominator mismatch: " + target)
        require(info.get("detected") == detected[target],
                "technique detection count mismatch: " + target)
        require(info.get("accepted_rules") == sum(r.get("technique") == target for r in accepted),
                "technique accepted-rule count mismatch: " + target)

    return {
        "schema": "predict-shield/ai-rule-experiment-independent-audit/1",
        "report_structurally_consistent": not issues,
        "issues": issues,
        "reported_scenario_detection": {
            "detected": sum(detected.values()),
            "denominator": len(expected_by_file),
            "by_technique": {t: {"detected": detected[t], "denominator": by_target[t]} for t in (targets or [])},
        },
        "selected_techniques": targets,
        "held_out_events_processed": event_count,
        "recordings_with_unrelated_technique_alerts": wrong_technique_alerts,
        "zero_detected_is_valid_negative_result": True,
        "event_level_detection_recall_established": False,
        "false_positive_rate_established": False,
        "independent_label_verification_established": False,
        "field_detection_effectiveness_established": False,
        "claim": "Selected attack-labelled recording coverage only; not attack-event recall or operational alert precision.",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--registration", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw = args.registration.read_bytes()
    result = inspect(json.loads(args.report.read_text(encoding="utf-8")),
                     json.loads(raw), raw)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result["report_structurally_consistent"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
