"""Score the verifier against injected ground truth.

The evaluation label is the oracle's post-action reading
(actual_revoked_access_denied): a separate process reading cache state
directly and probing each target directly. The verifier never reads it. Here
the verifier is the thing measured: sensitivity, specificity and abstain rate
per fault mode and action, for two verdicts:

- single evidence: the gateway scope verdict recorded at collection time;
- dual evidence: the scope verdict combined with post-action operator
  telemetry under the rule in PREREGISTRATION.json (agree, or abstain).

A positive case is "access truly denied after the action". A false VERIFIED
(verifier says fixed, oracle says exposed) is the costly error and is counted
on its own.

Usage, inside experiment-b/mechanism-lab:
  python verifier_scoring.py --records results/mechanism [--controls reports/controls.json] --output reports/verifier-scoring.json
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from math import sqrt
from pathlib import Path

ENFORCER_COUNT = 4


def wilson(k: int, n: int, z: float = 1.959963984540054) -> list[float] | None:
    if n == 0:
        return None
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return [max(0.0, centre - half), min(1.0, centre + half)]


def telemetry_reading(samples: list[dict] | None) -> str:
    """CONSISTENT, DIVERGENT or UNAVAILABLE from post-action operator telemetry."""
    if not samples:
        return "UNAVAILABLE"
    observed = [s for s in samples if s.get("observed")]
    revisions = {s.get("applied_revision") for s in observed}
    if len(revisions) > 1 or any(s.get("refresh_failed") for s in observed):
        return "DIVERGENT"
    if len(observed) < ENFORCER_COUNT or any(s.get("scheduled_callbacks_pending") for s in observed):
        return "UNAVAILABLE"
    return "CONSISTENT"


def dual_verdict(scope_status: str, telemetry: str) -> tuple[str, str]:
    """Combine two kinds of evidence; abstain when they disagree."""
    if scope_status == "VERIFIED" and telemetry == "CONSISTENT":
        return "VERIFIED", "scope and telemetry agree"
    if scope_status == "NOT VERIFIED" and telemetry in ("DIVERGENT", "UNAVAILABLE"):
        return "NOT VERIFIED", "scope negative" + ("; telemetry agrees" if telemetry == "DIVERGENT" else "; telemetry unavailable")
    if scope_status == "INDETERMINATE":
        return "ABSTAIN", "scope indeterminate"
    return "ABSTAIN", f"evidence disagrees or is incomplete (scope {scope_status}, telemetry {telemetry})"


def tally(rows: list[tuple[str, bool]]) -> dict:
    """rows: (verdict, truly_denied). Abstentions are reported separately."""
    c = defaultdict(int)
    for verdict, truth in rows:
        if verdict == "VERIFIED":
            c["TP" if truth else "false_VERIFIED"] += 1
        elif verdict == "NOT VERIFIED":
            c["FN" if truth else "TN"] += 1
        else:
            c["abstain_truly_denied" if truth else "abstain_truly_exposed"] += 1
    tp, fn, tn, fp = c["TP"], c["FN"], c["TN"], c["false_VERIFIED"]
    abstain = c["abstain_truly_denied"] + c["abstain_truly_exposed"]
    n = len(rows)
    return {
        **{k: c[k] for k in ("TP", "FN", "TN", "false_VERIFIED",
                             "abstain_truly_denied", "abstain_truly_exposed")},
        "cases": n,
        "sensitivity_when_answering": tp / (tp + fn) if tp + fn else None,
        "sensitivity_wilson_95": wilson(tp, tp + fn),
        "specificity_when_answering": tn / (tn + fp) if tn + fp else None,
        "specificity_wilson_95": wilson(tn, tn + fp),
        "abstain_rate": abstain / n if n else None,
    }


def load_record_cases(root: Path) -> list[dict]:
    """Join verification, oracle and pre-action streams by run_id."""
    cases = []
    for vfile in sorted((root / "verification").glob("*.json")):
        run_id = vfile.stem
        ofile = root / "oracle" / vfile.name
        pfile = root / "pre_action" / vfile.name
        if not (ofile.is_file() and pfile.is_file()):
            continue
        v, o, p = (json.loads(f.read_text()) for f in (vfile, ofile, pfile))
        cases.append({
            "source": "campaign",
            "run_id": run_id,
            "fault_mode": p["experimental_conditions"]["fault_mode"],
            "action": v["action_id"],
            "scope": v["outcome"],
            "telemetry": telemetry_reading(v.get("operator_observations_after")),
            "truly_denied": bool(o["actual_revoked_access_denied"]),
        })
    return cases


def load_control_cases(report: dict) -> list[dict]:
    """End-of-window control readings carry the same three fields."""
    cases = []
    for run in report.get("runs", []):
        end = run.get("end_of_campaign_window") or {}
        if "verifier_scope" not in end or end.get("oracle_denied") is None:
            continue
        cases.append({
            "source": "control",
            "run_id": run["control_id"],
            "fault_mode": run["fault_mode"],
            "action": "no_action_control",
            "scope": end["verifier_scope"],
            "telemetry": telemetry_reading(end.get("operator_telemetry")),
            "truly_denied": bool(end["oracle_denied"]),
        })
    return cases


def score(cases: list[dict]) -> dict:
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for case in cases:
        case["dual"], case["dual_reason"] = dual_verdict(case["scope"], case["telemetry"])
        groups[("ALL", "ALL")].append(case)
        groups[(case["fault_mode"], "ALL")].append(case)
        groups[(case["fault_mode"], case["action"])].append(case)
    out = {}
    for (fault, action), members in sorted(groups.items()):
        out[f"{fault}/{action}"] = {
            "single_evidence": tally([(m["scope"], m["truly_denied"]) for m in members]),
            "dual_evidence": tally([(m["dual"], m["truly_denied"]) for m in members]),
            "dual_reasons": dict(sorted(_count(m["dual_reason"] for m in members).items())),
        }
    return out


def _count(values) -> dict:
    c: dict = defaultdict(int)
    for v in values:
        c[v] += 1
    return c


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--records", type=Path)
    ap.add_argument("--controls", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    cases = []
    if args.records:
        cases += load_record_cases(args.records)
    if args.controls:
        cases += load_control_cases(json.loads(args.controls.read_text()))
    if not cases:
        raise SystemExit("no cases to score")
    report = {
        "schema": "predict-shield/verifier-scoring/1",
        "label": "oracle actual_revoked_access_denied (injected ground truth), never the verifier",
        "positive_class": "access truly denied after the action",
        "cases": len(cases),
        "with_post_action_telemetry": sum(c["telemetry"] != "UNAVAILABLE" for c in cases),
        "by_fault_and_action": score(cases),
        "note": "Trials sharing a configuration share a seed; Wilson intervals treat them as independent and understate uncertainty.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print(json.dumps(report["by_fault_and_action"]["ALL/ALL"], indent=1))


if __name__ == "__main__":
    main()
