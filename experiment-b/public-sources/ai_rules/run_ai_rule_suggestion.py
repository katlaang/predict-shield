"""AI-suggested detection rules: draft on development data, accept by gate,
freeze, then score once on held-out data.

Order, enforced by this script:
    1. load and verify the development recordings of the pre-registered split
    2. per technique, show the model summaries of its development recordings
       (values also seen in other techniques' development recordings removed)
    3. validate the model's rules against the closed grammar
    4. acceptance gate on development data: fires on its own technique, and
       on no contrast recording
    5. freeze the accepted set (SHA-256), write it to the report
    6. only then load the held-out recordings and score each once

The model never receives held-out data. Every exchange with the model is
kept in the report.
"""
from __future__ import annotations

import argparse
import os
import hashlib
import json
import sys
import time
import urllib.request
from math import sqrt
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "engine"))

from predict_shield.endpoint_telemetry import detect, iter_windows_events_xml  # noqa: E402
from predict_shield.language_model import HostedChatModel, OllamaModel  # noqa: E402
from predict_shield.rule_suggestion import acceptance_gate, freeze, suggest, summarize  # noqa: E402

LIMIT = 64 * 1024 * 1024
TECHNIQUE_NAMES = {
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1036.003": "Masquerading: Rename System Utilities",
    "T1047": "Windows Management Instrumentation",
}


def write_checkpoint(path: Path, data: dict) -> None:
    """Atomically preserve pre-freeze progress; never claim a complete score."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


class Recorder:
    def __init__(self, inner, *, on_exchange=None):
        self.inner, self.name, self.exchanges = inner, inner.name, []
        self.on_exchange = on_exchange

    def save(self):
        if self.on_exchange is not None:
            self.on_exchange(self.exchanges)

    def complete(self, system: str, prompt: str) -> str:
        started = time.monotonic()
        record = {"prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(), "prompt": prompt}
        try:
            reply = self.inner.complete(system, prompt)
        except Exception as error:  # recorded, then re-raised for suggest() to handle
            record.update(reply=None, error=str(error), seconds=round(time.monotonic() - started, 1))
            self.exchanges.append(record)
            self.save()
            raise
        record.update(reply=reply, seconds=round(time.monotonic() - started, 1))
        self.exchanges.append(record)
        self.save()
        return reply


class StubModel:
    """Not a model: returns no rules. Exercises the pipeline mechanics only."""
    name = "stub-no-model"

    def complete(self, system, prompt):
        return json.dumps({"rules": [], "uncertainty": "stub"})


def wilson(k: int, n: int, z: float = 1.959964):
    if n == 0:
        return None
    p, d = k / n, 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return round(c - h, 3), round(c + h, 3)


def load(entry: dict) -> list[dict]:
    if not entry["url"].startswith("https://media.githubusercontent.com/media/splunk/attack_data/"):
        raise ValueError("not a pinned attack_data URL")
    with urllib.request.urlopen(entry["url"], timeout=300) as response:
        data = response.read(LIMIT + 1)
    if len(data) > LIMIT or hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise ValueError("file does not match its pin: " + entry["file"])
    return [e for e, err in iter_windows_events_xml(data.decode("utf-8", errors="replace")) if e is not None]


def build_model(spec: str):
    if spec == "stub":
        return StubModel()
    if spec.startswith("ollama:"):
        # No hidden reasoning pass and a bounded answer: on a CPU runner the
        # reasoning pass alone exceeded the job limit (run 44459993639).
        return OllamaModel(spec.split(":", 1)[1], timeout=900.0, context_tokens=12288,
                           think=False, max_output_tokens=1500)
    if spec.startswith("hosted:"):
        _, provider, model = spec.split(":", 2)
        return HostedChatModel(provider, model)
    raise ValueError("model must be stub, ollama:<name> or hosted:<provider>:<model>")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--model-digest", default="")
    parser.add_argument("--checkpoint", type=Path, default=None,
                        help="record incomplete pre-freeze development progress, not scoring evidence")
    args = parser.parse_args()
    split = json.loads((HERE / "split.json").read_text())
    dev_files = {e["file"] for e in split["development"]}
    if dev_files & {e["file"] for e in split["held_out"]}:
        raise RuntimeError("a recording is in both halves")
    checkpoint = args.checkpoint
    def persist(exchanges, *, status="INCOMPLETE", technique=None):
        if checkpoint is not None:
            write_checkpoint(checkpoint, {
                "schema": "predict-shield/ai-rule-development-checkpoint/1",
                "status": status,
                "model": args.model,
                "model_digest": args.model_digest,
                "split_sha256": hashlib.sha256((HERE / "split.json").read_bytes()).hexdigest(),
                "technique_in_progress": technique,
                "model_exchanges": exchanges,
                "held_out_seen": False,
                "held_out_detection_rate": None,
                "completed_evaluation": False,
            })
    model = Recorder(build_model(args.model), on_exchange=lambda exchanges: persist(exchanges))
    report = {"schema": "predict-shield/ai-rule-suggestion/1", "model": model.name,
              "model_digest": args.model_digest, "split_commit": split["commit"],
              "split_sha256": hashlib.sha256((HERE / "split.json").read_bytes()).hexdigest(),
              "protocol": split["protocol"], "techniques": {}}

    # 1-4: development only
    dev = {t: [] for t in split["targets"]}
    for entry in split["development"]:
        dev[entry["technique"]].append(load(entry))
    accepted = []
    for technique in split["targets"]:
        persist(model.exchanges, technique=technique)
        contrast = [rec for other, recs in dev.items() if other != technique for rec in recs]
        summary = summarize(dev[technique], contrast=contrast, per_type=8)
        print(technique, "asking", model.name, flush=True)
        suggestion = suggest(model, technique, TECHNIQUE_NAMES[technique], summary)
        print(technique, "reply after", model.exchanges[-1]["seconds"] if model.exchanges else "-", "s;",
              len(suggestion.rules), "rules,", len(suggestion.problems), "problems", flush=True)
        gates = [acceptance_gate(spec, dev[technique], contrast) for spec in suggestion.rules]
        accepted += [g.rule for g in gates if g.accepted]
        report["techniques"][technique] = {
            "development_recordings": len(dev[technique]), "contrast_recordings": len(contrast),
            "summary_rows": {k: len(v) for k, v in summary.items()},
            "model_uncertainty": suggestion.uncertainty, "injection_suspected": suggestion.injection_suspected,
            "rules_proposed": len(suggestion.rules), "grammar_rejections": suggestion.problems,
            "gate": [{"rule": g.rule.to_json(), "accepted": g.accepted, "reason": g.reason,
                      "own_hits": f"{g.own_technique_recordings_hit}/{g.own_technique_recordings}",
                      "contrast_hits": f"{g.contrast_recordings_hit}/{g.contrast_recordings}",
                      "contrast_examples": g.contrast_examples} for g in gates],
        }
    # 5: freeze before any held-out data is read
    report["accepted_rules"] = [r.to_json() for r in accepted]
    report["accepted_set_sha256"] = freeze(accepted)
    report["model_exchanges"] = model.exchanges
    args.output.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    persist(model.exchanges, status="RULES_FROZEN_HELD_OUT_NOT_SCORED")

    # 6: held-out, scored once
    compiled = [r.compile() for r in accepted]
    rows = []
    for entry in split["held_out"]:
        recording = load(entry)
        hits = detect(recording, tuple(compiled))
        own = [h for h in hits if h.technique == entry["technique"]]
        rows.append({"file": entry["file"], "technique": entry["technique"], "events": len(recording),
                     "detected": bool(own), "own_rule_hits": len(own),
                     "other_technique_alerts": [{"rule": h.rule_id, "matched": dict(h.matched)}
                                                for h in hits if h.technique != entry["technique"]][:10]})
    per = {}
    for t in split["targets"]:
        mine = [r for r in rows if r["technique"] == t]
        k = sum(r["detected"] for r in mine)
        per[t] = {"held_out_recordings": len(mine), "detected": k, "wilson_95": wilson(k, len(mine)),
                  "accepted_rules": sum(1 for r in accepted if r.technique == t)}
    k = sum(r["detected"] for r in rows)
    report["held_out"] = rows
    report["summary"] = {
        "model": model.name, "accepted_rules": len(accepted),
        "accepted_set_sha256": report["accepted_set_sha256"], "by_technique": per,
        "held_out_recordings": len(rows), "held_out_detected": k, "held_out_wilson_95": wilson(k, len(rows)),
        "recordings_with_other_technique_alerts": sum(1 for r in rows if r["other_technique_alerts"]),
        "held_out_events": sum(r["events"] for r in rows),
        "development_events": sum(len(rec) for recs in dev.values() for rec in recs),
    }
    args.output.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    # A completed report is the only basis for measured held-out counts.
    # Keep checkpoint explicitly non-scored even after a successful full run.
    persist(model.exchanges, status="COMPLETED_REPORT_SEPARATELY_AVAILABLE")
    print(json.dumps(report["summary"], indent=1, sort_keys=True))
    for t, info in report["techniques"].items():
        print(t, "proposed", info["rules_proposed"], "grammar rejections", len(info["grammar_rejections"]),
              "accepted", sum(g["accepted"] for g in info["gate"]))
        for g in info["gate"]:
            print("   ", "ACCEPT" if g["accepted"] else "reject", g["own_hits"], g["contrast_hits"],
                  g["rule"]["event_type"], [(c["field"], c["op"], c["value"]) for c in g["rule"]["all_of"]])


if __name__ == "__main__":
    main()
