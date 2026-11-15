"""Compare advisory readers on the same advisories.

    PYTHONPATH=engine python -m predict_shield.advisory_eval \
        --corpus experiment-a/advisory-reading/corpus.json \
        --model ollama:<security-model> --model ollama:<general-model> \
        --output advisory-reading-results.json

The two rule readers always run. Each `--model` adds a model reader. Every
reader gets the advisory prose and the inventory's package list, and is scored
on which inventory versions it marks as affected:

    correct    it answered, and marked exactly the versions the answer key marks
    wrong      it answered, and marked a different set
    no answer  it abstained, or its answer was refused by a check

A wrong answer is the costly outcome, because the pipeline would act on it.
Results are reported separately for advisories whose prose states the versions
(answerable) and those where it does not (the right behaviour is no answer).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .advisory_reader import (ACCEPTED, REJECTED, AdvisoryReader, Affected, ArtifactNameRuleReader,
                              CoordinateRuleReader, ModelAdvisoryReader, Reading, affected_in, shortlist)
from .language_model import HOSTED_PROVIDERS, open_model
from .versions import VersionRange


def answer_key(item: dict) -> Reading:
    return Reading(ACCEPTED, tuple(
        Affected(e["package"], tuple(VersionRange(r["introduced"], r["fixed"]) for r in e["ranges"]))
        for e in item["truth"]), "answer-key")


def score_item(reading: Reading, item: dict, inventory: dict) -> dict:
    expected, _ = affected_in(answer_key(item), inventory)
    if reading.status != ACCEPTED:
        outcome = "no_answer"
        marked: set = set()
    else:
        marked, undecided = affected_in(reading, inventory)
        outcome = "correct" if marked == expected and not undecided else "wrong"
    return {"id": item["id"], "answerable": item["answerable"], "status": reading.status, "outcome": outcome,
            "packages_right": {a.package for a in reading.affected} == {e["package"] for e in item["truth"]},
            "missed": sorted(map(list, expected - marked)) if outcome == "wrong" else [],
            "extra": sorted(map(list, marked - expected)) if outcome == "wrong" else [],
            "reasons": list(reading.reasons)}


def summarize(rows: list[dict]) -> dict:
    def block(subset: list[dict]) -> dict:
        count = lambda outcome: sum(r["outcome"] == outcome for r in subset)
        answered = count("correct") + count("wrong")
        return {"advisories": len(subset), "correct": count("correct"), "wrong": count("wrong"),
                "no_answer": count("no_answer"),
                "refused_by_check": sum(r["status"] == REJECTED for r in subset),
                "precision_when_answering": round(count("correct") / answered, 3) if answered else None}
    return {"answerable": block([r for r in rows if r["answerable"]]),
            "not_answerable": block([r for r in rows if not r["answerable"]]),
            "all": block(rows)}


def evaluate(corpus: dict, readers: list[AdvisoryReader], limit: int | None = None) -> dict:
    inventory, items = corpus["inventory"], corpus["items"][:limit]
    packages = sorted(inventory)
    offered = sum(all(e["package"] in shortlist(i["text"], packages) for e in i["truth"]) for i in items)
    results = {}
    for reader in readers:
        rows = [score_item(reader.read(item["text"], packages), item, inventory) for item in items]
        results[reader.name] = {"summary": summarize(rows), "items": rows}
    return {"schema": "predict-shield/advisory-reading-results/1",
            "corpus_source_commit": corpus.get("source_commit"), "advisories": len(items),
            "inventory_packages": len(packages),
            "shortlist_contains_every_affected_package": offered,
            "readers": results}


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare advisory readers on one corpus")
    parser.add_argument("--corpus", type=Path, default=Path("experiment-a/advisory-reading/corpus.json"))
    parser.add_argument("--model", action="append", default=[],
                        help="ollama:<name>, featherless:<name>, together:<name>, or recorded:<path>")
    parser.add_argument("--record-dir", type=Path, help="save each model's exchanges here for replay")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    corpus = json.loads(args.corpus.read_text(encoding="utf-8"))
    readers: list[AdvisoryReader] = [CoordinateRuleReader(), ArtifactNameRuleReader()]
    for spec in args.model:
        record = (args.record_dir / (spec.replace(":", "_").replace("/", "_") + ".json")
                  if args.record_dir and spec.partition(":")[0] in ("ollama", *HOSTED_PROVIDERS)
                  else None)
        readers.append(ModelAdvisoryReader(open_model(spec, record_to=record)))
    report = evaluate(corpus, readers, args.limit)
    args.output.write_text(json.dumps(report, indent=1, default=sorted) + "\n", encoding="utf-8")
    print(f"{report['advisories']} advisories, {report['inventory_packages']} inventory packages")
    for name, result in report["readers"].items():
        a, n = result["summary"]["answerable"], result["summary"]["not_answerable"]
        print(f"  {name:28s} answerable: {a['correct']}/{a['advisories']} correct, {a['wrong']} wrong | "
              f"not answerable: {n['wrong']}/{n['advisories']} wrong")
    print(f"Report: {args.output}")


if __name__ == "__main__":
    main()
