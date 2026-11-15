"""Build the advisory-reading corpus from the GitHub Advisory Database.

    git clone --filter=blob:none --sparse https://github.com/github/advisory-database db
    git -C db sparse-checkout set advisories/github-reviewed/2025 advisories/github-reviewed/2026
    PYTHONPATH=engine python experiment-a/advisory-reading/build_corpus.py --database db

Each item pairs an advisory's prose (summary and details) with the affected
packages and version ranges that GitHub's reviewers recorded for it. The prose
is what a reader sees. The reviewed ranges are the answer key, and no reader
is shown them.

Selection, applied before sampling so that it cannot favour any reader:
  * reviewed, not withdrawn, Maven packages only
  * every range is one `introduced` and one `fixed` event
  * every version is dotted numeric, so the answer key needs no judgement calls
An item is `answerable` when every fixed version, and every stated first
affected version, appears in the prose. For the rest, the correct behaviour is
to give no answer.
"""
from __future__ import annotations

import argparse
import json
import random
import re
import subprocess
from pathlib import Path

from predict_shield.advisory_reader import MAX_TEXT_CHARS, mentions

NUMERIC = re.compile(r"^\d+(\.\d+){1,3}$")


def load(path: Path) -> dict | None:
    data = json.loads(path.read_text(encoding="utf-8"))
    affected = data.get("affected", [])
    if data.get("withdrawn") or not affected:
        return None
    truth: dict[str, list] = {}
    for entry in affected:
        if entry.get("package", {}).get("ecosystem") != "Maven" or not entry.get("ranges"):
            return None
        for item in entry["ranges"]:
            events = item.get("events", [])
            introduced = [e["introduced"] for e in events if "introduced" in e]
            fixed = [e["fixed"] for e in events if "fixed" in e]
            if item.get("type") != "ECOSYSTEM" or len(events) != 2 or len(introduced) != 1 or len(fixed) != 1:
                return None
            if not NUMERIC.match(fixed[0]) or (introduced[0] != "0" and not NUMERIC.match(introduced[0])):
                return None
            pair = {"introduced": None if introduced[0] == "0" else introduced[0], "fixed": fixed[0]}
            if pair not in truth.setdefault(entry["package"]["name"], []):
                truth[entry["package"]["name"]].append(pair)
    text = (data.get("summary", "") + "\n\n" + data.get("details", "")).strip()[:MAX_TEXT_CHARS]
    answerable = all(mentions(text, r["fixed"]) and (r["introduced"] is None or mentions(text, r["introduced"]))
                     for ranges in truth.values() for r in ranges)
    return {"id": data["id"], "aliases": data.get("aliases", []), "published": data.get("published", "")[:10],
            "text": text, "answerable": answerable,
            "truth": [{"package": p, "ranges": r} for p, r in sorted(truth.items())]}


def just_below(version: str) -> str | None:
    parts = version.split(".")
    if int(parts[-1]) == 0:
        return None
    return ".".join(parts[:-1] + [str(int(parts[-1]) - 1)])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--year", default="2026")
    parser.add_argument("--answerable", type=int, default=80)
    parser.add_argument("--unanswerable", type=int, default=40)
    parser.add_argument("--seed", type=int, default=20261114)
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("corpus.json"))
    args = parser.parse_args()

    root = args.database / "advisories" / "github-reviewed"
    pool = sorted((item for item in (load(p) for p in sorted(root.rglob("*.json"))) if item),
                  key=lambda item: item["id"])
    recent = [item for item in pool if item["published"].startswith(args.year)]
    rng = random.Random(args.seed)
    chosen = (rng.sample([i for i in recent if i["answerable"]], args.answerable)
              + rng.sample([i for i in recent if not i["answerable"]], args.unanswerable))
    chosen.sort(key=lambda item: item["id"])

    # Inventory: versions on both sides of every boundary in the answer key.
    inventory: dict[str, set[str]] = {}
    for item in chosen:
        for entry in item["truth"]:
            versions = inventory.setdefault(entry["package"], set())
            for r in entry["ranges"]:
                versions.add(r["fixed"])
                versions.update(v for v in (just_below(r["fixed"]), r["introduced"],
                                            just_below(r["introduced"]) if r["introduced"] else None) if v)
    # Distractors: other real packages, favouring ones that share a group with a corpus package.
    groups = {p.split(":")[0] for p in inventory}
    others: dict[str, str] = {}
    for item in pool:
        for entry in item["truth"]:
            others.setdefault(entry["package"], entry["ranges"][0]["fixed"])
    siblings = sorted(p for p in others if p not in inventory and p.split(":")[0] in groups)
    unrelated = sorted(p for p in others if p not in inventory and p.split(":")[0] not in groups)
    distractors = rng.sample(siblings, min(len(siblings), 60)) + rng.sample(unrelated, min(len(unrelated), 60))
    for package in distractors:
        inventory[package] = {others[package]}

    commit = subprocess.run(["git", "-C", str(args.database), "rev-parse", "HEAD"],
                            capture_output=True, text=True).stdout.strip()
    corpus = {
        "schema": "predict-shield/advisory-reading-corpus/1",
        "source": "GitHub Advisory Database (https://github.com/github/advisory-database), CC BY 4.0",
        "source_commit": commit, "seed": args.seed, "year": args.year,
        "note": "Advisory text and answer key are from the source. Inventory versions are derived from "
                "the answer-key boundaries and may not all be released versions.",
        "inventory": {p: sorted(v) for p, v in sorted(inventory.items())},
        "distractor_packages": sorted(distractors),
        "items": chosen,
    }
    args.output.write_text(json.dumps(corpus, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{len(chosen)} advisories ({args.answerable} answerable), {len(inventory)} inventory packages, "
          f"source commit {commit[:12]}")


if __name__ == "__main__":
    main()
