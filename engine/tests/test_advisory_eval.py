import json
import unittest
from pathlib import Path

from predict_shield.advisory_eval import evaluate, score_item
from predict_shield.advisory_reader import (ArtifactNameRuleReader, CoordinateRuleReader,
                                            ModelAdvisoryReader, validate_reply)
from scripted_model import ScriptedModel, reading

DIRECTORY = Path(__file__).resolve().parents[2] / "experiment-a" / "advisory-reading"
ITEM = {"id": "TEST-1", "answerable": True, "text": "Example Logging Core before 2.17.1 is vulnerable.",
        "truth": [{"package": "org.example:logging-core", "ranges": [{"introduced": None, "fixed": "2.17.1"}]}]}
INVENTORY = {"org.example:logging-core": ["2.17.0", "2.17.1"], "org.example:logging-facade": ["2.17.0"]}


def scored(reply):
    result = validate_reply(json.dumps(reply), ITEM["text"], INVENTORY, "m")
    return score_item(result, ITEM, INVENTORY)


class ScoringTests(unittest.TestCase):
    def test_correct_wrong_and_no_answer(self):
        self.assertEqual(scored(reading("org.example:logging-core", "2.17.1"))["outcome"], "correct")
        wrong = scored(reading("org.example:logging-facade", "2.17.1"))
        self.assertEqual(wrong["outcome"], "wrong")
        self.assertEqual(wrong["missed"], [["org.example:logging-core", "2.17.0"]])
        self.assertEqual(wrong["extra"], [["org.example:logging-facade", "2.17.0"]])
        self.assertEqual(scored({"affected": []})["outcome"], "no_answer")
        self.assertEqual(scored(reading("org.example:invented", "2.17.1"))["outcome"], "no_answer")

    def test_readers_are_compared_on_the_same_items(self):
        corpus = {"inventory": INVENTORY, "items": [ITEM, dict(ITEM, id="TEST-2", answerable=False)]}
        model = ModelAdvisoryReader(ScriptedModel([("Advisory text", reading("org.example:logging-core", "2.17.1"))]))
        report = evaluate(corpus, [CoordinateRuleReader(), model])
        self.assertEqual(report["readers"]["rule:coordinate"]["summary"]["all"]["no_answer"], 2)
        self.assertEqual(report["readers"]["model:scripted"]["summary"]["answerable"]["correct"], 1)


class CommittedCorpusTests(unittest.TestCase):
    def setUp(self):
        self.corpus = json.loads((DIRECTORY / "corpus.json").read_text(encoding="utf-8"))

    def test_corpus_shape(self):
        items = self.corpus["items"]
        self.assertEqual((len(items), sum(i["answerable"] for i in items)), (120, 80))
        self.assertEqual(len({i["id"] for i in items}), 120)
        for item in items:
            self.assertTrue(all(e["package"] in self.corpus["inventory"] for e in item["truth"]))

    def test_committed_rule_baseline_is_reproducible(self):
        committed = json.loads((DIRECTORY / "baseline-results.json").read_text(encoding="utf-8"))
        report = evaluate(self.corpus, [CoordinateRuleReader(), ArtifactNameRuleReader()])
        for name, result in report["readers"].items():
            self.assertEqual(result["summary"], committed["readers"][name]["summary"])


if __name__ == "__main__":
    unittest.main()
