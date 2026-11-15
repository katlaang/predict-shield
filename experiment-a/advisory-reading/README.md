# Advisory reading: rules against language models

The first decision in a case is which inventory packages an advisory affects. Advisories are prose and name products the way people do. Inventories list package coordinates. This experiment measures how well different readers connect the two.

## Corpus

`corpus.json` holds 120 advisories from the [GitHub Advisory Database](https://github.com/github/advisory-database), all published in 2026 and all for Maven packages.

- **What a reader sees:** the advisory's summary and details text, and the list of 236 packages in the inventory.
- **Answer key:** the affected packages and version ranges that GitHub's reviewers recorded. No reader is shown them.
- **Inventory:** every package in the answer key, at versions on both sides of each range boundary, plus 120 other real packages as distractors. Half of the distractors share a group with a corpus package.
- **Answerable:** in 80 advisories the text states every version in the answer key. In the other 40 it does not, and the correct behaviour is to give no answer.

`build_corpus.py` rebuilds the file from a checkout of the database. The selection rules are in its header and were applied before sampling.

## Scoring

A reader's answer is applied to the inventory and compared with the answer key.

| Outcome | Meaning |
| --- | --- |
| correct | The reader marked exactly the versions the answer key marks |
| wrong | The reader answered and marked a different set |
| no answer | The reader abstained, or a check refused its answer |

A wrong answer is the costly one, because the pipeline would act on it.

## Rule baseline (measured)

| Reader | Answerable (80): correct | wrong | no answer | Not answerable (40): wrong |
| --- | --- | --- | --- | --- |
| Exact coordinate in text | 1 | 0 | 79 | 1 |
| Artifact name in text, pattern-matched versions | 7 | 4 | 69 | 3 |

Full output: `baseline-results.json`. The engine tests reproduce these numbers from the corpus.

The rules fail for two reasons. In 44 of the 80 answerable advisories the text never uses the artifact name, and in 25 more it lists several fixed release lines, which the pattern rule treats as ambiguous.

## Model readers (not yet measured)

No model result is recorded here yet. To produce one, either serve an open-weight model locally with [Ollama](https://ollama.com), or use a hosted API that serves the same open weights ([Featherless](https://featherless.ai), [Together](https://together.ai)). A hosted run sends the 120 advisories' text and the inventory's package list to that provider; export its key first (`FEATHERLESS_API_KEY` or `TOGETHER_API_KEY`), never on the command line, where it would land in shell history.

```bash
# local
PYTHONPATH=engine python -m predict_shield.advisory_eval \
    --model ollama:<security-tuned model> --model ollama:<general model> \
    --record-dir experiment-a/advisory-reading/recordings \
    --output experiment-a/advisory-reading/model-results.json

# hosted API
PYTHONPATH=engine python -m predict_shield.advisory_eval \
    --model featherless:fdtn-ai/Foundation-Sec-8B-Reasoning --model together:<general model> \
    --record-dir experiment-a/advisory-reading/recordings \
    --output experiment-a/advisory-reading/model-results.json
```

`--record-dir` saves every prompt and reply, never the API key. Commit the recordings with the results so the run can be replayed with `--model recorded:<file>` and audited without the model, the key, or the provider present.

Before running, fix in writing which models and versions will be compared and what counts as a better result. Suggested primary measure: correct answers on the 80 answerable advisories, subject to no more wrong answers than the artifact-name rule on all 120.

## Limits

- A hosted run sends advisory text and inventory package names to that provider. The advisories here are public; the inventory's package list and versions are synthetic test fixtures, not a real deployment's inventory. Running this against a real inventory through a hosted API is a different decision than running it locally, and should be made separately.
- One ecosystem, one year, 120 advisories. Dotted numeric versions only.
- The pattern rule is a simple baseline. A more elaborate rule would score higher.
- The shortlist that keeps the prompt short offers every affected package for 114 of the 120 advisories, so a model reader cannot be fully correct on the other 6.
- The advisories are public. A model trained after their publication may have seen them. The reader accepts a version only if the advisory text states it, which limits what recall of training data can contribute, and the model's training cutoff should be reported with any result.
- Ranges with no fixed release ("through 2.4.0" with no fix stated) are outside this version. Readers give no answer for them.

## Attribution

Advisory text and ranges are from the GitHub Advisory Database, licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Source commit is recorded in `corpus.json`. Text is truncated to 6,000 characters. Inventory versions are derived from the range boundaries and may not all be released versions.
