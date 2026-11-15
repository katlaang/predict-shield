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

## Model readers

### Comparison run (preregistered 2026-11-15, measured)

This section was written before the run's numbers were known, so the comparison can't be read backward into a predetermined conclusion.

**Research question.** Does a security-domain-tuned model read advisory prose more accurately than a small general model, and does either stay within the wrong-answer ceiling the artifact-name rule already set? This is not a test of AI against a human analyst, and a single run on one corpus does not establish which model is better in general, only on these 120 advisories.

**Models compared.**

| Role | Model | Source |
| --- | --- | --- |
| General, no security tuning | `qwen3:0.6b` | Ollama library |
| Security-domain-tuned | `hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF:Q4_K_M` | Ollama, pulled from Hugging Face |

**Execution environment (fixed before the run, not tuned after seeing a result).**

- Workflow: [`.github/workflows/advisory-reading-model-comparison.yml`](../../.github/workflows/advisory-reading-model-comparison.yml), job `advisory-reading-comparison`, GitHub-hosted `ubuntu-latest` runner.
- One CPU-only `ollama/ollama:latest` container, one model loaded at a time (`OLLAMA_MAX_LOADED_MODELS=1`, `OLLAMA_NUM_PARALLEL=1`), `OLLAMA_CONTEXT_LENGTH=4096`, container memory capped at 7 GiB with an equal swap cap.
- Harness: `predict_shield.advisory_eval`, same corpus (`corpus.json`, 120 advisories, 80 answerable / 40 not answerable) and same scoring table as the rule baseline above, so all three readers' numbers are directly comparable.
- Every prompt and reply is recorded to `experiment-a/advisory-reading/recordings/` and archived as a run artifact, so the result can be replayed later with `--model recorded:<file>` without the model, a key, or a provider present.
- Run record: run ID `43704208571`, commit `a0d34b4` (merged to master as `0f69ae2`, PR #102). [Run log](https://github.com/katlaang/predict-shield/actions/runs/43704208571); report artifact `advisory-reading-120-model-comparison` (ID `14159051663`). A separate run, `43704195578`, was triggered by the same PR's own check re-run at nearly the same moment and sat queued for hours before being superseded and cancelled once this run's result was confirmed; it is not the source of the numbers below.

**Primary measure, fixed in advance.** Correct answers on the 80 answerable advisories, subject to no more total wrong answers (across all 120) than the artifact-name rule's 7 (4 on answerable + 3 on not-answerable). A model that answers more wrong than that does not get credit for extra correct answers; a wrong answer is the costly outcome the pipeline would act on, so it is the binding constraint, not the correct count.

**What would count as each outcome:**

- *Security-tuned model wins:* more correct on the 80 answerable advisories than both qwen3:0.6b and the artifact-name rule, at or under the 7-wrong ceiling.
- *Ties or loses:* at or below the rule's correct count, or exceeds the wrong-answer ceiling. Given the pattern already seen elsewhere in this repo on other advisory/action tasks (models roughly tying or losing to a strong deterministic baseline in most settings measured so far), this is the outcome treated as unsurprising, not the one being hoped for.
- *No answer from either model on most items:* reported as-is; an abstention-heavy result is not re-run with a different prompt to chase a better number.

**Result:** ties or loses, for both models, against the preregistered criteria above.

| Reader | Answerable (80): correct | wrong | Not answerable (40): wrong | Total wrong |
| --- | --- | --- | --- | --- |
| Artifact name rule (baseline) | 7 | 4 | 3 | 7 |
| qwen3:0.6b (general) | 8 | 11 | 0 | 11 |
| Foundation-Sec-8B (security-tuned) | 0 | 0 | 0 | 0 |

- **qwen3:0.6b** answered one more advisory correctly than the rule (8 vs. 7), but its 11 wrong answers on the answerable set alone already exceed the 7-wrong ceiling the rule set. Per the primary measure fixed in advance, it does not get credit for the extra correct answer: this is a loss.
- **Foundation-Sec-8B**, the security-domain-tuned model, scored 0 correct and 0 wrong on all 120 advisories, meaning it gave no answer at all, on every single one, including the 80 it should have been able to answer from the text. This is not a close loss; it is a model that abstained universally under this harness's exact prompt and parsing. Per preregistration, an abstention-heavy result is reported as-is, not re-run with a different prompt to chase a better number, so no attempt was made here to tune around it. Whether that is a property of the model, the quantization used, or the prompt format is an open question for a separate run, not answered by this one.
- Neither model wins. This matches the pattern already seen elsewhere in this repository on other advisory and action-selection tasks: automation has value as a shortlist generator even where it is not yet beating a well-built fixed rule, and no claim of AI superiority is made here.

Full output: `model-results.json` and `recordings/`, archived as the run's `advisory-reading-120-model-comparison` artifact (not committed to the repository; see the run log above to retrieve it).

### How to reproduce or extend this run

To add another model or run it yourself, either serve an open-weight model locally with [Ollama](https://ollama.com), or use a hosted API that serves the same open weights ([Featherless](https://featherless.ai), [Together](https://together.ai)). A hosted run sends the 120 advisories' text and the inventory's package list to that provider; export its key first (`FEATHERLESS_API_KEY` or `TOGETHER_API_KEY`), never on the command line, where it would land in shell history.

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

Before running, fix in writing which models and versions will be compared and what counts as a better result, the same way the run above does.

## Limits

- A hosted run sends advisory text and inventory package names to that provider. The advisories here are public; the inventory's package list and versions are synthetic test fixtures, not a real deployment's inventory. Running this against a real inventory through a hosted API is a different decision than running it locally, and should be made separately.
- One ecosystem, one year, 120 advisories. Dotted numeric versions only.
- The pattern rule is a simple baseline. A more elaborate rule would score higher.
- The shortlist that keeps the prompt short offers every affected package for 114 of the 120 advisories, so a model reader cannot be fully correct on the other 6.
- The advisories are public. A model trained after their publication may have seen them. The reader accepts a version only if the advisory text states it, which limits what recall of training data can contribute, and the model's training cutoff should be reported with any result.
- Ranges with no fixed release ("through 2.4.0" with no fix stated) are outside this version. Readers give no answer for them.

## Attribution

Advisory text and ranges are from the GitHub Advisory Database, licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Source commit is recorded in `corpus.json`. Text is truncated to 6,000 characters. Inventory versions are derived from the range boundaries and may not all be released versions.
