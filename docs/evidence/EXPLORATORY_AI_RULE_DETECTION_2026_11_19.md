# November 19, 2026: real-model exploratory AI rule-generation checkpoint

**Historical run:** https://github.com/katlaang/predict-shield/actions/runs/44477985951

**Source artifact:** `ai-rule-suggestion`, GitHub Actions artifact ID `14506884192`.

The run's Ollama `qwen3:4b` model **completed all five model exchanges** and
the script finished development gating and the 33-recording scoring pass.
The workflow as a whole **FAILED** at its report-validation step with
`KeyError: 'accepted_set_sha256'`, because that step globbed the separate
`ps-ai-rules-local-progress.json` checkpoint and attempted to treat it as
a completed experiment report. This is a reporting-workflow defect, not a
model inference exception. The existing independent audit step was skipped.

The recorded completed report, inspected from the downloaded original
artifact, states:

| Recorded quantity | Result |
| --- | --- |
| Model | `ollama:qwen3:4b` |
| Exact model digest | `sha256:359d7dd4bcdab3d86b87d73ac27966f4dbb9f5efdfcc75d34a8764a09474fae7` |
| Accepted development-gated rules | **3** |
| Held-out attack-labelled recordings scored | **33** |
| Selected recordings with own-technique rule hits | **3** |
| Events processed in those recordings | **130,176** |
| Recordings with other-technique alerts | **2** |
| Frozen accepted-rule SHA-256 | `6fcc8b0fefe7220a871de78cf65fa34cbd4c6b99b53340b93c9f352ea446dcf7` |

Per-technique scenario hits: T1562.001 0/11, T1059.001 2/10,
T1053.005 1/5, T1036.003 0/3, and T1047 0/4.

**Important:** These are **exploratory**, because the 33 recordings had
already been tested using the previous prompt in
[run 44470495011](https://github.com/katlaang/predict-shield/actions/runs/44470495011).
The proposed rule improvements may reflect prompt revision after inspected
results, and the test set was **not freshly unseen**. The 3/33 figure is a
selected attack-recording hit count, **not attack-event recall**, a
false-positive rate, operational detection accuracy, or demonstrated AI
superiority. Cross-technique alerts in attack-labelled datasets cannot be
classified as false positives without event-level ground truth.

The separate newly introduced
`ai-rule-archived-result-audit.yml` uses the original run's archived JSON,
the registered source split file and the deterministic existing
`audit_report.py` auditor. It does not regenerate rules or load a model.
It must finish successfully before the repository can claim a
post-hoc, independently *structurally* audited result.

The immediate reporting fix restricts validation to the two named
**completed** files, excluding `*-progress.json`. Future model runs
continue to retain incomplete checkpoints for outages/timeouts.

**Next science requirements:** a newly frozen untouched evaluated
population, independently adjudicated attacks plus normal activity, actual
detection precision/recall/FPR with denominators and uncertainty, a baseline,
and isolation/latency/service-continuity measurements. None is established
by the record above.
