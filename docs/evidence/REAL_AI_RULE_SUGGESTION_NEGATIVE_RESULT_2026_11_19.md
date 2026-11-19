# Real AI detection-rule experiment: measured negative result (2026-11-19)

**Source:** GitHub Actions run
https://github.com/katlaang/predict-shield/actions/runs/44470495011

**Frozen artifact:** `ai-rule-suggestion` (ID `14506416081`).
The archived files are `ps-ai-rules-local.json` and
`ps-ai-rules-local-audit.json`. The model digest is
`sha256:359d7dd4bcdab3d86b87d73ac27966f4dbb9f5efdfcc75d34a8764a09474fae7`.

## Measured findings

| Metric | Actual result |
| --- | --- |
| Local model | Ollama `qwen3:4b` |
| Target ATT&CK techniques | 5 |
| Model responses attempted | 5 |
| Successfully parsed JSON replies | **0 of 5** |
| Grammar-valid proposed rules | **0** |
| Accepted rules after development gate | **0** |
| Scored held-out attack recordings | **33** |
| Held-out scenarios detected | **0 of 33** |
| Held-out events processed | **130,176** |
| Independent report-integrity audit | Passed, with no structural issues |

Per-technique attack-recording coverage: T1562.001 0/11,
T1059.001 0/10, T1053.005 0/5, T1036.003 0/3 and T1047 0/4.

A green workflow therefore meant **the experiment and its audit ran**,
not that the AI successfully detected any attacks.

The model returned a large copied `event_summaries` object on each
attempt, with approximately 4.8–5.2 KB of output, cut off before a complete
JSON object could be formed. Every reply was rejected as malformed JSON.
No invalid rule was executed or accepted, and none of these observations
provides an event-level detection recall or false-positive rate.

## Corrective development, not retroactive success

The next change provides a bounded development-only evidence prompt,
explicit direction not to echo the evidence, and Ollama's official
JSON-schema-constrained output format. The project's local rule grammar,
development acceptance gate and independent result audit remain mandatory.

These fixes make well-formed model output more plausible. **They do not
establish that the model learns useful rules or that rules pass the gate.**
If the revised model again produces no admissible rules, that result
must be retained and investigated.

**The original 33-recording evaluation set is no longer unseen to the
researchers.** Any repeat using that set after modifying prompts or
constraints must be explicitly labeled exploratory. It cannot count as a
new independent held-out validation. Before making a new prospective
accuracy claim, freeze an untouched evaluation population and publish
its actual independent label/provenance checks.

Source for constrained decoding:
https://docs.ollama.com/capabilities/structured-outputs
