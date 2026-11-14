# Actual physical AI defense selection pilot

**Registration date:** November 14, 2026. **Research scope:** exploratory, not a replacement for the original frozen v3 1,200-action protocol or uninspected confirmatory v3.1 study.

## Question

Given only an operator-observable pre-action snapshot and declared action restrictions, can a trained random-forest action selector choose lower-regret defenses than fixed and telemetry-based deterministic rules on separately configured Kafka/JVM faults?

## Physical experiment

- Deterministically sample **24 distinct configurations** from the existing physical v3 mechanism-lab generator, balanced across four supported fault families (loss/delay/duplicate/reorder) and three difficulty strata (two per cell).
- Lock **12 training / 6 calibration / 6 held-out test configuration groups** before any physical execution. A configuration, not an action or HTTP request, is the independent evaluation unit.
- Physically replay **four actions once per configuration**, using new lab resets: **96 measured actions**. Each produces four integrity-audited streams (pre-action, verification, operations, privileged oracle).
- Use one group's **monitor-only pre-action snapshot** for all four action predictions, so action-specific pre-action variation cannot inform the prediction. Train on features from existing `train.to_features`, including nonprivileged operational telemetry and action identity; injected fault identity and after-action oracle values are never features.
- Predict three measured components via separately fitted `RandomForestRegressor` models: sampled upper-bound path exposure, independently verified remaining control exposure, and failed authorized/legitimate requests. Apply the preexisting 0.50/0.25/0.25 utility and fixed observed-error allowance. This is a research utility, not a real remaining SLO budget.
- Compare seven deterministic policies: fixed resync, fixed restrict, fixed monitor, restart-when-permitted otherwise restrict, engineering rule, telemetry rule, and training-fitted rule grid.
- Select **one strong comparator only using six calibration groups**. Test AI choices and all seven rule choices on **six untouched held-out groups**, reporting each action decision and measured hindsight regret. Bootstrap whole groups 2,000 times for a paired exploratory 95% interval.
- Record the actual Git commit, registration hash, four-stream audit counts, source schema, held-out decisions and both positive **and negative** results, with a SHA-256 artifact checksum.

## What can and cannot be concluded

If the mean AI regret is below the selected deterministic baseline, that is **an observed exploratory result in these six configurations**, not proof that the AI is generally better. If the interval overlaps zero, or if another of the seven comparators performs better, those negative limitations must be reported. A favorable result does not authorize a security action.

This pilot has **one actual replay per action/configuration**, **only six independent held-out configurations**, and uses four already studied physical fault mechanisms. It is not a new blind population, not a complete 150 × 4 × 2 six-family study, and not an evaluation of authority-outage UNKNOWN utility. No U.S. critical-infrastructure operator is involved.

The later strict validation already defined in `decision_superiority_audit.py` requires a full real measured data set and at least 20 untouched held-out groups plus conservative multiple-baseline checks. The confirmatory protocol must be frozen before collecting those test outcomes. The model does not control Docker or production systems.

## Run and inspect

The public GitHub Actions workflow `.github/workflows/ai-physical-decision-pilot.yml` executes the real lab on an isolated runner and uploads only sanitized summary results.

From a disposable lab clone:

```bash
# Set LAB_CONTROL_TOKEN, LAB_ORACLE_TOKEN, LAB_INTERNAL_TOKEN to distinct disposable values
docker compose up --build -d
python run_actual_ai_pilot.py --execute-lab \
  --root /tmp/new-physical-ai-study --report reports/physical-ai-study.json
docker compose down --remove-orphans --volumes
```

A failed or incomplete physical run does not generate a positive report. Do not commit the raw four-stream oracle dataset or disposable lab credentials to the public repository.

**Evidence states:** `PLANNED_NOT_EXECUTED` in the registration is never a measured outcome; unit tests contain synthetic examples explicitly marked as such; only a green GitHub Actions run with 96 audited physical records may support an exploratory AI-versus-rule lab result.
