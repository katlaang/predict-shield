# Historical detection error audit

This tool explains **where** the already-measured NSL-KDD detector missed labeled attack rows. It does **not** prove **why** those misses occurred and does not tune the detector.

Source experiment: [PR #137](https://github.com/katlaang/predict-shield/pull/137). Independently recorded measurements: [PR #138](https://github.com/katlaang/predict-shield/pull/138), GitHub Actions run 44648143458. The recorded confusion matrix is 8,580 TP, 4,253 FN, 274 FP, and 9,437 TN on 22,544 historical test rows.

Run after downloading the **original JSON result artifact** from that run (do not transcribe or invent a replacement):

~~~sh
python experiment-b/nsl-kdd-anomaly/audit_family_errors.py \
  --input /path/to/original-historical-report.json \
  --output /path/to/family-error-audit.json
python -m unittest discover -s experiment-b/nsl-kdd-anomaly -p 'test_audit_family_errors.py'
~~~

Auditor fail-closed checks:
- Original recorded confusion matrix and denominators cannot silently change.
- Family tested/detected totals must reconcile exactly with the global attack totals.
- Novel-by-label family roster must reconcile with the reported novelty counts.
- Missing, invalid, negative, or impossible counts are rejected.
- Historical and zero-day effectiveness claim flags must remain false.
- The output includes family miss counts, share of total missed rows, zero-recall families and both the source JSON's canonical SHA-256 and its exact downloaded file-byte SHA-256.

**Evidence boundary:** Synthetic unit fixtures check the auditor; they are not new attack-detection measurements. We have not established the cause of any family-level miss. We have neither per-record anomaly scores nor verified modern field labels in the published summary; these require separately scoped diagnostic collection and independent external evaluation.

**Next candidate-model gate:** Write and register a new model/features/training/calibration specification using only development data. Freeze feature extraction and threshold before any new independent holdout is accessed. Preserve all failure cases, operational alerts, and family-level results. Do not select candidate models or alarm thresholds on this already-tested historical holdout.

No AI response, anomaly score or audit output authorizes an operational action. The independent safety policy and verification remain mandatory.

The CI workflow now runs both `test_historical_benchmark` and `test_audit_family_errors`, then audits the regenerated historical report and uploads both artifacts. **A regenerated historical report is not the original run 44648143458 artifact and is not independent new evaluation data.** A separate check against the original downloaded artifact remains pending until that artifact is available and independently checked.
