# CTU-13: independent labeled network-flow AI detection experiment

**Implementation status:** Parser, deterministic stratified sampling, scenario-level
train/calibration/test separation, a real sklearn logistic baseline, SHA-256
checks and negative tests are implemented. **Actual CTU-13 source files have
NOT been downloaded, processed, or measured by repository CI in this change.**
CI tests use synthetic sample rows; it cannot establish real detection
accuracy. Do not report the synthetic classifier's scores as scientific
results.

## Source and interpretation

Official publisher: https://www.stratosphereips.org/datasets-ctu13/

CTU-13 (Stratosphere Laboratory / Czech Technical University) contains
thirteen 2011 network captures with manually labeled **bidirectional
NetFlows**. The publisher describes three principal categories:

- **From-Botnet:** originated at a known infected host; positive label for
  this deliberately narrow *known-botnet-source flow classification*.
- **From-Normal:** originated at a registered known normal host; negative label.
- **To-Botnet / To-Normal:** may originate from unknown computers, and the
  publisher specifically says they must **not** be labeled malicious or
  legitimate by destination alone. Treat them as **UNKNOWN**.
- **Background and all other labels:** UNKNOWN. Exclude from supervised
  positive/negative denominators but report the counts separately.

The parser explicitly rejects the naive substring method that would
misclassify To-Botnet / To-Normal by label name alone. The source README
for scenario 42 provides the original warning:
https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/README.html

The parser also excludes all ambiguous and unrecognized labels. This does
not equate a Botnet flow to a complete independent incident adjudication,
and does not make results transferable to present-day electric substations,
small ISPs or U.S. critical infrastructure.

## Local-only data protocol

Download selected CTU-13 **`.binetflow` text files** from the official
scenario directories (not executable malware samples). The full publisher
archive is approximately 1.9 GB; data may be downloaded capture by capture.
Record original URLs, scenario IDs, original file digests, retrieval date,
license and permitted redistribution independently. Do not place huge
captures or raw IP data in the public repository.

Pre-register a JSON manifest **before fitting or examining test labels**:

```json
{
  "schema": "predict-shield/ctu13-flow-protocol/1",
  "sample_cap_per_label_per_scenario": 10000,
  "scenarios": [
    {
      "scenario_id": "CTU-42",
      "split": "train",
      "file": "capture-42.binetflow",
      "sha256": "<real lowercase 64-hex SHA-256 of this exact file>"
    },
    {
      "scenario_id": "CTU-43",
      "split": "calibration",
      "file": "capture-43.binetflow",
      "sha256": "<real lowercase 64-hex SHA-256 of this exact file>"
    },
    {
      "scenario_id": "CTU-44",
      "split": "test",
      "file": "capture-44.binetflow",
      "sha256": "<real lowercase 64-hex SHA-256 of this exact file>"
    }
  ]
}
```

Replace every placeholder with a **measured** digest. Larger, multiple
scenario groups are recommended. The example is instructional, not an
assertion that these three scenarios satisfy class balance. A valid run
requires actual labeled flows, one or more scenarios per partition, and
both train classes. The parser rejects missing files or hashes and does
not fetch anything from arbitrary websites.

```bash
python -m pip install scikit-learn==1.7.2
python experiment-b/ctu13-flow/fit_evaluate.py \
  --manifest /secure/research/ctu13-manifest.json \
  --data-root /secure/research/ctu13-files \
  --output /secure/research/reports/ctu13-evaluation.json
```

The code computes all provided source-file SHA-256 digests **before**
using their rows, and rejects a mismatch. It excludes IPs, start timestamps
and scenario IDs from features to mitigate direct capture-specific leakage.
Features are durations, packet/byte counts and protocol categories. The
model uses class-balanced logistic regression, fixed threshold 0.5 and no
test-label tuning. No production action is connected.

## Required result reporting

- Source identity and SHA, file-level and scenario-level train/test split.
- Total From-Botnet, From-Normal, UNKNOWN (including To-* and Background)
  and malformed counts per scenario.
- Number of stratified sampled attack and benign flows. Class-stratified
  subsampling changes class prevalence.
- Exact test TP, FP, FN, TN; sample recall, precision and FPR; confidence
  intervals across independent scenario groups should be added before
  research publication.
- Actual sample/model versions; attempted runs, exceptions and failed
  workflows, including unexpected missing classes.
- Precision from the stratified sample is **NOT operational precision**.
  Flow-level repetitions within a scenario are dependent and should
  not be treated as independent operators or independent incidents.
- Historical 2011 botnets are not 2026 U.S. infrastructure traffic.

## Next gating steps

1. Acquire and validate approved CTU-13 files, freeze a multi-scenario
   manifest and publish its SHA without uploading private host details.
2. Execute the real benchmark, preserve every result and report group-level
   uncertainties and minority-class metrics.
3. Add a separate benign-only operational-duration evaluation with
   false-alerts-per-host-day and alert latency.
4. Run the real detection-to-intake-to-authorization-to-response chain in
   an isolated emulator, with independent post-action probes.
5. For energy systems, follow with real virtual-switch and power/communications
   **coupled** simulation before claiming grid resilience.

Original publication: Sebastián García, Martin Grill, Jan Stiborek and
Alejandro Zunino, "An empirical comparison of botnet detection methods,"
Computers & Security 45 (2014) 100–123.
https://doi.org/10.1016/j.cose.2014.05.011
