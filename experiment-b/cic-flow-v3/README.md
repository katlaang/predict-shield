# Cross-dataset flow detector, version 3

Version 2 met its false-alarm ceiling on CSE-CIC-IDS2018 but detected 0.83%
of attack flows (`docs/evidence/MEASURED_CROSS_DATASET_FLOW_DETECTOR_V2_2026_11_20.md`).
Version 3 makes the four changes that evidence named, fixed in
`protocol_v3.json` before any HIKARI-2021 flow is read:

- **Verified-normal calibration.** The anomaly model and both thresholds use only flows marked normal on the network being calibrated. Code refuses to run if an attack enters that set.
- **A detection floor.** The pass condition requires at least 50% of attack flows detected. False alarms must stay at or below 1%, both pooled and for each normal category.
- **Training fit beside held-out results.** Model size and feature set are chosen on development data by a fixed rule (leave one network out), and a learning curve is reported.
- **Two training networks.** CIC-IDS2017 and CSE-CIC-IDS2018 are both development data. The final model is fitted on both.

The test network, HIKARI-2021, was captured with a different flow meter, the
Zeek flowmeter package. `features_v3.py` defines each of the 57 shared
statistics once, with its name in each tool. Zeek's flow duration is
converted from seconds to microseconds. Both tools already report
inter-arrival, active and idle times in microseconds. The units come from
each tool's documentation and source code, not from the test data.

| Stage | What it does |
|---|---|
| `develop` | Samples both CIC networks, runs the grid, chooses a configuration, fits it on both networks, and commits the freeze. It never reads HIKARI-2021. |
| `test` | Verifies the freeze and the HIKARI pin, then splits the file by flow uid. The Benign flows in buckets 0 and 1 calibrate the model. Every flow in buckets 2 to 9 is scored once. |

Benign and Background both count as normal when false alarms are measured.
Only Benign flows calibrate the model.
