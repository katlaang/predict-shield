# Cross-dataset flow detector, version 2

Version 1 (`experiment-b/cic-flow/`) detected 99.97% of CSE-CIC-IDS2018
attack flows but alerted on 30.85% of benign flows, against a 1% budget,
because thresholds set on 2017 benign traffic did not carry over. Version 2
changes the design in response, fixed in `protocol_v2.json` before any version
2 result:

- **Calibrate on the protected network.** The anomaly model and both
  thresholds are set on the first 2018 day's flows, without reading their
  labels, the way a deployment would use its first day. That day is then
  excluded; the other nine days are scored once.
- **No per-source context.** Per-source counts let the model learn which
  machine attacked. Only per-destination counts remain.
- **Context in time order.** Flows are sorted by timestamp before the 60-second
  counts are computed; out-of-order rows are counted and reported.
- **Code in the freeze.** The feature, scoring and protocol files are hashed
  into the freeze, and the test stage refuses to run if any changed.
- **Development by day.** 2017 results are reported leave-one-day-out, with
  each held-out day calibrated the same way as the 2018 calibration day.

Pass condition, stated in advance: benign alert rate at most 1% pooled and on
every test day.

Version 1 read every 2018 label, so this is a second measurement on the same
data, not an untouched test. The version 1 result stays on record.
