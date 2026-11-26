# DVWA correlation detector v2

The v2 detector learns an Isolation Forest from **benign-only** request-process-network-file rows and calibrates against later benign requests. It separately scores previously unseen executables/endpoints/files and learned HTTP response-structure deviations. The earlier v1 model and test artifacts are never overwritten.

The frozen protocol is `protocol.json`. The first-scored v2 run is [45881347517](https://github.com/katlaang/predict-shield/actions/runs/45881347517); it **FAILED** its registered detection target: 35/92 successful attacks caught at 3/500 benign alerts, with zero SQL-injection login detections. The complete first test is archived at `reports/first-scored-run-45881347517.json` and in `docs/evidence/MEASURED_DVWA_CORRELATION_V2_2026_11_26.md`.

The default PR CI runs *unit tests only* after the first scored evaluation; repeats of the same fixed-seed lab test are exploratory rather than fresh external evidence. Manual replay is allowed for debugging only and must be labeled exploratory. To establish an independent next result, register new seeds and evaluation scope before running another test.

The lab uses the original pinned DVWA project and local loopback MariaDB/strace. Nothing in this directory performs defensive changes on an external target.
