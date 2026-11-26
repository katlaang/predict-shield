# Superviz25-SQL reports

- `../frozen/test-report.json`: the single registered pass/fail test (run 45895391129).
- `baselines.json`: first baseline run (45906319077). **Its OWASP CRS figures are void.** The harness sent Python's default client headers, and CRS blocked every request at paranoia levels 3 and 4, benign probes included. The frozen-detector, libinjection and supervised figures in it are valid and are recomputed identically in the rerun.
- `baselines-rerun.json`: rerun with one fixed set of browser headers on every CRS request. Each level aborts unless benign probes pass. Use this file.
