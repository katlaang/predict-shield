# External cybersecurity data registry and ingestion

Sources and checksums are taken from each publisher's record, **not** from a successful download by PREDICT-SHIELD. The registry explicitly distinguishes publisher-verified and locally-ingested status. No downloaded data, credentials, or telemetry is committed to the repository.

- `python registry.py validate`: validate metadata, environment identities, license gating and checksum syntax.
- `python registry.py list`: print source, license, environment and operational use.
- `python registry.py download --dataset soc-mld-v2 --file SOC-MLD-v1.zip --output /tmp/soc.zip`: small, explicitly licensed pinned download. Each download verifies the published checksum before exposing a file.
- CAM-LDS requires `--max-mb 250` to opt into the published ~160.5 MB scenario archive. Never download ~7.4 GB as part of regular CI.
- `python registry.py inspect --archive /tmp/cam.zip`: inspect archive member paths and identify candidate Wazuh/Suricata/attack timeline files **without extraction**.
- `python registry.py correlate --archive /tmp/cam.zip --host-member path/to/wazuh.json --network-member path/to/eve.json --output /tmp/cam-pairs.json`: correlate explicit JSONL events by timestamp and shared IP, preserving **UNKNOWN** labels. The numeric co-occurrence count is not a detection accuracy estimate.

Collection environment is mandatory for every source; grouping records from the same collection under different filenames does not prove cross-network generalization. CAM-LDS has **no simulated benign user traffic**; do not compute a production false-positive rate from it. Label evaluation may be added only after verifying `attacker/logs/attackmate.json` ground truth and timestamps.

Do not unzip untrusted archives directly. The ingester reads one selected member at a time with size bounds. Large data is an explicit offline pilot.

Publisher records: https://zenodo.org/records/18861762 (CAM-LDS CC BY 4.0, scenario_2_cron MD5 c33aca73d6962414bd6c2c3f82b934c4); https://zenodo.org/records/23116148 (SOC-MLD CC BY 4.0, MD5 764ca570a35753a90f6ac3046750c716); https://zenodo.org/records/7958259 (CTU-SME-11 CC BY 4.0). Attributions required for redistribution and published analyses.
