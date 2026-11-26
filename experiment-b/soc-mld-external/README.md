# SOC-MLD inspection (no detection run)

Structure inspection of SOC-MLD v1.0 (Zenodo record 23116148, CC BY 4.0), made before any detection protocol, to decide whether it can test the DVWA v3 method (per-field request profiles and calibrated fusion) on traffic from another environment.

**Decision: not used for detection scoring.** The publisher's `code/extract_features.py` labels requests in two steps. First, each of the 5,840 L7 label events is assigned to the single nearest unused request within 30 s. Second, every other request (about 192,000 of 198,082) is labelled by `label_l7_payload()`, the publisher's own payload pattern rule, which returns NORMAL when nothing matches.

Request-level labels therefore mostly reproduce a signature detector. A detector scored against them would measure agreement with those patterns, and attacks the patterns missed would count as false alarms.

Other limits:

- All traffic, benign and attack, comes from one source IP.
- The label file records step start times without end times.

Files:

- `inspect_schema.py`: archive members, columns, label-like value counts.
- `inspect_raw.py`: raw log and label formats, and how curated request ids relate to the log.
- `show_labeling.py`: prints the labelling parts of the publisher's script. It reads the script and does not run it.
- Workflow: `.github/workflows/soc-mld-inspect.yml` (download with publisher checksum, then inspection only).
