# P1 operational-data adapters: LANL, UGR'16 and MAWILab

**State:** Implemented read-only local parsers and synthetic admission tests. **No operational dataset has been downloaded, authorized by a site administrator, or scored in this PR.** None of the output is an attack-detection accuracy estimate.

## Verified publisher formats and usage restrictions

| Dataset | Publisher / source | Adapter | Limits |
| --- | --- | --- | --- |
| LANL comprehensive 58-day events | https://csr.lanl.gov/data/cyber1/ | `lanl-auth`, `lanl-flow`, `lanl-dns`, `lanl-redteam` | Publisher offers file-specific downloads after a use-information form. Public-domain-like copyright waiver is published, but **access has not been exercised**. Red-team lines are only **partial positive indicators**, not complete negative labels. Dataset is very large (~12 GB compressed). |
| UGR'16 original ISP NetFlow | https://nesg.ugr.es/nesg-ugr16/ and https://nesg.ugr.es/nesg-ugr16/dataset_AuthorVersionFinal.pdf | `ugr16-flow` | CSV columns `te,td,sa,da,sp,dp,pr,flg,fwd,stos,pkt,byt` verified against original paper. Source reuse/license is **not independently confirmed**. Traffic scenarios are not complete per-flow benign ground truth. |
| MAWILab v1.1 anomaly CSV | https://www.fukuda-lab.org/mawilab/ | `mawilab-annotation` | CSV fields `anomalyID,srcIP,srcPort,dstIP,dstPort,taxonomy,heuristic,distance,nbDetectors,label`. Its anomaly classes are detector-generated annotations, **not independent confirmed exploits or benign traffic**. WIDE trace terms can differ from annotation terms. |
| Superviz26-SQL | https://zenodo.org/records/21068333 | Assigned to separate detection workstream | CC BY 4.0; a 2.4 GB archive and publisher-specified cross-domain splits; OurAirports domain duplicates Superviz25. No model work here. |

## Before ingesting real data

1. Obtain source files through the publisher or authorized owner. **Do not circumvent LANL's use form** or copy unofficial mirrors while provenance is unresolved.
2. Review allowed intended use and data security. Write a *local* authorization record, approved by the actual data custodian or a documented researcher with a legitimate use basis. This is an operator-controlled authorization assertion, not a digital signature.
3. Calculate the *compressed original source file* SHA-256 locally with `sha256sum /path/to/file.gz`.
4. Store a random persistent keyed-pseudonymization secret in `PREDICT_SHIELD_P1_HMAC_KEY` for the duration of the study, **never in git or CI logs**. A key rotation changes identity linkage.
5. Run the normalizer on the approved local file. It has no network access; it refuses altered file hashes, malformed formats, symlinks and overlarge records, and writes only a bounded sample with pseudonymous identity fields.
6. Keep full raw files outside the public repository. Keep normalized data, permission records, and source manifest in restricted storage. Do not treat the generated JSONL as a confirmed benign or malicious-labeled dataset.

An illustrative local authorization record (change `status` from `pending` only *after* reviewing real permission):

```json
{
  "source": "lanl-auth",
  "status": "pending",
  "official_url": "https://csr.lanl.gov/data/cyber1/",
  "authorized_purpose": "Controlled, read-only AI cybersecurity methodology evaluation",
  "reviewer": "ACTUAL_REVIEWER",
  "reviewed_on": "YYYY-MM-DD"
}
```

Use:

```bash
export PREDICT_SHIELD_P1_HMAC_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(40))')"
cd experiment-b/operational-sources
python normalize.py \
  --dataset lanl-auth \
  --source /private/authorized/auth.txt.gz \
  --expected-sha256 ACTUAL_64_HEX_SHA256 \
  --authorization-record /private/approved-dataset-rights.json \
  --max-records 10000 \
  --output /private/results/lanl-auth-normalized.jsonl
```

The tool never marks non-redteam authentication events benign, never converts MAWILab anomalies into attacks, and never labels UGR flows benign or malicious based on an unverified source campaign. For evaluation, independent reviewers must label and admit a separate cohort under `experiment-b/framework-readiness/cohort_guard.py`. The public data record alone is not production telemetry or evidence of effectiveness on a US critical-infrastructure site.

## Read-only cross-source asset-context correlation

Once two or more authorized source files have been normalized with **the same persistent secret**, the derived records carry a keyed `pseudonym_scope_id`. This prevents the framework from claiming it has joined the same asset when different data sources were normalized with different pseudonymization keys.

```bash
python context_graph.py \
  --input /private/results/lanl-auth-normalized.jsonl \
          /private/results/lanl-dns-normalized.jsonl \
          /private/results/lanl-flows-normalized.jsonl \
  --max-records 100000 \
  --output /private/results/pseudonymous-observed-graph.json
```

The graph reports only observed pseudonymous endpoints, directional event counts and selected evidence categories. It does not call any AI model, invent a complete inventory, label non-redteam activity benign, or convert MAWILab anomaly labels into verified attacks. An IAM/authentication failure or published red-team event is investigation evidence, **not authorization for remediation**. All input provenance must be complete; mixed secret scopes, duplicate events and malformed labels are rejected rather than silently joined.

This is a useful building block for **automated risk assessment** after the actual operator's asset owner, criticality, service dependencies and permissions have been independently validated.

## Implementation and test limitations

- Only LANL auth, flow, DNS and redteam formats and UGR'16 nfdump CSV and MAWILab anomaly-annotation CSV are supported. Other formats fail closed.
- A row identifier is the original file hash and original line number plus its line hash; a non-raw keyed identity is computed using HMAC-SHA256. This is **pseudonymization, not anonymization**.
- Raw text, source IPs, usernames and machine identifiers are not exported, but some nonidentifying attributes (authentication type, protocol category, duration) remain. Treat all output as potentially sensitive.
- Source permission records are local trust assertions; the parser cannot independently authenticate the signer's authority, nor prove downloaded source bytes originate from the publisher without a separately verified publisher hash.
- The CLI processes a bounded sample but hashes the entire compressed source file beforehand. This can be slow on large datasets; no accuracy is inferred from sampling.
- MAWILab anomaly CSV alone does not contain flow denominators required to calculate a false-positive rate. LANL red-team events have incomplete positive labeling and cannot establish a complete confusion matrix.
- Synthetic tests validate parsers and safety refusals, not deployed ingestion, real-data semantics, attack detection or AI defense selection.

## Next externally dependent steps

**LANL:** Submit use form, retrieve selected files (start with `redteam.txt.gz` and a permitted, bounded auth subset), verify sizes/hash, record source receipt and source-appropriate permissions. **UGR'16:** establish reuse terms and obtain a suitably sized weekly CSV from official publisher. **MAWILab:** record permission and pin one annotation file, with separately licensed trace needed for actual traffic validation. Then perform an independent human-labeled cohort review before any calibrated AI accuracy report.

Tracked in `docs/roadmap/FRAMEWORK_P0_P1_TRACKER.md`.
