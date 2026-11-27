# Framework P0/P1 readiness tools

**Purpose:** Allow PREDICT-SHIELD's research experiments to **refuse unverified data**, catch train/calibration/test leakage, and evaluate a frozen model threshold without using final-test benign labels to choose that threshold. This is a harness, not a trained detector or a measured external dataset result.

- `cohort_guard.py`: validates source rights review, publisher/provenance digests, local source bytes, capture group split isolation and independently reviewed event labels. `BLOCKED` is not a failed model; it means **no scientific metric is admissible yet**.
- `frozen_evaluator.py`: sets a strict greater-than alert threshold on 1000+ confirmed benign calibration scores **only**; never reads final-test scores to set the operating point; reports known attack, known benign and excluded unknown/scenario-only events separately.
- `test_cohort_guard.py` and `test_frozen_evaluator.py`: deterministic synthetic software tests only. They do **not** imply real-world performance or a model evaluation.
- `source_candidates.json`: candidates with pending permission/provenance checks. It is not a dataset import manifest.

### Run tests
```bash
cd experiment-b/framework-readiness
python -m unittest discover -s . -p 'test_*.py' -v
```

### Validate a real manifest locally
```bash
python cohort_guard.py /path/to/cohort.json --data-root /path/to/approved-files --output /path/to/fresh-audit.json
```
Required manifest: `schema="predict-shield/research-cohort-manifest/1"`, `protocol_sha256`, `sources` (id, official_url, rights_status, rights_evidence, sha256, relative_path), `rows` (id, source_id, capture_group, role, label, truth_basis, content_sha256). Source bytes are checked in place and never uploaded. The SHA-256 of every row must be unique across splits; all rows from a capture group must remain in one split. Independent event truth requires an auditable human/external process, not a string set by the experiment author.

```bash
python frozen_evaluator.py /path/to/scored-cohort.json --data-root /path/to/approved-files --model-sha256 <64-char-model-digest> --output /path/to/fresh-result.json
```

Add numeric `score` values to independently reviewed benign calibration and independently reviewed labeled final-test rows; the model that generated these scores must already be frozen. Separate inference process and model-feature provenance are not implemented here.

### Limits
- Minimum 1000 independently labeled benign calibration events, 1000 benign test events and 30 independently confirmed attack test events are preliminary admission controls; they do not guarantee statistical power or generalization.
- `READY_FOR_EVALUATION` means **eligible to calculate descriptive scores**, not that a detector performed well, that data rights are legally guaranteed, or that raw data are authentic beyond pinned bytes.
- A capture may contain repeated events and independent groups may still be correlated. Interpret CIs at campaign/site granularity.
- Local file hashes validate bytes against the supplied manifest, not the publisher unless publisher provenance was separately reviewed. This tool cannot authenticate a claimed human label.
- **No external datasets are downloaded by CI**. Raw traffic, customer data and model pickle files must not enter the public repository.
