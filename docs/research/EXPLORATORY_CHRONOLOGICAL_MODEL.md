# Exploratory historical learned threat ranking (post-hoc)

**Research status:** exploratory, not a preregistered scientific superiority test. PREDICT-SHIELD's AI-centered threat-intelligence pillar needs real learned models and comparisons, but the October 2026 baseline result was inspected **before** this model and its protocol were created. October is therefore not an untouched test set.

The repository pins five independently dated EPSS/KEV feature windows, with a separate November 10, 2026 catalog used *only as a source of later labels*. The baseline observation cutoffs are June 2, July 2, August 4, September 2 and October 2. June–August are used for fitting, September for diagnostics, and October for a previously inspected exploratory evaluation. Historical EPSS commit dates and CISA KEV commit refs are recorded in `data/exploratory_model_windows_2026.json`.

The model is a **fixed-parameter standard-scaled logistic regression**, trained on three operator-available features: historical EPSS log-odds, EPSS percentile, and CVE-year age. It uses all positive training examples and a deterministic hash-selected 3% sample of negatives, with class balancing; the resulting scores are **uncalibrated ranks**, not probabilities of exploitation or loss. The predictive target is *later KEV catalog addition*, not observed exploit occurrence. It does not access enforcement oracle states, current asset inventories, or future labels during inference.

Compare the learned model with **EPSS-only** on identical evaluation CVEs and report AP and precision@100/1000, including ties, losses and catalog coverage. A single forward-period result with rare positives cannot establish statistically reliable superiority. A later, genuinely uninspected prospective window and independent validation are required for that claim.

GitHub Actions workflow `.github/workflows/threat-chronological-model.yml` downloads the real immutable archives, fits the model, and uploads **only a sanitized score summary**. No raw source snapshots or model inputs are committed or exported. No action execution or autonomous defense is enabled.

Run from an environment with outbound access and Python 3.12:

```bash
python -m pip install -r experiment-b/requirements-ml.txt
PYTHONPATH=engine python -m predict_shield.chronological_model \
  --manifest docs/research/data/exploratory_model_windows_2026.json \
  --output /tmp/chronological-model-exploratory.json
```
