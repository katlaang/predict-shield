# Manuscript insert: External validity on published production web traffic

**Status:** publication-ready draft section, **not** a claim that the existing LNCS manuscript was modified or resubmitted. Reviewed against original frozen v3 and experimental v3.2 GitHub result JSON on 2026-11-27. This is a reporting revision, **not** a third detector experiment, a refit or an additional independent holdout.

## Suggested section heading: Evaluation on published web-server access logs

To assess transfer beyond generated SQL inputs, we evaluated the frozen benign-only input-anomaly method on access logs published by two Indonesian public-sector organizations (Zenodo record 20001206). The analyzed scope comprises requests containing URL query strings; POST bodies and requests without query strings are outside the observed input space. The sources include an organization with one observed website (X) and an organization whose test period contained 18 site identifiers (Y). Models were fitted to earlier traffic without removing suspicious requests, and scored later requests at thresholds frozen before their evaluation. The model is not a password-guessing or request-rate detector.

The original evaluation was specified before reading test request values. The comparison evidence comprised independently run OWASP Core Rule Set (CRS) checks and libinjection probes. We report the proportion of requests alerted by our detector, the share without a concurrent warning from those tools, and the share of comparator-flagged requests also alerted. **We do not call these true false-positive rates, precision, recall or independently verified attack labels.** CRS and libinjection themselves have false positives and false negatives. In this harness, the source target was replayed to CRS as a GET request, rather than reconstructing its original HTTP method and body; this is an additional reason that agreement cannot be used as a definitive oracle.

### Frozen v3, originally registered test periods

| Measure | Organization X, Oct 1–7, 2025 | Organization Y, Apr 22–May 1, 2025 |
|---|---:|---:|
| Query-bearing requests | 6,244 | 279,389 |
| Frozen fused alerts | 93 (1.489%) | 8,843 (3.165%) |
| Alerts without CRS/libinjection agreement | 0 (0.000%) | 8,119 (2.906%) |
| Requests flagged by at least one comparator | 422 | 86,793 |
| Fraction of comparator-flagged requests alerted by v3 | 22.0% | 0.834% |
| Share of evaluated requests on previously unseen templates | 12.89% | 18.57% |
| V3 alert rates, seen versus unseen templates | 0.44% versus 8.57% | 1.17% versus 11.91% |

A template is defined by the site identifier, HTTP method and digit-normalized URL path. Query parameter names are **not** part of the template identity, although query values contribute model input. On Organization Y, 6,183 of 8,843 alerts occurred on previously unseen templates. This corresponds to approximately 70% of the alerts. The result suggests an operational dependence on changing websites and URLs, not a measured 2.91% *confirmed false-positive rate*. In Organization X, all 93 alerts overlapped conventional-detector flags, but **none** was independently adjudicated as an attack. In Organization Y, many CRS level-2 alerts were associated with repeated login requests that appear ordinary at the query-value level; rate and sequence information are required to test such campaigns reliably. Their true attack status cannot be established from comparator agreement alone.

### Registered v3.2 experiment and its failed transfer test

After examining the original v3 outcomes, we registered a development modification that replaced maximum novelty scores for unknown templates with a site-and-method pooled profile, while retaining the maximum score when the entire site-and-method combination had no history. The comparison used earlier temporal windows and models fitted to the corresponding earlier training partitions. Although these were not the original test periods, **they were drawn from data that had already contributed to the earlier v3 training period**; therefore, they are not an independent external dataset or a wholly untouched confirmation.

| Earlier window | Requests | Algorithm | Alert rate | Alerts without CRS/libinjection agreement | Agreement-based comparator detection proxy |
|---|---:|---|---:|---:|---:|
| X, Sep 28–30 | 3,462 | v3 refitted on early train period | 1.242% | 0.116% | 25.49% |
| X, Sep 28–30 | 3,462 | v3.2 refitted on early train period | 1.069% | 0.087% | 22.22% |
| Y, Apr 15–21 | 558,017 | v3 refitted on early train period | 0.066% | 0.023% | 24.22% |
| Y, Apr 15–21 | 558,017 | v3.2 refitted on early train period | **76.087%** | **76.010%** | 43.24% |

On Y's earlier window, 76.17% of evaluated requests had templates absent from the corresponding fit data. The v3.2 frozen novelty threshold for Y was 1.0, and the implementation assigns an unseen-site-and-method query a novelty score of 10. The resulting 76% aggregate alert burden indicates a severe failure of operational calibration, making v3.2 unsuitable for unqualified deployment in this setting. The observed behavior is consistent with a distribution shift in the calibration scores after pooling unknown templates, but the effects of calibration and new-site prevalence have **not** been isolated in a causal ablation. The earlier v3's very low alert rate on the same period similarly does not establish reliable unseen-site behavior.

The post hoc v3.2 evaluation on the original already examined split is secondary: for Y it produced 33.83% alerts and 2.94% alerts without comparator agreement. It must not be presented as another independent confirmatory test.

### Limitations and implications

These studies demonstrate the difference between controlled attack-containing datasets and high-volume changing website traffic. The original v3 model and v3.2 experiment both have material external-validity limitations. They do not establish accurate detection of previously unseen real attack types, verified benign false-alarm rates, or reliable deployment on newly onboarded websites. Results depend on request parsing, training contamination by real-world suspicious activity, template frequency, changing site inventories and the independence and coverage of conventional detection proxies.

The supported engineering requirement is to model the **site lifecycle** explicitly: (1) established site and known template; (2) new template on an established site; (3) newly observed site with insufficient trustworthy history. For the third case, an onboarding/abstention mode and separate rate/behavior defenses should be considered before any automated security judgment. These are design implications, not demonstrated effectiveness of a new model. Because the Indonesian logs have already informed both versions, **any new approach must be registered and evaluated on a genuinely independent source or a separately authorized pilot**, with blinded human adjudication of a prespecified sample where permitted.

## Findings to carry into abstract and conclusion

**Suggested abstract addition:** "On two sets of published production web-access logs, the frozen method alerted on 1.49% and 3.17% of query-bearing requests. These alerts were compared against established rule-based detectors, but definitive attack and false-positive rates could not be measured. A registered follow-up model modification exposed a severe unseen-site calibration failure, producing a 76.09% alert rate on one earlier temporal window. The findings delimit the method's applicability to evolving web estates."

**Suggested conclusion addition:** "Our work establishes controlled-domain detection capability and documents important real-traffic limitations. In particular, agreement with security rules is not independent truth, and a detector calibrated on familiar query templates can behave unreliably on newly appearing sites. Any production readiness claim requires site-aware onboarding, independent labeled evaluation, and operational controls for attacks outside query-value anomaly detection."

## Primary reproducibility sources

- Original frozen protocol: `experiment-b/real-logs-indonesia/protocol.json`.
- Original frozen measured results: `experiment-b/real-logs-indonesia/frozen/test-report.json`; GitHub Actions run `46018576222`.
- New development protocol and results, **not merged as a deployable improvement**: PR [#202](https://github.com/katlaang/predict-shield/pull/202), `protocol_v32.json`, `frozen-v32/test-report.json`; experiment run `46035174294`.
- Original evidence correction merged in [PR #203](https://github.com/katlaang/predict-shield/pull/203).
- Dataset: https://zenodo.org/records/20001206.
- Do not publish raw request targets or review artifacts. Reviewer adjudication has **not** been performed.

**Scope:** This is web-input anomaly detection, not confirmation of autonomous attack response, security prediction or better adaptive defense selection.
