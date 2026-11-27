# Pilot execution identity and exclusion notice for confirmatory protocol #196

**Registered pilot cohort:** [GitHub Actions run 45948413992](https://github.com/katlaang/predict-shield/actions/runs/45948413992), source commit `d0dabd84edf9ee1a332aef37dca0605a64c75342`, opened by pilot PR [#197](https://github.com/katlaang/predict-shield/pull/197). It is the only permitted 16-configuration cohort for estimating the registered sample size. Its validity is contingent on the complete pilot four-stream physical audit, correct frozen model hash and all success/failure rules.

**Excluded duplicate:** [GitHub Actions run 45948661643](https://github.com/katlaang/predict-shield/actions/runs/45948661643), initially triggered by follow-on PR [#199](https://github.com/katlaang/predict-shield/pull/199) because the inherited pilot workflow's broad path filter also matched new main-analysis code. This extra run reused the **same registered pilot seed and configuration IDs**. Even if it finishes with successful Docker action execution, it is a **duplicate, unregistered experimental execution** and must not be included in the pilot, future model training, sample-size estimation, non-inferiority analysis or claims of independent configurations. Preserve its original records and workflow run for reproducibility; do not erase or relabel. It is not a substitute if the registered pilot is negative or fails.

**Prevention:** The follow-on PR #199 restricts the pilot *physical* job to PR #197 against `master` (or deliberately manual workflow dispatch). No main plan may become executable without a committed pilot-derived N lock. Main configurations are generated in a distinct phase/shard namespace.

**No claim of superiority follows from completing any workflow.**
