# First live AI-selected remediation pilot: real CVE-2020-8203

## Research hypothesis

Can a local AI advisory-analysis model, after receiving **independent evidence that a real published software flaw is present**, select a pre-authorized package upgrade that passes separate behavior verification? How does its outcome compare with a strong deterministic vulnerability rule?

A single laboratory demonstration cannot establish AI decision superiority, a 99.9% success rate, or critical-infrastructure field effectiveness.

## Actual package and independent source

- **CVE:** CVE-2020-8203, prototype pollution in lodash deep-path helpers including `zipObjectDeep`.
- Independent public references: [GitHub Reviewed Advisory GHSA-p6mc-m468-83gw](https://github.com/advisories/GHSA-p6mc-m468-83gw) and [NVD CVE-2020-8203](https://nvd.nist.gov/vuln/detail/CVE-2020-8203). These sources differ slightly on the earliest fixed patch version. Both recognize `lodash@4.17.11` as affected and `lodash@4.17.21` as fixed for this CVE, which are the **only** versions used in this experiment.
- A genuine dependency is installed from the public npm registry into a **temporary local directory**. `npm install` uses `--ignore-scripts` to avoid executing package install scripts.
- `independent_probe.js` uses a **fresh Node.js process** to inspect installed package source and JSON, computes their SHA-256 digests, and performs a marker-only `zipObjectDeep` prototype test. It never sends a network request, accesses a real target or executes arbitrary shell commands. A benign normal-path `zipObjectDeep` call checks functionality.
- The pre-action oracle must observe actual prototype pollution in the affected version, not just see a CVE in an SBOM.
- Real local Qwen3 0.6B (the existing Ollama integration) receives only recorded pre-action evidence and a publicly sourced advisory, and selects from `upgrade_lodash_4_17_21` and `monitor_only`. If the model abstains or selects monitoring, the outcome is **not fixed**, not counted as success.
- A **separate deterministic policy gate** permits only the exact version upgrade in a disposable directory if live evidence proves the affected version and behavior; it cannot execute arbitrary model commands.
- A second independent child-process oracle is run after the real npm dependency upgrade. The result is VERIFIED_LAB_ONLY only when the installed version is exactly 4.17.21, the independently measured prototype pollution behavior is gone, legitimate behavior still works, and code bytes have changed.
- A separate fresh, equally vulnerable disposable instance is used for a strong deterministic comparator: if the affected package and actual behavior are proven, upgrade to the fixed version. Both model and baseline have the same available repair and their independent outcomes are recorded.
- Independently observed confirmation is at the **same laboratory host/process trust boundary**, not an external security assessor or operator. Source flags and content digests are integrity evidence only, not cryptographically authenticated operator attestations.
- This is **not** the existing JVM/Kafka policy-convergence CVE executor, which cannot patch npm packages. It is a narrow, allowlisted `npm`-only research adapter, not a general privileged package management engine.

## What this experiment does not prove

The real Node lab only measures software prototype pollution behavior and a benign legitimate-function regression. It does **not** measure customer-service availability, real network latency, organization-wide dependencies or other service disruption. No external critical-infrastructure operator participates. No repeated independent held-out fault families, statistical calibration, AI action-value superiority or field verification is implied.

**Research success criterion:** preserve actual outcomes. If Qwen chooses the upgrade and the post-action independent oracle passes, one **live AI-selected laboratory CVE mitigation** has been demonstrated, *but not AI superiority*: the strong deterministic baseline is also expected to patch this straightforward case. If the model abstains or fails, record and report that result without modifying the case or excluding it.

**Future external evidence:** independent assessor verifies the starting vulnerable configuration, pre-registers permitted changes and service budgets, supervises the operator-authorized run, signs pre/post observations, independently compares rule and AI action choices on held-out sites or fault classes, and records separately measured security and continuity outcomes.

Replay the workflow `.github/workflows/real-cve-ai-remediation-lab.yml` on GitHub Actions with Node 22, Python 3.12, local Ollama and publicly available npm registry. No production assets, credentials or public network probes are used.

## Failed first preflight and corrective protocol revision

The first actual GitHub Actions attempt used `lodash@4.17.17`, which is inside some published affected-version ranges, but the separate benign `zipObjectDeep` probe observed **no prototype pollution** on the runner. **The study failed closed before invoking AI or changing any package.** That is a negative precondition result, not a measured remediation or AI failure. The exact legacy `zipObjectDeep` issue has variant/fix-version differences among published advisories, so the next preregistered input is the older `lodash@4.17.11`, whose prototype-pollution behavior is separately documented in vulnerability reports. The patched target `4.17.21`, action menu, separate oracle and strong-rule comparator remain unchanged. Independent preflight JSON is now archived whether it passes or fails. Do not discard the 4.17.17 failed attempt.
