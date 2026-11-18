# Measured AI-selected mitigation of an actual published CVE: laboratory evidence

**Evidence recorded:** November 15, 2026 UTC. This record is based on the actual GitHub Actions workflow output and saved independent Node.js probe JSON, not a mock, training set, AI-generated claim, or success label inferred from `npm install`.

## Actual successful trial

- **Workflow:** [real CVE lab, run 43679777962](https://github.com/katlaang/predict-shield/actions/runs/43679777962), completed SUCCESS.
- **Merged implementation:** [PR #93](https://github.com/katlaang/predict-shield/pull/93), master commit `49f47889ecd7717d5c8f70047e4dda2fd0a76f03`.
- **Original evidence:** GitHub Actions artifact `actual-cve-2020-8203-ai-and-strong-rule-lab-remediation`, artifact ID `14147624388`, ZIP SHA-256 `11ec849c7eff27b89031e86daaa9b115e307e488dc98ac5041e2e26138175b2c`. Contains complete `ps-real-cve-ai-pilot.json`, `ps-real-cve-ai-pilot.preflight.json` and exact installed model manifest digest.
- **Report content digest:** SHA-256 `ec1f8af6806ac298f51706ef6a57998bf8808ab58bb67f4a879e97388afb8bfe`, as recorded inside the report.
- **Published vulnerability:** CVE-2020-8203, lodash prototype pollution, verified against [GitHub Reviewed Advisory GHSA-p6mc-m468-83gw](https://github.com/advisories/GHSA-p6mc-m468-83gw) and [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-8203). Reports differ slightly on early patch boundaries. Both indicate `lodash@4.17.11` is affected and `lodash@4.17.21` is beyond the relevant fixed release.

## Recorded before-and-after evidence

| Dimension | AI-controlled package instance |
|---|---|
| Original real npm version | lodash `4.17.11` |
| Safe independent pre-action behavior | Prototype marker propagated via both `constructor.prototype` and `__proto__` paths |
| Actual package update | Real `npm install lodash@4.17.21` after model choice and lab safety gate |
| Independent post-action version | `4.17.21` |
| Separate post-action behavior | No marker propagation via either probe path |
| Legitimate `zipObjectDeep` function | Passed |
| Laboratory remediation verdict | VERIFIED_LAB_ONLY |

### AI decision and action

- **Actual local language model:** `qwen3:0.6b`, installed manifest `sha256:7df6b6e09427a769808717c0a93cadc4ae99ed4eb8bf5ca557c90846becea435`.
- The model received real pre-action evidence and vendor advisory context, plus two allowed choices: `upgrade_lodash_4_17_21` or `monitor_only`.
- **Actual selected action:** `upgrade_lodash_4_17_21`, with permitted independent check IDs `separate_child_process_prototype_probe`, `exact_dependency_version_and_digest`, and `legitimate_zipObjectDeep_regression`.
- The independent **laboratory-specific** safety gate required observed vulnerable behavior, exact affected package/version and a disposable path before performing a fixed npm command. The model supplied no shell command, authorization token or test verdict.
- The independent verifier ran in a separate Node.js process after the actual upgrade. The recorded package source SHA-256 changed from `bd2f49d95621bf001f876ce79cb76485e9853c4a71e98a19121131a813d3e72b` to `4c04561befdf653aef017a42ac5addf68ea943cdfca6bdee5ce04e04e8139f54`. Both benign prototype-pollution probes changed from positive to negative, while ordinary function behavior remained successful.
- Total workflow **script elapsed time** reported as 13.651 seconds. This includes npm package operations and other case steps, and **must not** be used as a production remediation time, availability or throughput measure.

### Failed preliminary trials retained

1. [Run 43679524426](https://github.com/katlaang/predict-shield/actions/runs/43679524426) failed to download Qwen3 when the upstream Ollama registry returned HTTP 503. No AI remediation or vulnerability observation occurred.
2. [Run 43679629260](https://github.com/katlaang/predict-shield/actions/runs/43679629260) retrieved the real model, but a `lodash@4.17.17` installation **did not reproduce** the registered harmless prototype test. The run correctly failed *before* using model recommendations or changing packages. This was not counted as a successfully verified vulnerability.
3. The final successful version was the older, separately documented `4.17.11`. The test behavior was verified by the actual pre-action oracle rather than being assumed from a CVE version lookup; the action choices and verification criteria remained unchanged.

These failed attempts cannot be erased to suggest a perfect run history.

## Claims supported and not supported

**Supported:** one real, publicly documented vulnerable npm component in a disposable local environment; actual observed vulnerability-relevant behavior before the action; real local model selected an allowed patch; actual dependency upgraded; a separate process independently observed the security-relevant behavior was gone.

**Not supported:** an independently audited production CVE applicability assessment; a CVE that is exploitable from a real customer-facing service; measured unrelated service continuity; an actual infrastructure operator deployment; independent critical-infrastructure site validation; generalizability to other vulnerabilities or attack families. The local independent child-process oracle is an important **separate measurement path** but is not an independent external organization or cryptographically authenticated assessor.

**Next step:** use configuration-dependent, operationally meaningful vulnerabilities with independently measured action risk and legitimate-service impacts; freeze and evaluate AI effect predictions on new sites/fault families. For external deployments, apply [the operator approval and field trial protocol](EXTERNAL_US_CRITICAL_INFRA_FIELD_VALIDATION_PROTOCOL.md). The field-study status is still **NOT STARTED**, not VERIFIED.
