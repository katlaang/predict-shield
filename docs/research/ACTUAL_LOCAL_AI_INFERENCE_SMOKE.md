# Real local-model inference interoperability: controlled smoke test

This workflow loads the **actual open-weight Qwen3 0.6B model** with the official localhost Ollama runtime, collects the exact installed model digest, and runs an end-to-end PREDICT-SHIELD read-only case against a fictional advisory and synthetic Docker/SBOM report. The model is real, but the vulnerability example, asset, and all data are fictional. This proves only the **software/runtime integration** when the physical workflow passes.

The small 0.6B model is selected **for a low-cost interoperability smoke test**, not as the best model for cybersecurity analysis. The primary model should be selected only after comparative evaluation of security-specialized and general instruction-tuned models, including Foundation-Sec-8B-Reasoning when its exact license and format are reviewed. No cost or latency estimate from the smoke workflow generalizes to an 8B model.

The model receives an exact known asset/CVE/purl matching pair from the test fixture and an approved catalog with one `request_security_review` action and two read-only verification check IDs. Its output is constrained by a JSON Schema and validated by a separate parser against the catalog and exact known evidence. It can choose to abstain. It cannot certify the fictional finding, approve actions, execute repairs or independently verify outcomes. Unexpected identifiers, extra fields and unsupported formats cause the workflow to fail rather than silently count success.

The CLI report must say `ESCALATE_FOR_EVIDENCE`, `dispatch_authorized=false` and `selected_action=null`, regardless of what the model suggests. Every GitHub Actions run captures the installed model's SHA-256 digest and recorded case report if successful.

**Reproducibility:** The example uses a public model tag and container tag. An external maintainer must verify the original artifact model digest and runtime version before interpreting or reproducing results, because remote tags may change. The tests use a fixed loopback-only endpoint and must not be exposed on external network interfaces.

Model and format references: https://ollama.com/library/qwen3%3A0.6b and https://ollama.com/blog/structured-outputs. No 99.9% performance claim, model superiority, applicable real CVE finding or operational infrastructure effectiveness is made.


## First actual completed local-model result

- **Execution:** [GitHub Actions workflow run 43671825573](https://github.com/katlaang/predict-shield/actions/runs/43671825573), completed successfully on November 14, 2026.
- **Execution type:** actual CPU-only Ollama inference, not a mocked model response.
- **Model:** `qwen3:0.6b`, installed model manifest digest `sha256:7df6b6e09427a769808717c0a93cadc4ae99ed4eb8bf5ca557c90846becea435`.
- **Input:** a deliberately fictional advisory `CVE-2099-99999`, one synthetic Docker asset and software component, and one research review action.
- **Observed result:** one schema-validated model proposal: `request_security_review`; the model suggested `review_version` and `reconcile_configuration` from the allowlist. Model's analysis was only an unverified recommendation.
- **Independent safety outcome:** `selection_status=ESCALATE_FOR_EVIDENCE`, `selected_action=null`, `dispatch_authorized=false`. No real vulnerability was detected, no defense executed and no remediation independently verified.
- **Retained evidence:** GitHub Actions artifact `actual-local-qwen-0-6b-advisory-smoke`, ZIP SHA-256 `37dd14128689bc38389bf2a42ec40dff907b5ba44e7a19101c2e899904a08899`. It contains the full structured case and exact local model digest.

This verifies real local language-model runtime interoperability and strict non-execution behavior. It is **not** an accuracy measurement, cybersecurity model ranking, vulnerability detection result, 99.9% result, or proof of AI superiority. The synthetic inputs have no independently confirmed security truth. No security-sensitive real inventory was supplied.
