# Real local-model inference interoperability: controlled smoke test

This workflow loads the **actual open-weight Qwen3 0.6B model** with the official localhost Ollama runtime, collects the exact installed model digest, and runs an end-to-end PREDICT-SHIELD read-only case against a fictional advisory and synthetic Docker/SBOM report. The model is real, but the vulnerability example, asset, and all data are fictional. This proves only the **software/runtime integration** when the physical workflow passes.

The small 0.6B model is selected **for a low-cost interoperability smoke test**, not as the best model for cybersecurity analysis. The primary model should be selected only after comparative evaluation of security-specialized and general instruction-tuned models, including Foundation-Sec-8B-Reasoning when its exact license and format are reviewed. No cost or latency estimate from the smoke workflow generalizes to an 8B model.

The model receives an exact known asset/CVE/purl matching pair from the test fixture and an approved catalog with one `request_security_review` action and two read-only verification check IDs. Its output is constrained by a JSON Schema and validated by a separate parser against the catalog and exact known evidence. It can choose to abstain. It cannot certify the fictional finding, approve actions, execute repairs or independently verify outcomes. Unexpected identifiers, extra fields and unsupported formats cause the workflow to fail rather than silently count success.

The CLI report must say `ESCALATE_FOR_EVIDENCE`, `dispatch_authorized=false` and `selected_action=null`, regardless of what the model suggests. Every GitHub Actions run captures the installed model's SHA-256 digest and recorded case report if successful.

**Reproducibility:** The example uses a public model tag and container tag. An external maintainer must verify the original artifact model digest and runtime version before interpreting or reproducing results, because remote tags may change. The tests use a fixed loopback-only endpoint and must not be exposed on external network interfaces.

Model and format references: https://ollama.com/library/qwen3%3A0.6b and https://ollama.com/blog/structured-outputs. No 99.9% performance claim, model superiority, applicable real CVE finding or operational infrastructure effectiveness is made.
