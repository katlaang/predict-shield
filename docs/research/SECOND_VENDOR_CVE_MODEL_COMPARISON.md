# Fresh advisory group evaluation after the first real model benchmark

## Observed prior pilot, not revised retrospectively

The original [13-case model comparison run](https://github.com/katlaang/predict-shield/actions/runs/43673876993) is permanently retained. **Both Qwen3 0.6B and Foundation-Sec-8B-Reasoning returned `UNKNOWN` on all 13 affected-version checks** (six affected, seven unaffected). There were no model transport errors. The exact vendor version-range deterministic baseline correctly classified **13 of 13**. Artifact `real-foundation-sec-vs-qwen-vendor-case-comparison`, ZIP SHA-256 `288e6ab85d302207a0de13c2c4da61575e876a9a48cf0963f1a4ff95beeb848a`.

That outcome establishes neither security-specialist superiority nor a universal inability to classify vulnerabilities. It indicates the first prompt was too ambiguous about interpreting inclusive affected ranges. It must **not** be relabeled as a trained-model success or reused for fresh validation.

## Registered new source-case protocol

The next 12 cases are from **three separate CVEs not represented in the first 13-case study**, using explicit public vendor ranges:

- CVE-2023-50164, Apache Struts, official [CVE Record](https://www.cve.org/CVERecord?id=CVE-2023-50164): 2.0.0 through 2.5.32 and 6.0.0 through 6.3.0.1 affected; 2.5.33 and 6.3.0.2 fixed.
- CVE-2023-46604, Apache ActiveMQ client, [vendor notice](https://activemq.apache.org/news/cve-2023-46604): 5.17.5 and 5.18.2 affected, 5.17.6 and 5.18.3 fixed in their respective branches.
- CVE-2023-24998, Commons FileUpload, [Apache security report](https://commons.apache.org/proper/commons-fileupload/security.html): 1.x prior to 1.5 affected, 1.5/1.6.0 not affected *by this particular CVE*. Note the fix must be explicitly configured and other CVEs may affect newer versions.

The updated prompt only clarifies that `through` is inclusive, `before` is exclusive, a documented fixed release is not affected, and **component affected-version matching does not establish runtime exploitability**. Both models use this *identical* clarified prompt. The source case set was committed separately before any new inference execution. The 13 earlier cases are not rescored in the new result.

Comparison arms: official quantized Foundation-Sec-8B-Reasoning, the original Qwen3 0.6B, and a strong exact vendor rule matching package, version family, fixed releases and documented affected ranges. All 12 cases are retained, including abstentions, errors and timeouts. Only historical vendor component-version truth is measured. There is no independent external vulnerability testing, novel advisory generation, proof of exploitability or real defensive action selection.

The 12 new cases still do not establish the user's 99.9% requirement or independent infrastructure protection. A positive new model score on version-range facts is not proof of risk-assessment superiority or remediation benefit. The next substantive research benchmark must include independently verified **configuration and exposure** evidence where straightforward version rules cannot decide applicability.

Reproduce locally with the same registered cases:

```bash
cd experiment-b/vulnerability-benchmark
python -m unittest test_compare_fresh_advisories -v
python compare_fresh_advisories.py --dataset fresh_vendor_cases.json \\
 --models qwen3:0.6b hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF:Q4_K_M \\
 --output /tmp/fresh-version-comparison.json
```
