# PREDICT-SHIELD: Recorded ISP discovery and defense laboratory evidence

**Record date:** November 14, 2026. These results are from **actual completed GitHub Actions measurements in disposable software laboratories**, not simulated responses supplied to unit tests. Preserve outcome files and original workflow run references; repeatability and authenticity beyond this repository are separate questions.

## Actual observed discovery and security test measurements

| Test | Measured outcome | Reproducible run and retained evidence |
|---|---|---|
| SNMPv3 device inventory | 3 real SNMP authPriv agents returned identity data; deliberately incomplete OSS registered 2; `forgotten-c` discovered as unregistered | [GitHub Actions run 43650121051](https://github.com/katlaang/predict-shield/actions/runs/43650121051), artifact `live-snmpv3-isp-lab-observation`, ZIP SHA-256 `fa4b5ecfd09c9224f8f56cee41d15c6b45643e377971991362e626a7faa45e26` |
| Controlled simulated-access defense | Before isolation HTTP 200; after authorized action six independent HTTP 403 denial observations; service health HTTP 200; verdict `VERIFIED_LAB_ONLY` | [GitHub Actions run 43650442003](https://github.com/katlaang/predict-shield/actions/runs/43650442003), artifact `physical-isp-lab-defense-postcondition`, ZIP SHA-256 `a9b01b0466d832e3b310275652c3349914277913be08ce3287be3863c4bde2ed` |
| Mutual-TLS gNMI protocol collection | One actual interface-state gNMI Get update received by the PREDICT-SHIELD collector from a disposable Go gNMI target | [GitHub Actions run 43651196755](https://github.com/katlaang/predict-shield/actions/runs/43651196755), artifact `physical-gnmi-mtls-get-observation`, ZIP SHA-256 `7239be6595d386fff1abd41923b7c83d56837caad7d7689c36cce313f14981df` |
| Graph-aware risk inference on live evidence | 3 actual SNMP observations and HTTP 200 from a simulated access service. Synthetic-trained graph logistic model gave score `0.7474347010833787`; uncalibrated, no action authorized | [GitHub Actions run 43651141507](https://github.com/katlaang/predict-shield/actions/runs/43651141507), artifact `physical-isp-graph-risk-inference`, ZIP SHA-256 `7f46d2950ad05b51003a57d55191ce6c4e36f938f94b356d0523b45412a6dc6a` |

**Interpretation:** Measured records are source-specific research evidence. Three Linux Net-SNMP agents on Docker are not genuine routers or an operational ISP. A disposable Go gNMI service is not router firmware. The graph service-to-device dependency was explicitly declared in a synthetic scenario rather than physically measured. The graph risk score is **not a calibrated probability of an actual security incident**.

The access-service test confirmed HTTP deny at a single simulated endpoint and endpoint health. It **did not measure end-to-end customer service disruption, unrelated service latency, broadband connectivity, backhaul resilience or actual network outage effects**. Missing measurements must be recorded as `UNKNOWN`, never described as zero disruption.

## AI effectiveness research status

The historical experimental AI action model has not established consistent superiority over deterministic baselines. The separate fresh physical model case recorded **ABSTAINED** on its safety gate, which is a valid negative/inconclusive research observation. The telecom missing-link model has passed synthetic unit tests, but those are **not independent real-topology model superiority evidence**. The real rewired-network paired study is tracked separately and should only be entered here after its actual CI completes.

**Remaining external evidence:** independently audited real router/radio/optical topology datasets, trained model performance on unseen operator environments, a comparably strong deterministic baseline, verified cyber incident/outcome labels and measured service continuity. None of these are implied by passing the above workflows.

Original source artifact ZIP hashes are useful for archive integrity checks, not cryptographic proof of independent source identity. Artifacts have retention limits; archive evidence externally under controlled research procedures as appropriate.
