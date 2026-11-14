# Actual trained-model lab recommendation path

This module integrates an existing locally trained mechanism-lab bundle with live Docker/runtime and gateway/probe scope evidence. It calls `predictions_from_bundle`, then `select_action`, allowing a model-ranked **research-lab recommendation** when the lab scope is supported and the independent action gate accepts the prediction intervals. Unlike synthetic rankings, its CLI expects an actual trained bundle with independently trusted SHA-256 fingerprint and a real pre-action telemetry record.

From `experiment-b/mechanism-lab` with the local Docker lab running and `LAB_CONTROL_TOKEN` set:

```bash
PYTHONPATH=../../engine python lab_ai_decision.py \\
 --project <actual-compose-project> \\
 --pre-action /private/pre_action.json \\
 --model /private/trained-model.joblib \\
 --trusted-model-sha256 <trusted-hash-outside-model> \\
 --remaining-lab-budget 25 \\
 --output /private/decision-1.json
```

The budget is an explicitly supplied experimental allowance, **not** evidence of measured production budget. It must not authorize real infrastructure changes. This runner performs no action dispatch and makes no post-action verification claim. If scope or model calibration is unsupported, it abstains. Real automated execution requires separately authorized lab-only capability issuance, exact-target policy controls, measured budgets, and independent post-action probes.

The old `risk_evidence` module continues to refuse to upgrade an **unvalidated vulnerability candidate**. This new pathway proves lab-scope membership separately and does not equate it with confirmed CVE applicability. Actual measured-trained-model advantage remains a separate scientific question.
