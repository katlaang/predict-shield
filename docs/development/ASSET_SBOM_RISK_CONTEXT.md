# Asset-to-SBOM advisory correlation

The module `predict_shield.asset_risk_context` joins discovered **running image IDs** to their Syft SBOM result and explicit, separately supplied advisories using exact package URLs (purls). The output is evidence context for risk analysis, **not** a learned AI prediction or a confirmed exploitable vulnerability.

Usage: `PYTHONPATH=engine python -m predict_shield.asset_risk_context --discovery /private/discovery.json --advisories /private/advisories.json --output /private/risk-context.json`.

Advisories are a JSON list with `purl`, `cve`, and `source`. Source must identify the actual advisory provenance. The caller must confirm affected version, configuration, reachability, fixes and proper as-of timing before treating a match as applicable. SBOM scanner failure is NOT_SCANNED/UNAVAILABLE, not a clean bill of health. All unit fixtures are synthetic. No external operator results are claimed.

Next: attach verified vulnerability applicability and exposure observation to the existing AI risk interface, with proper time and group splits.
