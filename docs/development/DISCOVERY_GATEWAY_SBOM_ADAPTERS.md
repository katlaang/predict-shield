# Gateway and image-SBOM discovery adapters

This optional lab collector queries a separately instrumented localhost gateway JSON exporter and can ask Syft to scan the exact immutable running Docker image ID.

Example (from repository root, authorized disposable lab only):

```bash
PYTHONPATH=engine python -m predict_shield.discovery_adapters \\
  --gateway-url http://127.0.0.1:18090/discovery \\
  --scan-sbom --output /tmp/discovery-new.json
```

The gateway URL above is **illustrative**: the current lab has no confirmed exporter at this path. The adapter does not invent gateway observations or silently substitute Docker output. The exporter must independently obtain its own actual routing/target membership. The gateway JSON contract is `predict-shield/gateway-observation/1` as documented in the first asset-discovery milestone.

For SBOM use, install Syft in the caller environment. This feature does not install Syft, fetch vulnerability data or claim CVE mapping. Missing scanner permissions, invalid image IDs, absent images or scan errors produce `UNAVAILABLE`, not a clean asset assertion.

## Known security limitations
Local-only URLs are required and HTTP redirects are disabled. Gateway export itself is not authenticated, and source independence is **not established** by its self-reported source name. Do not expose an unauthenticated exporter on a public interface. The collector does not accept remote URLs, credentials in URLs, or perform remediation. Running with Docker socket access is sensitive.

This is not yet integrated into AI threat assessment or real-time case closure. No production scope completeness, continuous discovery or SBOM source attestation is claimed. Image SBOMs contain software-package metadata but are not a vulnerability verdict.
