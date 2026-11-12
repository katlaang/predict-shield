# Experiment B v3 prospective protocol freeze

**Freeze anchor (Git commit):** `5c3f5854e1644b1858c281221a2126ac70d4c1d2`

**Protocol path:** `experiment-b/mechanism-lab/PROTOCOL_V3_AI_EVALUATION.md`

**Git blob SHA-1 at freeze:** `3ac868036435720d6a809c3de3b3e265ea766fcf`

**Status:** frozen research specification before newly scored expanded-pilot results are examined. Previous 12-trial results were inspected and are explicitly disclosed in the protocol. No new test-set AI result is claimed by this freeze.

The referenced commit permanently identifies the protocol text. This document is **not itself a Git tag**. A repository maintainer can add an annotated tag pointing to the immutable freeze-anchor commit:

```bash
git tag -a experiment-b-v3-protocol-frozen 5c3f5854e1644b1858c281221a2126ac70d4c1d2 -m "Experiment B v3 evaluation protocol frozen before expanded scoring"
git push origin experiment-b-v3-protocol-frozen
```

Changing this protocol for a later experiment requires a new version, a recorded rationale and a separate protocol freeze. Previously acquired pilot results must not be retroactively described as independent prospective evaluation.

**Key safeguards:** true injected fault labels and independent oracle records excluded from model inputs; authorized protected traffic contributes to gateway-restriction disruption; node service latency is a real runtime setting but not a separate primary-cost component; physical cold-start heterogeneity is not claimed; tuned deterministic rule thresholds fit using training groups only; three objective-weight sensitivity profiles; positive AI evidence requires outperforming the strongest predeclared non-AI comparator on independent configuration groups, not simply lower prediction MAE.
