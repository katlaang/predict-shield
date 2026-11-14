# Exploratory physical interventions during a stopped policy authority

This opt-in experiment compares **observations**, not decision utility, under the same declared fault family. It performs four separate resets, injects real loss of a Kafka revocation event at enforcer-b, captures a privately observed live-authority revocation witness and its SHA-256 commitment, stops the real authority container, then individually performs resync, local JVM restart, gateway restriction or monitoring.

For every action it checks the stopped authority, samples HTTP outcomes for **both revoked and authorized test principals** before and after intervention, and asks the independently deployed oracle to measure each of four enforcement nodes. It reports observed allow, deny and unknown counts and conservative lower/upper allow fractions relative to the historically witnessed revoked policy. The live authoritative policy verdict remains UNKNOWN throughout the outage. All complete denial observations still do not constitute VERIFIED.

The authority is restored in `finally` before the next registered action. The public CI artifact includes only action names, HTTP status counts, witness commitment hashes and non-sensitive uncertainty bounds. It excludes raw oracle snapshots and identities. The samples are discrete HTTP probes, **not** a time-integrated exposure trace, a representative risk rate, or an authenticated proof of persistent policy state.

## Limitations

- This is **four actual physical action replays under a single fault configuration**, not the complete registered six-family v3.1 feasibility study.
- A resynchronization attempt must fail while the authority is stopped. A local JVM restart cannot restore the authority service. Gateway restriction has operational collateral effects visible in authorized test requests.
- The historical policy witness can become stale if the authoritative state changes while the authority is unavailable. It is not a live truth oracle.
- There is no normalized cross-action utility here. Do not assign artificial NOT VERIFIED labels or rank by cherry-picked status codes.
- The next scientific milestone is independently registered multi-configuration outage trials with continuous probe timing, eligibility-safe action handling and measured costs under a predeclared conservative UNKNOWN policy. Do not start 1,200 trials until all six families meet the feasibility and precision gates.

Run: `python authority_outage_actions.py --execute-lab --output reports/outage-actions.json` from the disposable Compose lab.


## Timed physical observation extension

The follow-up implementation `outage_timed_measure.py` performs one measured 6-second observation window **per action**, starting intervention at the registered +1-second mark while independent revoked, authorized-protected and legitimate-endpoint HTTP probes continue. It uses the already audited monotonic HTTP step-integral to produce lower/upper **sampled gateway exposure duration**. Missing probe periods are UNKNOWN and increase the upper bound; they are not considered denials.

For the two legitimate identities/routes the output records actual HTTP status counts, requests and failed requests, rather than inventing disruption from action names. The timed sampler records late probe counts and propagates failed restart/restrict actions. Full externally authoritative policy verification remains INDETERMINATE during outage.

These are separate **observation dimensions**, not a combined cost. No 0–1 risk/disruption score has been preregistered for an outage with historical, potentially stale desired policy. Comparing actions by a weighted sum or integrating results into `feasibility_v31.py` would be premature. This four-arm experiment is still one exploratory configuration with no independent repeats.
