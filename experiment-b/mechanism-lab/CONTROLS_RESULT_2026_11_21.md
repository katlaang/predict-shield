# First control run (PR #145, CI run 44867638482)

These controls ran on unlocked code, before any scored trial.

## Negative control

There were 8 runs with no fault injected. All 8 were HEALTHY: the oracle
reported access denied at every read, and the verifier saw no exposure.

## Positive controls

Each run injected the fault and took no action.

| Fault | TTL 2.5 s | TTL 15 s | Time until access was denied |
|---|---|---|---|
| loss | 4 of 4 self-healed | 4 of 4 persisted past 6 s | about 2.1 s (TTL 2.5 s); about 14.1 s (TTL 15 s) |
| delay, 0 ms | 4 of 4 not exercised | (same cells) | 0.02 s |
| delay, 2500 ms | 4 of 4 self-healed | (same cells) | about 2.05 s |
| duplicate | 8 of 8 not exercised | | 0.02 s |
| reorder | 8 of 8 not exercised | | 0.02 s |

Under the preregistered rule (at least 7 of 8 runs persisting), no fault mode
counts as persistent.

- **Loss** persists past the 6 s campaign window only when the cache TTL is
  longer than the window. Even then it heals when the cache entry expires.
- **Delay** heals once the injected delay has passed.
- **Duplicate and reorder** never left revoked access exposed. Access was
  already denied at the first read.

## Verifier against oracle truth

Sensitivity and specificity below are measured only on the cases where the
verifier gave an answer. Abstentions are counted separately.

**Control runs (40 runs, read at 6 s):**
- 36 correct VERIFIED and 4 correct NOT VERIFIED.
- No false VERIFIED and no abstentions.
- The dual-evidence verdict was identical.

**Pilot trials (40 trials):**
- 17 correct VERIFIED and 7 correct NOT VERIFIED.
- No false VERIFIED and no false NOT VERIFIED.
- 16 abstentions (40%): 11 where access was truly denied and 5 where it was
  exposed.
- By fault mode, abstention was highest for reorder (5 of 8). For loss it
  was 7 of 16.
- The dual-evidence verdict also had no false VERIFIED.

## Consequence for the plan

As planned, 75 of the 100 configurations use delay, duplicate or reorder. The
controls show that, without any action, these either never expose access or
heal within about 2 s. Loss configurations with a TTL under about 6 s heal
too. Most of the 1,200 trials would therefore measure cases where doing
nothing is correct.

The plan should be revised before it is locked.

## Second control run (plan v3.1, CI run 44870659784)

This run used plan v3.1, before locking.

**Negative control:** 8 of 8 runs HEALTHY, at TTL 10 s and 30 s.

**Positive controls:** 9 of the 10 registered cells behaved as their class
says.

| Cell | Runs | Outcome | Time until access was denied |
|---|---|---|---|
| loss, TTL 10 s | 4 | persisted past 6 s | 9.0 to 9.1 s |
| loss, TTL 30 s | 4 | persisted past 6 s | 29.0 to 29.1 s |
| loss, TTL 2.5 s | 4 | self-healed | 2.05 to 2.06 s |
| loss, TTL 4 s | 4 | self-healed | 3.07 to 3.08 s |
| listener pause, TTL 10 s | 4 | persisted past 6 s | 9.0 to 9.1 s |
| listener pause, TTL 30 s | 4 | persisted past 6 s | 29.0 to 29.1 s |
| delay 2.5 s | 4 | self-healed | 2.04 s |
| **delay 1 s** | 4 | **not exercised** (already denied at the first read) | 0.01 s |

**Why delay 1 s failed:** the event arrives before the first read after setup,
so it never exposes access. The plan's delay range therefore moved from 1 to
2.5 s up to 2 to 3 s. This change was also made before locking, and the
controls run again on the new cells.

**v3.1 pilot:** all 16 trials completed, with no reruns and no exclusions.
Verifier results:
- no false VERIFIED;
- 2 correct VERIFIED and 4 correct NOT VERIFIED;
- abstention on 10 of 16 trials, all because the gateway scope check was
  inconclusive.
