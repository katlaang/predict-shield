# Superviz26-SQL input-noise stress test (2026-11-26)

**Outcome: the registered condition passed in 3 of 3 new domains.** When some benign inputs carry realistic international values, the frozen models alert on about half of those inputs. Models learned from equally noisy benign data return to about 0.5% benign alerts, and detection holds in B, C and D.

- **Protocol:** `experiment-b/superviz26-sql/stress/protocol.json`, registered before any stress model was fitted.
- **Freezes:** stress freeze `9ad4977c…6504`; base freeze `b739c584`.
- **Runs:** develop run 45938054252; single test run 45940288966.
- **Noise:** Faker 37.12.0 names, street addresses, companies and cities in 14 locales, replacing the first run of Latin-letter words in a benign input.
- **Pass condition:** for the matched arm at 5% noise, benign alerts at most 1% and detection at least 90%.

## Frozen models, noisy benign test inputs (shock)

| Domain | Noisy benign inputs that alert | Benign rate if 5% of traffic is noisy | If 20% |
|---|---|---|---|
| A OurAirports | 51.6% | 2.4% | 9.6% |
| B sakila | 63.6% | 1.8% | 7.2% |
| C AdventureWorks | 52.8% | 1.6% | 6.5% |
| D OHR | 54.6% | 1.1% | 4.2% |

Input novelty causes almost all of these alerts: apostrophes, hyphens, commas, slashes and combining marks are new character classes for most templates. This matched the registered prediction (above 50%).

## Learned from equally noisy benign data (matched)

| Domain | Noise | Benign alerts | Noisy benign that alert | Attacks caught |
|---|---|---|---|---|
| B | 1% / 5% / 20% | 0.49 / 0.49 / 0.48% | 8.8 / 3.1 / 1.1% | 99.3 / 99.3 / 99.3% |
| C | 1% / 5% / 20% | 0.46 / 0.47 / 0.46% | 11.1 / 3.6 / 1.7% | 99.9 / 99.9 / 99.9% |
| D | 1% / 5% / 20% | 0.47 / 0.50 / 0.50% | 10.9 / 7.0 / 4.1% | 99.9 / 99.8 / 99.7% |
| A | 1% / 5% / 20% | 0.49 / 0.51 / 0.49% | 10.5 / 3.5 / 1.2% | 89.4 / 89.0 / 88.8% |

- **B, C and D: passed.** The registered prediction that detection would fall was wrong here. Detection held, because injection still adds structure that names and addresses do not.
- **A: below 90%.** The prediction held: detection fell from 91.6% to 89.0%, and time-based attacks fell to 69.5%. OurAirports benign inputs already contain more punctuation, so the margin was thin.

## What this means

- **Unseen input variety:** a model learned from clean data and then exposed to messier real users will raise many false alarms, so profiles have to be learned from the traffic the application actually receives.
- **Learning from messy data:** when the model learns from that variety, false alarms return to budget and detection holds in three of four domains.
- **Limits:** the values are generated from real name and address lists, but they are still generated. This measures sensitivity to one stated kind of variety, not a real-user false alarm rate. In the shock table, the implied rates use the alert rate of rows that could not be perturbed as the clean rate.
