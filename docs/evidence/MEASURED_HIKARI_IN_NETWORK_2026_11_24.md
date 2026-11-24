# In-network flow detection on HIKARI-2021 (2026-11-24)

**Outcome: failed its condition.** The question was whether learning from the protected network's own labelled traffic fixes what cross-network training could not. In this dataset it did not.

- **Protocol:** `experiment-b/hikari-in-network/protocol.json`, committed before the code read any flow.
- **Registered test:** run 45330331055.
- **Report:** `experiment-b/hikari-in-network/reports/in-network.json`.

## Setup

- **Model:** the same detector configuration as cross-dataset version 3, trained on HIKARI's own labelled flows.
- **Training sizes:** four nested slices of the training pool.
- **Test:** the held-out half (277,670 flows), scored once per training size.
- **Pass condition:** at the 5% slice, at least 90% of attacks detected and at most 1% of normal flows alerted, both pooled and for each normal category.

| Training slice (share of the dataset) | Attack flows in training | Attacks detected | Normal flows alerted |
|---|---|---|---|
| 1% | 175 | 8.6% | 1.24% |
| 5% (pass point) | 890 | 5.5% | 1.13% |
| 20% | 3,785 | 6.6% | 0.92% |
| 50% | 9,452 | 8.0% | 0.96% |

More of the network's own data did not improve detection.

## Exploratory check (written after the result was seen)

`explore_separation.py` (run 45330750423, `reports/exploratory-separation.json`) asked whether this was a bug or a real limit. It used the 50% slice.

| Measure | Value |
|---|---|
| Supervised ROC AUC on the test half | 0.949 (training 0.955) |
| Per-category AUC | 0.93 (probing) to 0.99 (crypto-miner) |
| Anomaly model ROC AUC | 0.48 (no better than chance) |

The supervised model separates attacks from normal traffic, but the two overlap heavily at the low false-alarm end:

| Normal flows alerted | Attacks caught |
|---|---|
| 0.5% | 9% |
| 1% | 16% |
| 5% | 59% |
| 10% | 82% |

## What the result shows

- **It is not a bug and not overfitting.** Training and test fit are almost equal. The limit is the information in flow statistics for these attacks: encrypted brute force, probing and crypto-mining traffic look much like normal encrypted traffic in flow statistics alone.
- **Cross-network transfer was not the only problem.** Even with the network's own data, flow statistics cannot reach high detection at a 1% false-alarm rate on HIKARI.
- **The anomaly model adds nothing here.** Its AUC is 0.48.

## Secondary host-disjoint check (registered in advance)

It was uninformative. The training side held no attacking host except the crypto-miner's, so the model learned almost nothing about the other attacks. It flagged nearly all test flows, attacks and normal alike (47% of normal flows).

## Implication for the detection design

Flow statistics alone are not enough for these attacks. The next step is richer evidence per event: what the server did after the request, and connections that follow it. That is the request, process and network correlation, and it can be built and measured in the DVWA and ISP labs.
