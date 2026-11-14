"""Pre-execution group-level decision-diversity precision audit.

Wilson score intervals for independent binary *configuration-level* outcomes.
These intervals do not infer model-regret power or cross-fault generalization.
"""
from __future__ import annotations

import argparse
import json
import math
from statistics import NormalDist
from pathlib import Path


def wilson(successes: int, groups: int, confidence: float = .95) -> tuple[float, float]:
    if (type(successes) is not int or type(groups) is not int or
            groups <= 0 or not 0 <= successes <= groups):
        raise ValueError("Valid independent configuration counts required")
    if not 0 < confidence < 1:
        raise ValueError("Confidence must be in (0,1)")
    z = NormalDist().inv_cdf((1 + confidence) / 2)
    p = successes / groups
    d = 1 + z*z/groups
    center = (p + z*z/(2*groups)) / d
    half = (z/d) * math.sqrt(p*(1-p)/groups + z*z/(4*groups*groups))
    return max(0.0, center-half), min(1.0, center+half)


def minimum_successes_to_clear(groups: int, threshold: float = .30) -> int | None:
    if type(groups) is not int or groups <= 0 or not 0 < threshold < 1:
        raise ValueError("Invalid feasibility threshold or group count")
    return next((k for k in range(groups + 1)
                 if wilson(k, groups)[0] > threshold), None)


def report(sample_sizes=(5, 18, 30, 90, 150), threshold: float = .30) -> dict:
    if not sample_sizes or len(set(sample_sizes)) != len(sample_sizes):
        raise ValueError("Unique planned sample sizes required")
    rows = []
    for n in sample_sizes:
        necessary = minimum_successes_to_clear(n, threshold)
        rows.append({
            "independent_configuration_groups": n,
            "minimum_group_mismatches_for_observed_fraction_at_least_threshold":
                math.ceil(n * threshold - 1e-12),
            "minimum_group_mismatches_for_wilson_95pct_lower_above_threshold":
                necessary,
            "confidence_interval_type": "95pct_wilson_score",
        })
    return {
        "schema": "predict-shield/v31-group-diversity-precision-planning/1",
        "minimum_proposed_decision_diversity": threshold,
        "sample_size_scenarios": rows,
        "unit_of_analysis": "independent_configuration_group",
        "no_data_used_for_model_selection": True,
        "no_power_claim_for_ai_model_improvement": True,
        "binomial_independence_assumption_may_fail_under_shared_services": True,
        "feasibility_sample_size_not_approved": True,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    obj = report()
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with a.output.open("x", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")
    print(json.dumps(obj, indent=2))


if __name__ == "__main__":
    main()
