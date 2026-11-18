"""Measured cost of one executed lab action: weighted temporal exposure,
unresolved control and absolute request failures against a declared allowance."""
from __future__ import annotations



METRIC_WEIGHTS = {
    "label_path_exposure": 0.50,
    "label_security_exposure": 0.25,
    "label_absolute_failed_requests": 0.25,
}


def observed_utility(row: dict, weights: dict[str, float] = METRIC_WEIGHTS) -> float:
    """Score measured temporal exposure, unresolved control and absolute failure.

    Values must be nonnegative and exposure fractions no greater than one.
    The laboratory failure allowance is a fixed positive *count* per window,
    which keeps a costly restart expensive when absolute request failures
    rise with traffic. This is a research utility, not a safety permission.
    """
    if set(weights) != set(METRIC_WEIGHTS) or abs(sum(weights.values()) - 1) > 1e-8:
        raise ValueError("Unregistered objective weight components")
    budget = row.get("absolute_error_budget_requests")
    if type(budget) is not int or budget <= 0:
        raise ValueError("No declared absolute error allowance")
    for name in ("label_path_exposure", "label_security_exposure"):
        value = float(row[name])
        if not 0 <= value <= 1:
            raise ValueError("Invalid normalized exposure")
    failures = float(row["label_absolute_failed_requests"])
    if failures < 0 or failures != failures:
        raise ValueError("Invalid absolute failure observation")
    return (weights["label_path_exposure"] * float(row["label_path_exposure"])
            + weights["label_security_exposure"] * float(row["label_security_exposure"])
            + weights["label_absolute_failed_requests"] * failures / budget)
