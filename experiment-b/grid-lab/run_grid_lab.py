"""Run a bounded electric-grid cyber/physical demonstration.

No network controller, relay, breaker, grid interface, or physical equipment
is controlled. Default action choice is a labelled test double. To use an
actual local AI model, explicitly pass --model ollama:<model-id>.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "engine"))

from predict_shield.grid_cyber_physical_lab import (  # noqa: E402
    load_registration, digest, observe_power, propose, screen,
    apply_simulated, verify_independently,
)
from predict_shield.language_model import open_model  # noqa: E402


class FixedChoiceModel:
    name = "fixed-choice-test-double-NOT-AI"

    def complete(self, system, prompt):
        return json.dumps({
            "action_id": "block_untrusted_remote_management",
            "severity": "high",
            "rationale": "The registered threat path crosses untrusted VPN access.",
        })


def run(*, model_spec: str | None = None) -> dict:
    reg = load_registration(HERE / "registration.json")
    model = open_model(model_spec) if model_spec else FixedChoiceModel()
    before_power = observe_power(load_scaling=reg["model"]["load_scaling"])
    proposal = propose(reg, model, observation={
        "notes": "Registered laboratory incident: unauthorized remote-management path is reachable",
        "source": "declared topology scenario, not independently authenticated incident telemetry",
    })
    initial_gate = screen(reg, proposal, trustworthy_observations=True)
    report = {
        "schema": "predict-shield/grid-physical-report/1",
        "run_at": datetime.now(timezone.utc).isoformat(),
        "registration_sha256": digest(reg),
        "scenario_id": reg["scenario_id"],
        "model": proposal.model_name,
        "model_is_real_ai": model_spec is not None,
        "proposal": proposal.__dict__,
        "preapproval_gate": initial_gate,
        "before_power": before_power,
        "simulation_only": True,
        "real_sdn_switches_used": False,
        "field_effectiveness_established": False,
    }
    if proposal.state != "PROPOSED":
        report["outcome"] = "INDETERMINATE"
        report["reason"] = "AI did not produce an admissible proposal"
        return report
    # This is explicit test-runner approval for a simulated action, NOT an
    # identity-verified utility operator approval or production privilege.
    gate = screen(reg, proposal, trustworthy_observations=True, operator_approved=True)
    report["lab_gate"] = gate
    if gate["decision"] != "LAB_APPROVED_ONLY":
        report["outcome"] = "INDETERMINATE"
        report["reason"] = "simulation gate rejected proposed action"
        return report
    applied = apply_simulated(reg, proposal, gate)
    after_power = observe_power(load_scaling=reg["model"]["load_scaling"])
    report["applied_simulation"] = applied
    report["after_power"] = after_power
    report["verification"] = verify_independently(reg, applied, before_power, after_power)
    report["outcome"] = report["verification"]["outcome"]
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default=None, help="optional real model, e.g. ollama:qwen3:0.6b")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(model_spec=args.model)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("scenario_id", "model", "outcome", "simulation_only")},
                     indent=2))
    if result["outcome"] != "VERIFIED_LAB_ONLY":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
