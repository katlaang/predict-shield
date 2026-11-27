"""One predeclared physical lab model->policy->action->oracle pilot.

Train on original measured lab data separately. This runner uses ONLY
new pre-action HTTP/operator telemetry and a local trusted model artifact.
Never use private oracle labels as inference features.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path

from pilot import wait_ready, setup_fault, gateway_probes
from operator_telemetry_v2 import operator_telemetry_v2
from model_adapter import load_local_bundle
from lab_ai_decision import select_lab_defense
from lab_autonomous_execution import execute_lab_recommendation
from predict_shield.lab_scope_evidence import collect_live_scope


def run(*, project: str, model: Path, trusted_sha256: str, control_token: str,
        oracle_token: str, output: Path) -> dict:
    if output.exists():
        raise FileExistsError("Pilot report already exists")
    if len(control_token) < 24 or len(oracle_token) < 24 or control_token == oracle_token:
        raise ValueError("Separate disposable lab tokens required")
    if not trusted_sha256:
        raise ValueError("Expected model SHA-256 required from trusted local manifest")
    bundle=load_local_bundle(model,trusted_sha256=trusted_sha256)
    wait_ready()
    # One fixed configuration: a new physical execution of a known fault family.
    setup_fault(control_token, ttl_ms=5000, delay_ms=125,
                fault_target="enforcer-b", fault_mode="loss",
                oracle_token=oracle_token, gateway_includes_hidden=True,
                routing_profile="balanced", complexity_stratum="SIMPLE")
    pre={
        "run_id":"physical-ai-scope-pilot-v1",
        "experiment_type":"real_kafka_multijvm_lab",
        "oracle_features_excluded":True,
        "routing_profile":"balanced",
        "features":{
            "cache_ttl_ms":5000,
            "requested_rps":25,
            "measurement_seconds":4,
            "visible_enforcement_processes":4,
        },
        "external_deny_observations":gateway_probes(24),
        "operator_observations":operator_telemetry_v2(control_token),
    }
    snapshot, scope, inventory=collect_live_scope(
        project=project, token=control_token, case_id=pre["run_id"])
    recommendation=select_lab_defense(bundle,pre,snapshot,
                                      remaining_budget=50,restart_permitted=False)
    if (recommendation["abstained"] or
            recommendation["selected_action"] is None):
        execution={"status":"ABSTAINED","action_executed":False,
                   "oracle_verdict":"NOT_EVALUATED",
                   "independent_postcondition_verified":False}
    else:
        execution=execute_lab_recommendation(
            recommendation,scope_assessment=scope,
            control_token=control_token,oracle_token=oracle_token)
    report={
        "schema":"predict-shield/physical-ai-lab-execution-pilot/1",
        "experimental_scenario":"fixed single bounded Kafka event-loss, full gateway visibility",
        "pre_action_observed_gateway_probes":len(pre["external_deny_observations"]),
        "pre_action_operator_observations":len(pre["operator_observations"]),
        "snapshot_id":snapshot.snapshot_id,
        "scope":scope,
        "discovery_digest":inventory["sha256"],
        "model_artifact_sha256":trusted_sha256,
        "model_training_fingerprint":bundle["training_fingerprint"],
        "recommendation":recommendation,
        "execution":execution,
        "laboratory_only":True,
        "independent_new_fault_family":False,
        "production_service_budget_verified":False,
    }
    report["sha256"]=hashlib.sha256(
        json.dumps(report,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    return report


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--project",required=True)
    p.add_argument("--model",type=Path,required=True)
    p.add_argument("--trusted-sha256",required=True)
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    result=run(project=args.project,model=args.model,
               trusted_sha256=args.trusted_sha256,
               control_token=os.environ.get("LAB_CONTROL_TOKEN",""),
               oracle_token=os.environ.get("LAB_ORACLE_TOKEN",""),
               output=args.output)
    print("PHYSICAL MODEL LAB RESULT:",
          result["recommendation"]["selected_action"],
          result["execution"]["status"],
          "oracle:",result["execution"].get("oracle_verdict","unknown"))


if __name__=="__main__":
    main()
