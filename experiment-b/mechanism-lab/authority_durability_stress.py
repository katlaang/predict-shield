"""Isolated physical repeated authority crash/restart witness; outage truth UNKNOWN.

No invented success labels, AI recommendation, production credentials, or
authorization bypass. Every cycle preserves a separate report before next.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path

from pilot import request, setup_fault, wait_ready
from physical_faults import compose_command, wait_authority_unavailable
from authority_outage_actions import verify_authority_restored


def _policy(oracle_token):
    status, snap, _ = request("oracle", "/oracle/observe", oracle=oracle_token, timeout=5)
    if status!=200 or snap.get("authority_http")!=200:
        raise RuntimeError("No independent online authority policy witness")
    obj=snap.get("authority",{})
    if (type(obj.get("revoked")) is not bool or obj["revoked"] is not True
            or type(obj.get("revision")) is not int or not obj.get("trialId")):
        raise RuntimeError("No independently witnessed active revocation")
    return obj


def _outage(oracle_token):
    status, snap, _=request("oracle", "/oracle/observe", oracle=oracle_token, timeout=5)
    if status!=200 or snap.get("authority_http") is not None:
        raise RuntimeError("Authority was still available or oracle unavailable")
    if snap.get("authority_truth_available") is not False or snap.get("all_revoked_access_denied") is not None:
        raise RuntimeError("Outage incorrectly asserted VERIFIED security truth")
    return {"authority_http":None,"authority_truth":"UNKNOWN",
            "security_verdict":"INDETERMINATE"}


def run(control_token,oracle_token,compose_dir,output_dir,cycles=3):
    if (min(len(control_token),len(oracle_token))<24
            or control_token==oracle_token or not 2<=cycles<=5):
        raise ValueError("Distinct disposable tokens and 2–5 cycles required")
    if output_dir.exists():
        raise FileExistsError("Refusing overwrite of durability evidence directory")
    output_dir.mkdir(parents=True,exist_ok=False)
    wait_ready()
    setup_fault(control_token,ttl_ms=30000,delay_ms=0,
                fault_target="enforcer-b",fault_mode="loss",
                oracle_token=oracle_token,gateway_includes_hidden=True)
    policy=_policy(oracle_token)
    initial=policy.copy()
    complete=[]
    for index in range(cycles):
        stopped=False
        try:
            compose_command(["stop","authority"],cwd=compose_dir)
            stopped=True
            wait_authority_unavailable()
            observed=_outage(oracle_token)
        finally:
            if stopped:
                compose_command(["start","authority"],cwd=compose_dir)
                wait_ready()
        recovered=verify_authority_restored(
            request,oracle_token=oracle_token,expected_policy=policy)
        actual=_policy(oracle_token)
        if any(actual[k]!=policy[k] for k in ("trialId","revision","revoked")):
            raise RuntimeError("Recovered a different trial/policy revision")
        row={"cycle":index+1,"physical_stop_start_observed":True,
             "outage":observed,"recovery_source_continuity":True,
             "policy_revision":actual["revision"],
             "recovered_target_inventory":recovered["declared_target_inventory_observed"],
             "validated_revoked_state":actual["revoked"],
             "field_effectiveness_established":False}
        with (output_dir/f"restart-cycle-{index+1:02d}.json").open("x") as stream:
            json.dump(row,stream,indent=2,sort_keys=True)
            stream.write("\n")
        complete.append(row)
        # Between independent cold restart cycles, write a strictly increasing
        # reaffirmation while the authority is actually up. This confirms
        # durable writes continue after recovery, not just old bytes survive.
        if index<cycles-1:
            status,ack,_=request("authority","/control/reaffirm",method="POST",
                                 token=control_token,timeout=10)
            if status!=202 or ack.get("publication_queued") is not True:
                raise RuntimeError("Post-restart durable authority mutation failed")
            replacement=_policy(oracle_token)
            if (replacement["revision"]!=policy["revision"]+1
                    or replacement["trialId"]!=policy["trialId"]
                    or replacement["revoked"] is not True):
                raise RuntimeError("New durable authority state did not advance safely")
            policy=replacement
    report={
        "schema":"predict-shield/durable-authority-repeated-physical/1",
        "status":"PHYSICAL_LAB_DURABILITY_ONLY",
        "physical_restarts":cycles,"same_trial_id":initial["trialId"]==policy["trialId"],
        "expected_monotonic_revision_increase":cycles-1,
        "observed_revision_increase":policy["revision"]-initial["revision"],
        "all_outage_truth_indeterminate":all(x["outage"]["security_verdict"]=="INDETERMINATE"
                                              for x in complete),
        "all_restarts_retained_revocation":all(x["validated_revoked_state"] for x in complete),
        "cycles":complete,
        "critical_infrastructure_effectiveness_established":False,
        "limitations":["Validates repeated clean Docker stop/start, not kill -9 or torn storage writes",
                       "The record's policy digest is not a cryptographic third-party attestation",
                       "No production cyber-defense success or AI accuracy measured"],
    }
    if (not report["same_trial_id"] or not report["all_outage_truth_indeterminate"]
            or not report["all_restarts_retained_revocation"]
            or report["observed_revision_increase"]!=cycles-1):
        raise RuntimeError("Repeated physical durability conditions not met")
    with (output_dir/"summary.json").open("x") as stream:
        json.dump(report,stream,indent=2,sort_keys=True);stream.write("\n")
    return report


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--execute-isolated-lab",action="store_true")
    p.add_argument("--cycles",type=int,default=3)
    p.add_argument("--output-dir",type=Path,required=True)
    a=p.parse_args()
    if not a.execute_isolated_lab:
        p.error("Physical experiment requires explicit isolated lab opt-in")
    result=run(os.environ.get("LAB_CONTROL_TOKEN",""),
               os.environ.get("LAB_ORACLE_TOKEN",""),
               Path(__file__).resolve().parent,a.output_dir,cycles=a.cycles)
    print(json.dumps({"status":result["status"],
                      "physical_restarts":result["physical_restarts"],
                      "all_outages_INDETERMINATE":result["all_outage_truth_indeterminate"]}))
