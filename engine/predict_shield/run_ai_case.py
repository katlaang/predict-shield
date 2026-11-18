"""Read-only command-line entry point for a local AI vulnerability case.

No field-supplied evidence is treated as authenticated production authority.
The CLI does not accept approval tokens, invoke a lab actuator, or certify
successful remediation.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .ai_contracts import ActionTier, CandidateAction
from .local_ai import LocalOllama
from .pipeline import plan_case


def load_catalog(path: Path) -> tuple[tuple[CandidateAction,...],tuple[str,...]]:
    payload=json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema")!="predict-shield/lab-action-catalog/1":
        raise ValueError("Unsupported catalog schema")
    records=payload.get("actions")
    checks=payload.get("allowed_verification_checks")
    if not isinstance(records,list) or not records or not isinstance(checks,list) or not checks:
        raise ValueError("Explicit actions and read-only verification check IDs required")
    actions=[]
    for record in records:
        if not isinstance(record,dict) or set(record)!={"action_id","tier",
                "affected_services","postcondition","reversible"}:
            raise ValueError("Malformed action definition")
        if (not isinstance(record["affected_services"],list)
                or not record["affected_services"] or
                any(not isinstance(s,str) or not s for s in record["affected_services"])
                or type(record["reversible"]) is not bool):
            raise ValueError("Invalid service closure or reversibility")
        actions.append(CandidateAction(record["action_id"],ActionTier(record["tier"]),
                          tuple(record["affected_services"]),
                          record["postcondition"],record["reversible"]))
    if len({a.action_id for a in actions})!=len(actions):
        raise ValueError("Duplicate action identities")
    if len(set(checks))!=len(checks) or any(not isinstance(c,str) or not c for c in checks):
        raise ValueError("Duplicate or malformed verification check IDs")
    return tuple(actions),tuple(checks)


def main():
    parser=argparse.ArgumentParser(description="Local-model advisory assessment; no remediation")
    parser.add_argument("--case-id",required=True)
    parser.add_argument("--discovery",type=Path,required=True)
    parser.add_argument("--advisories",type=Path,required=True)
    parser.add_argument("--catalog",type=Path,required=True)
    parser.add_argument("--model",required=True)
    parser.add_argument("--model-fingerprint",required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():
        parser.error("Refusing to overwrite case evidence")
    actions,checks=load_catalog(args.catalog)
    report=plan_case(
        case_id=args.case_id,
        discovery=json.loads(args.discovery.read_text(encoding="utf-8")),
        advisories=json.loads(args.advisories.read_text(encoding="utf-8")),
        local_model=LocalOllama(args.model,args.model_fingerprint),
        actions=actions,verification_check_ids=checks)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print("AI case",report["case_id"],"proposals",len(report["ai_proposals"]),
          "policy",report["selection_status"],"dispatch: forbidden by this CLI")


if __name__=="__main__":
    main()
