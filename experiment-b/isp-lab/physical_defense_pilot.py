"""Execute one lab-only isolate action and independently probe the access service."""
import argparse
import json
import os
from pathlib import Path
from isp_defense import execute_and_verify

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():
        parser.error("Refusing evidence overwrite")
    # Lab-only scenario is exact-asset and hardcoded. Model uncertainty is not
    # promoted to execution eligibility. An AI predictor can suggest but cannot
    # authorize this controlled simulated network experiment.
    proposal={"research_lab_only":True,"selected_action":"isolate_access",
              "policy_decision":"ELIGIBLE_LAB_ONLY","scope_complete":True,
              "approved_lab_asset":"simulated-broadband-access"}
    outcome=execute_and_verify(base="http://127.0.0.1:18310",
                token=os.environ.get("LAB_ACCESS_TOKEN",""),proposal=proposal)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(outcome,indent=2,sort_keys=True)+"\n")
    print("PHYSICAL ISP LAB POSTCONDITION:",outcome["postcondition"])
    if outcome["postcondition"]!="VERIFIED_LAB_ONLY":
        raise RuntimeError("Actual action did not meet defined lab postcondition")

if __name__=="__main__":
    main()
