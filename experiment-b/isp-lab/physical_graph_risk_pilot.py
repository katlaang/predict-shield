"""End-to-end research smoke test: real SNMP assets -> graph -> trained risk score.

The training labels and service dependency are deliberately synthetic.
No claim of calibrated telecom risk or production-ready defense is made.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
from urllib.request import urlopen
from predict_shield.telecom_collectors import snmpv3_sysname
from predict_shield.telecom_graph import build_graph
from predict_shield.graph_risk import predict_graph_risk
from graph_risk_training import fit_and_evaluate

SERV="simulated-broadband-access"
ASSETS=(("edge-a",11611),("aggregation-b",11612),("forgotten-c",11613))


def synthetic_training_rows():
    data=[]
    for group in range(10):
        for cls in range(2):
            asset=f"synthetic-router-{group}-{cls}"
            graph={"schema":"predict-shield/asset-evidence-graph/1",
                  "nodes":[{"asset_id":asset,"type":"router"},{"asset_id":SERV,"type":"service"}],
                  "edges":[{"source":asset,"target":SERV,
                            "relation":"SERVES","status":"DECLARED"}],
                  "unresolved_links":[]}
            data.append({"topology_group":f"toy-{group}",
                         "split":"train" if group<8 else "test",
                         "asset_id":asset,"graph":graph,"critical_services":[SERV],
                         "confirmed_exposure":float(cls),
                         "observed_security_incident":bool(cls)})
    return data


def run(output:Path):
    if output.exists():raise FileExistsError("Report already exists")
    auth=os.environ["LAB_SNMP_AUTH"]
    priv=os.environ["LAB_SNMP_PRIV"]
    exports=[]
    for name,port in ASSETS:
        evidence=snmpv3_sysname(device_id=name,port=port,user="reader",
                                auth_passphrase=auth,privacy_passphrase=priv)
        if evidence["assets"][0]["attributes"]["name"]!=name:
            raise ValueError("Real SNMPv3 inventory identity mismatch")
        exports.append(evidence)
    # Service relationship is a *declared toy lab scenario*, not discovered
    # L2/optical connectivity and never a physically observed link.
    exports.append({"schema":"predict-shield/telecom-source-export/1",
        "source_kind":"inventory","source_id":"synthetic-service-dependency",
        "collected_at":exports[0]["collected_at"],
        "assets":[{"asset_id":SERV,"type":"service","attributes":{"simulated":True}}],
        "links":[{"source":"forgotten-c","target":SERV,
                  "relation":"SERVES","evidence_id":"synthetic-declared-dependency"}]})
    graph=build_graph(exports)
    with urlopen("http://127.0.0.1:18310/protected",timeout=4) as response:
        status=response.status
    if status not in (200,403):
        raise ValueError("Unexpected measured service status")
    # Actual HTTP ALLOW is an observed path exposure under the synthetic
    # expected-deny scenario; it is NOT a confirmed software vulnerability.
    exposure=float(status==200)
    bundle,training_report=fit_and_evaluate(synthetic_training_rows())
    score=predict_graph_risk(bundle,graph,"forgotten-c",
          critical_services=(SERV,),confirmed_exposure=exposure)
    report={"schema":"predict-shield/physical-isp-graph-risk-smoke-test/1",
      "actual_snmp_agents_polled":len(ASSETS),
      "actual_simulated_service_http_status":status,
      "source_graph_sha256":graph["sha256"],
      "graph_declared_service_dependency_not_physically_verified":True,
      "model_trained_on_synthetic_labels_only":True,
      "training_test_topologies":training_report["test_groups"],
      "risk_model_prediction":score,
      "independent_ai_superiority_established":False,
      "telco_field_risk_calibration_established":False,
      "defense_action_executed":False}
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    return report

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",required=True,type=Path)
    result=run(parser.parse_args().output)
    print("PHYSICAL ISP GRAPH-INFERENCE:",result["actual_snmp_agents_polled"],
          "agents, model score",result["risk_model_prediction"]["model_score"],
          "action dispatched: false")
