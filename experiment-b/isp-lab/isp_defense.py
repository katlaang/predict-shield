"""Simulated access-service post-action independent HTTP verification."""
import json
import urllib.error
import urllib.request
from urllib.parse import urlsplit


def _request(base, path, *, method="GET", token=None, opener=None):
    p=urlsplit(base)
    if (p.scheme!="http" or p.hostname not in ("localhost","127.0.0.1","::1")
       or not p.port or p.path or p.query or p.fragment or p.username or p.password):
        raise ValueError("Only localhost simulated ISP service allowed")
    if path not in ("/protected","/healthz","/admin/isolate","/admin/restore"):
        raise ValueError("Unknown scoped path")
    headers={"X-Lab-Access-Token":token} if token else {}
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,req,fp,code,msg,headers,newurl):return None
    transport=opener or urllib.request.build_opener(NoRedirect()).open
    req=urllib.request.Request(base+path,headers=headers,method=method,
                               data=b"" if method=="POST" else None)
    try:
        with transport(req,timeout=4) as r:
            code,data=r.status,r.read(8193)
    except urllib.error.HTTPError as ex:
        code,data=ex.code,ex.read(8193)
    if len(data)>8192:raise ValueError("Oversized HTTP response")
    payload=json.loads(data)
    if not isinstance(payload,dict):raise ValueError("Invalid lab response")
    return code,payload


def execute_and_verify(*, base, token, proposal, baseline_observation=None, requester=None):
    """Explicit lab policy authorization, no ML score alone grants execution."""
    if (proposal.get("lab_only") is not True
       or proposal.get("selected_action")!="isolate_access"
       or proposal.get("policy_decision")!="ELIGIBLE_LAB_ONLY"
       or proposal.get("scope_complete") is not True
       or proposal.get("approved_lab_asset")!="simulated-broadband-access"):
        raise ValueError("Missing exact lab-scope policy eligibility")
    if not isinstance(token,str) or len(token)<24:
        raise ValueError("Missing disposable lab control authorization")
    request=requester or _request
    prior=baseline_observation
    if prior is None:prior=request(base,"/protected")
    if prior[0] not in (200,403):
        raise ValueError("Unknown pre-action service state")
    ack=request(base,"/admin/isolate",method="POST",token=token)
    if ack[0]!=200 or ack[1].get("acknowledged") is not True:
        raise RuntimeError("Isolation action was not accepted")
    # Reuse no action acknowledgment for oracle; fresh GET samples only.
    probes=[request(base,"/protected") for _ in range(6)]
    health=request(base,"/healthz")
    valid=(health[0]==200 and all(code in (200,403) for code,_ in probes))
    verified=valid and all(code==403 and payload.get("decision")=="DENY"
                           for code,payload in probes)
    verdict=("VERIFIED_LAB_ONLY" if verified else
             "NOT_VERIFIED_LAB_ONLY" if valid else "INDETERMINATE")
    return {"schema":"predict-shield/isp-lab-defense-measurement/1",
            "lab_asset":"simulated-broadband-access",
            "action":"isolate_access",
            "pre_http_status":prior[0],
            "post_http_statuses":[code for code,_ in probes],
            "post_health_http_status":health[0],
            "postcondition":verdict,
            "action_ack_is_not_verification":True,
            "cross_service_disruption_measured":False,
            "cross_service_disruption_outcome":"UNKNOWN",
            "lab_only":True,
            "real_telecom_network_protected":False}
