"""Opt-in read-only localhost telecom management collectors.

SNMPv3 authPriv sysName via Net-SNMP, and TLS-verified gNMI Get via gnmic.
No broad scanning, SSH, writes, configuration changes, or remote targets.
"""
from __future__ import annotations
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

SYSNAME = "1.3.6.1.2.1.1.5.0"
_SAFE_ID = re.compile(r"^[a-zA-Z0-9._:-]{1,128}$")
_ALLOWED = {"127.0.0.1", "localhost", "::1"}


def _device_id(value):
    if not isinstance(value,str) or not _SAFE_ID.fullmatch(value):
        raise ValueError("Explicit safe asset identifier required")
    return value


def _stamp():
    return datetime.now(timezone.utc).isoformat()


def snmpv3_sysname(*, device_id: str, port: int, user: str,
                   auth_passphrase: str, privacy_passphrase: str,
                   runner=subprocess.run) -> dict:
    """SNMPv3 with authentication and encryption. Secret values never in argv."""
    device_id=_device_id(device_id)
    if not 1024 <= port <= 65535 or not _SAFE_ID.fullmatch(user):
        raise ValueError("Invalid SNMPv3 localhost endpoint or user")
    if not all(isinstance(x,str) and len(x)>=8 and "\n" not in x and "\r" not in x
               for x in (auth_passphrase,privacy_passphrase)):
        raise ValueError("SNMPv3 authPriv passphrases required")
    # Net-SNMP supports these configuration directives. Private temp dir is
    # removed even on failure, and no credential-bearing command-line flags.
    with tempfile.TemporaryDirectory(prefix="ps-snmp-",) as directory:
        config=Path(directory)/"snmp.conf"
        config.write_text("defAuthPassphrase "+auth_passphrase+"\n"
                          "defPrivPassphrase "+privacy_passphrase+"\n")
        config.chmod(0o600)
        env={**os.environ,"SNMPCONFPATH":directory}
        cmd=["snmpget","-v3","-l","authPriv","-u",user,"-a","SHA","-x","AES",
             "-Oqv",f"udp:127.0.0.1:{port}",SYSNAME]
        result=runner(cmd,env=env,capture_output=True,text=True,timeout=12,check=True)
    name=result.stdout.strip().strip('"')
    if not name or len(name)>256 or "\n" in name:
        raise ValueError("Missing SNMP sysName response")
    return {"schema":"predict-shield/telecom-source-export/1",
            "source_kind":"telemetry","source_id":"snmpv3:"+device_id+":"+str(port),
            "collected_at":_stamp(),
            "assets":[{"asset_id":device_id,"type":"router",
                       "attributes":{"name":name,"management_protocol":"SNMPv3-authPriv",
                                     "management_loopback_port":port}}],
            "links":[]}


def gnmi_get_interfaces(*, device_id: str, port: int, ca: Path, client_cert: Path,
                        client_key: Path, runner=subprocess.run) -> dict:
    """Only TLS-validated gNMI Get. No insecure or skip-verify option."""
    device_id=_device_id(device_id)
    if not 1024 <= port <= 65535:
        raise ValueError("Invalid localhost gNMI port")
    for file in (ca,client_cert,client_key):
        if not file.is_file() or file.is_symlink():
            raise ValueError("Missing regular local TLS identity file")
    cmd=["gnmic","--address",f"127.0.0.1:{port}",
         "--tls-ca",str(ca),"--tls-cert",str(client_cert),"--tls-key",str(client_key),
         "--format","json","get","--path","/interfaces/interface/state"]
    result=runner(cmd,capture_output=True,text=True,timeout=20,check=True)
    data=json.loads(result.stdout)
    if not isinstance(data,dict) or not isinstance(data.get("updates"),list):
        raise ValueError("Unexpected gNMI Get JSON response")
    # Raw update preservation is intentionally narrow: each bounded response
    # is evidence for the device, not blindly flattened to invented link edges.
    if len(result.stdout)>1024*1024:
        raise ValueError("Oversized gNMI response")
    return {"schema":"predict-shield/telecom-source-export/1",
            "source_kind":"telemetry","source_id":"gnmi:"+device_id+":"+str(port),
            "collected_at":_stamp(),
            "assets":[{"asset_id":device_id,"type":"router",
                       "attributes":{"management_protocol":"gNMI-TLS",
                                     "get_update_count":len(data["updates"])}}],
            "links":[]}


def main():
    import argparse
    parser=argparse.ArgumentParser(description="Read-only loopback network collector")
    sub=parser.add_subparsers(dest="protocol",required=True)
    sn=sub.add_parser("snmpv3")
    sn.add_argument("--device-id",required=True)
    sn.add_argument("--port",type=int,required=True)
    sn.add_argument("--user",required=True)
    gm=sub.add_parser("gnmi")
    gm.add_argument("--device-id",required=True)
    gm.add_argument("--port",type=int,required=True)
    gm.add_argument("--ca",required=True,type=Path)
    gm.add_argument("--client-cert",required=True,type=Path)
    gm.add_argument("--client-key",required=True,type=Path)
    parser.add_argument("--output",required=True,type=Path)
    args=parser.parse_args()
    if args.output.exists():
        parser.error("Refusing to overwrite original collection")
    if args.protocol=="snmpv3":
        report=snmpv3_sysname(device_id=args.device_id,port=args.port,user=args.user,
              auth_passphrase=os.environ.get("PS_SNMP_AUTH",""),
              privacy_passphrase=os.environ.get("PS_SNMP_PRIV",""))
    else:
        report=gnmi_get_interfaces(device_id=args.device_id,port=args.port,
              ca=args.ca,client_cert=args.client_cert,client_key=args.client_key)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("Observed device via",args.protocol,"asset",args.device_id,
          "links confirmed: 0")

if __name__=="__main__":
    main()
