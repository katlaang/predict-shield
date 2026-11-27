"""Fail-closed, crash-durable receipt for authorized normalized P1 network data.

This does NOT ingest external services, label attacks or train a detector.
A receipt is committed atomically only after the entire normalized JSONL
file has been validated. The HMAC pseudonymization key never enters receipts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path

from normalize import DATASETS

HEX = frozenset("0123456789abcdef")


def hex64(x):
    return isinstance(x,str) and len(x)==64 and set(x)<=HEX


def file_digest(path):
    digest=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1048576),b""):
            digest.update(chunk)
    return digest.hexdigest()


def audit_file(path, *, max_records=1000000):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Normalized source must be regular and non-symlink")
    if not 1<=max_records<=1000000:
        raise ValueError("Unbounded normalized receipt")
    counts={"attack_publisher_scenario":0,"unknown":0}
    source=None
    original_sha=None
    scope=None
    seen=set()
    last_number=0
    with path.open("rt",encoding="utf-8",errors="strict") as stream:
        for row_n,line in enumerate(stream,1):
            if len(line)>1000000:
                raise ValueError("Unbounded input record")
            record=json.loads(line)
            if not isinstance(record,dict) or record.get("schema")!="predict-shield/p1-operational-event/1":
                raise ValueError("Unsupported normalized P1 schema")
            actual_source=record.get("source")
            if actual_source not in DATASETS:
                raise ValueError("Unknown P1 dataset adapter")
            actual_sha=record.get("source_sha256")
            scope_id=record.get("pseudonym_scope_id")
            if not hex64(actual_sha) or not hex64(record.get("raw_line_sha256")):
                raise ValueError("Missing original source-line integrity")
            if not isinstance(scope_id,str) or len(scope_id)!=20 or not set(scope_id)<=HEX:
                raise ValueError("Missing pseudonymization scope")
            if source is None:
                source,original_sha,scope=actual_source,actual_sha,scope_id
            if (actual_source,actual_sha,scope_id)!=(source,original_sha,scope):
                raise ValueError("Mixed publisher sources or identity scopes")
            n=record.get("source_line")
            if type(n) is not int or n<=last_number or (actual_sha,n) in seen:
                raise ValueError("Duplicate or non-monotonic source event")
            seen.add((actual_sha,n))
            last_number=n
            if record.get("verified_attack") is not False:
                raise ValueError("Unverified publication treated as verified attack")
            label,basis=record.get("label"),record.get("truth_basis")
            if source=="lanl-redteam":
                if label!="attack" or basis!="publisher_scenario":
                    raise ValueError("Lost publisher red-team positive provenance")
                counts["attack_publisher_scenario"]+=1
            else:
                if label!="unknown" or basis!="unverified":
                    raise ValueError("Unlabelled network telemetry silently reclassified")
                counts["unknown"]+=1
            if row_n>max_records:
                raise ValueError("Exceeded bounded ingestion count")
    if not seen:
        raise ValueError("Empty P1 normalized file")
    return {
        "schema":"predict-shield/p1-admitted-data-receipt/1",
        "status":"VALIDATED_P1_FORMAT_NOT_DETECTION_ACCURACY",
        "dataset":source,"source_sha256":original_sha,
        "normalized_input_sha256":file_digest(path),
        "pseudonym_scope_id":scope,
        "record_count":len(seen),"last_source_line":last_number,
        "labels":counts,
        "original_source_authorization_verified_by_receipt":False,
        "independent_attack_ground_truth_established":False,
        "outcome_verification_established":False,
    }


def write_receipt(receipt, destination):
    """Atomic publish, never silently overwrite or trust an orphan temp file."""
    if destination.is_symlink() or destination.exists():
        raise FileExistsError("Existing receipt cannot be replaced")
    parent=destination.parent
    parent.mkdir(parents=True,exist_ok=True)
    tmp=None
    try:
        fd,name=tempfile.mkstemp(prefix=".p1-admission-",suffix=".tmp",dir=parent)
        tmp=Path(name)
        os.fchmod(fd,0o600)
        with os.fdopen(fd,"wb") as out:
            out.write((json.dumps(receipt,indent=2,sort_keys=True)+"\n").encode())
            out.flush()
            os.fsync(out.fileno())
        # File system atomic create without overwriting an existing receipt.
        os.link(tmp,destination)
        dir_fd=os.open(parent,os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if tmp is not None:
            tmp.unlink(missing_ok=True)


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--input",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--max-records",type=int,default=1000000)
    a=p.parse_args()
    receipt=audit_file(a.input,max_records=a.max_records)
    write_receipt(receipt,a.output)
    print(json.dumps({"status":receipt["status"],"dataset":receipt["dataset"],
                      "record_count":receipt["record_count"],
                      "accuracy_established":False}))
