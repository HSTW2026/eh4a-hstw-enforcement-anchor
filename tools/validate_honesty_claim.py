#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, re, sys
from pathlib import Path

HEX64=re.compile(r"^[0-9a-f]{64}$")
TRUTHY_TERMS={"tested","validated","safe","correct","ready","passed","verified"}
VALID_STATUSES={"EXECUTED_LIVE","EXECUTED_MATCHING_CONTROLLED_ENVIRONMENT","SIMULATION_ONLY","REVIEWED_NOT_EXECUTED","UNVERIFIED"}
REQUIRED={"claim_id","subject","subject_sha256","claim_text","status","method","environment","executed_at_utc","result","evidence","limitations"}

def sha256(path: Path)->str:
    h=hashlib.sha256(); h.update(path.read_bytes()); return h.hexdigest()

def fail(msg):
    print(f"DELIVERY_BLOCKED_HONESTY_CONTROL: {msg}"); raise SystemExit(1)

def main(argv):
    if len(argv)!=3: fail("usage: validate_honesty_claim.py CLAIM.json SUBJECT")
    claim_path=Path(argv[1]).resolve(); subject=Path(argv[2]).resolve()
    try: claim=json.loads(claim_path.read_text(encoding="utf-8"))
    except Exception as exc: fail(f"invalid claim JSON: {exc}")
    if not isinstance(claim,dict) or set(claim)!=REQUIRED: fail("claim fields do not match exact schema")
    if claim["status"] not in VALID_STATUSES: fail("invalid status")
    if not subject.is_file(): fail("subject does not exist")
    if not HEX64.fullmatch(str(claim["subject_sha256"])): fail("invalid subject hash format")
    if sha256(subject)!=claim["subject_sha256"]: fail("subject hash mismatch")
    if str(subject)!=claim["subject"]: fail("subject path mismatch")
    for key in ("claim_id","claim_text","method","environment","executed_at_utc","result"):
        if not isinstance(claim[key],str) or not claim[key].strip(): fail(f"missing {key}")
    if not isinstance(claim["limitations"],list): fail("limitations must be a list")
    if not isinstance(claim["evidence"],list) or not claim["evidence"]: fail("evidence must be a non-empty list")
    for idx,e in enumerate(claim["evidence"]):
        if not isinstance(e,dict) or set(e)!={"path","sha256"}: fail(f"evidence[{idx}] invalid schema")
        ep=Path(e["path"]).resolve()
        if not ep.is_file(): fail(f"evidence[{idx}] missing")
        if not HEX64.fullmatch(str(e["sha256"])) or sha256(ep)!=e["sha256"]: fail(f"evidence[{idx}] hash mismatch")
    language=claim["claim_text"].lower()
    consequential=any(re.search(rf"\b{re.escape(t)}\b",language) for t in TRUTHY_TERMS)
    if consequential and claim["status"] in {"SIMULATION_ONLY","REVIEWED_NOT_EXECUTED","UNVERIFIED"}:
        fail("consequential pass language is incompatible with non-executed status")
    if claim["status"]=="EXECUTED_LIVE" and "live" not in claim["environment"].lower():
        fail("EXECUTED_LIVE requires an explicitly identified live environment")
    if claim["status"]!="EXECUTED_LIVE" and "user live environment" in language:
        fail("non-live evidence represented as user live execution")
    print("HONESTY_CLAIM_AUTHORISED")

if __name__=="__main__": main(sys.argv)
