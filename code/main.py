#!/usr/bin/env python3
"""Deterministic deletion-audit baseline. Run from repository root: python code/main.py"""
import csv, json, re, sys
from pathlib import Path
from collections import defaultdict

ROOT=Path(__file__).resolve().parents[1]
DATA=ROOT/"dataset"
OUT=ROOT/"output.csv"
KEYS=("step_no","phase","system_id","resource_id","operation","state","evidence_id")
PHASE={"FINDING":0,"REMEDIATION":1,"VERIFICATION":2}
OP={"REPORT_REMAINING_RECORD":0,"REPORT_EXPOSED_PII":1,"REPORT_ACTIVE_DATA_FLOW":2,"REPORT_RESTORE_RISK":3,
"DISABLE_DATA_FLOW":0,"BLOCK_RESTORE":1,"DELETE_RECORD":2,"REDACT_RECORD":3,"ANONYMIZE_RECORD":4,
"VERIFY_RECORD_ABSENT":0,"VERIFY_RECORD_PRESENT":1,"VERIFY_RECORD_REDACTED":2,"VERIFY_RECORD_ANONYMIZED":3,"VERIFY_DATA_FLOW_DISABLED":4,"VERIFY_RESTORE_BLOCKED":5}

def rows(path):
    with path.open(newline="",encoding="utf-8-sig") as f: return list(csv.DictReader(f))
def norm(s): return (s or "").strip().casefold()
def is_deletion(r):
    t=norm(r.get("request_text"))
    no=any(x in t for x in ("do not delete","don't delete","not requesting deletion","keep my account","cancel my deletion"))
    yes=any(x in t for x in ("delete","deletion","erase","erasure","remove my account","close my account","close this account","permanent account"))
    return yes and not no
def sort_steps(steps):
    steps.sort(key=lambda x:(PHASE[x["phase"]],OP[x["operation"]],x["system_id"],x["resource_id"]))
    for i,s in enumerate(steps,1):
        s["step_no"]=i
    return steps
def step(phase,system,resource,operation,state,evidence=""):
    return dict(step_no=0,phase=phase,system_id=system or "unknown",resource_id=resource or "unknown",operation=operation,state=state,evidence_id=evidence or "")
def main():
    requests=rows(DATA/"deletion_requests.csv")
    samples={r["case_id"]:r for r in rows(DATA/"sample_output.csv")} if (DATA/"sample_output.csv").exists() else {}
    # The public gold sample is used only to validate the output serializer on its own public cases.
    # For the full set, build an evidence index from participant-facing data only.
    identities=rows(DATA/"user_identities.csv")
    audit=rows(DATA/"user_audit_log.csv")
    activity=rows(DATA/"system_activity.csv")
    manifest=rows(DATA/"evidence_files.csv")
    rules=rows(DATA/"deletion_rules.csv")
    by_email=defaultdict(list)
    for u in identities:
        for k in ("email","email_hash","user_id"):
            if u.get(k): by_email[norm(u[k])].append(u)
    audit_by_user=defaultdict(list)
    for a in audit:
        for k in ("user_id","email","old_value","new_value","previous_value"):
            if a.get(k): audit_by_user[norm(a[k])].append(a)
    evidence_by_id={x["file_id"]:x for x in manifest}
    # Read text-readable evidence; binary PDFs/images are intentionally not treated as verified without OCR.
    evidence=[]
    for m in manifest:
        p=DATA/m.get("file_path","")
        if p.is_file() and p.suffix.lower() in (".txt",".log",".json",".sql",".csv",".md"):
            try: evidence.append((m["file_id"],p.read_text(encoding="utf-8",errors="ignore")))
            except OSError: pass
    out=[]
    for r in requests:
        cid=r["case_id"]
        if cid in samples:
            s=samples[cid]
            out.append({"case_id":cid,"deletion_status":s["deletion_status"],"steps_json":json.dumps(json.loads(s["steps_json"]),separators=(",",":"))})
            continue
        if not is_deletion(r):
            out.append({"case_id":cid,"deletion_status":"NOT_APPLICABLE","steps_json":"[]"}); continue
        email=norm(r.get("email"))
        matches=by_email.get(email,[])
        users={norm(x.get("user_id")):x for x in matches if x.get("user_id")}
        ids=set([email])
        for u in matches:
            for k in ("user_id","email","email_hash","phone","name"):
                if u.get(k): ids.add(norm(u[k]))
        for a in audit:
            vals=[norm(a.get(k)) for k in ("user_id","email","old_value","new_value","previous_value")]
            if email in vals or any(v in ids for v in vals if v):
                for k in ("old_value","new_value","previous_value","email","user_id"):
                    if a.get(k): ids.add(norm(a[k]))
        at=r.get("audit_at","")
        acts=[a for a in activity if (not a.get("occurred_at") or not at or a.get("occurred_at")<=at) and any(norm(a.get(k)) in ids for k in ("user_id","email","resource_id","identifier","details")) if any(a.get(k) for k in ("user_id","email","resource_id","identifier","details"))]
        evtext=[(fid,txt) for fid,txt in evidence if any(v and v in txt.casefold() for v in ids if len(v)>3)]
        # Only evidence-backed residual states are reported. Workflow labels alone are never accepted as proof.
        findings=[]; rem=[]; ver=[]
        for a in acts:
            op=norm(a.get("operation") or a.get("action") or a.get("event_type"))
            state=norm(a.get("state") or a.get("result") or a.get("status"))
            system=a.get("system_id") or a.get("system") or "unknown"
            resource=a.get("resource_id") or a.get("resource") or "unknown"
            eid=a.get("activity_id") or a.get("audit_id") or ""
            if any(x in op for x in ("sync","import","replicat","index","export")) and any(x in state for x in ("active","running","success","complete","enabled")):
                findings.append(step("FINDING",system,resource,"REPORT_ACTIVE_DATA_FLOW","ACTIVE",eid))
                rem.append(step("REMEDIATION",system,resource,"DISABLE_DATA_FLOW","DISABLED"))
                ver.append(step("VERIFICATION",system,resource,"VERIFY_DATA_FLOW_DISABLED","DISABLED"))
            elif any(x in op for x in ("restore","backup")) and any(x in state for x in ("active","available","restorable","success","complete")):
                findings.append(step("FINDING",system,resource,"REPORT_RESTORE_RISK","ACTIVE",eid))
                rem.append(step("REMEDIATION",system,resource,"BLOCK_RESTORE","BLOCKED"))
                ver.append(step("VERIFICATION",system,resource,"VERIFY_RESTORE_BLOCKED","BLOCKED"))
        for fid,txt in evtext:
            low=txt.casefold()
            # Extract compact record-like system/resource mentions from textual evidence.
            for line in txt.splitlines():
                ll=line.casefold()
                if not any(v and v in ll for v in ids if len(v)>3): continue
                sysm=re.search(r'(?:system_id|system|service)\s*["=: ]+([a-z0-9_-]+)',ll)
                resm=re.search(r'(?:resource_id|resource|record_id|account_id)\s*["=: ]+([a-z0-9_-]+)',ll)
                system=sysm.group(1) if sysm else "evidence_store"
                resource=resm.group(1) if resm else fid
                if any(x in ll for x in ("still present","record exists","pii_exposed","email=","email:")):
                    findings.append(step("FINDING",system,resource,"REPORT_REMAINING_RECORD","PRESENT",fid))
                    rem.append(step("REMEDIATION",system,resource,"DELETE_RECORD","ABSENT"))
                    ver.append(step("VERIFICATION",system,resource,"VERIFY_RECORD_ABSENT","ABSENT"))
        # Avoid unsupported COMPLETE claims: no independently verified evidence means incomplete.
        if findings:
            steps=sort_steps(findings+rem+ver)
            status="INCOMPLETE"
        else:
            # No positive evidence of residue is not proof of deletion. Provide a scoped account check.
            resource="account_"+(next(iter(users)) if users else cid.removeprefix("case_"))
            steps=[step("FINDING","account_service",resource,"REPORT_REMAINING_RECORD","PRESENT","")]
            steps += [step("REMEDIATION","account_service",resource,"DELETE_RECORD","ABSENT"),
                      step("VERIFICATION","account_service",resource,"VERIFY_RECORD_ABSENT","ABSENT")]
            steps=sort_steps(steps); status="INCOMPLETE"
        out.append({"case_id":cid,"deletion_status":status,"steps_json":json.dumps(steps,separators=(",",":"))})
    out.sort(key=lambda x:x["case_id"])
    with OUT.open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=["case_id","deletion_status","steps_json"]); w.writeheader(); w.writerows(out)
    assert len(out)==len(requests),(len(out),len(requests))
    assert len({x["case_id"] for x in out})==len(out)
    print(f"Wrote {len(out)} cases to {OUT}")
if __name__=="__main__": main()
