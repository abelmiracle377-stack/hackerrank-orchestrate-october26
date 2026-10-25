#!/usr/bin/env python3
"""Evidence-driven deletion audit baseline. Run: python code/main.py"""
import csv,json,re
from pathlib import Path
from collections import defaultdict
ROOT=Path(__file__).resolve().parents[1]; DATA=ROOT/"dataset"; OUT=ROOT/"output.csv"
PHASE={"FINDING":0,"REMEDIATION":1,"VERIFICATION":2}
ORDER={"REPORT_REMAINING_RECORD":0,"REPORT_EXPOSED_PII":1,"REPORT_ACTIVE_DATA_FLOW":2,"REPORT_RESTORE_RISK":3,"DISABLE_DATA_FLOW":0,"BLOCK_RESTORE":1,"DELETE_RECORD":2,"REDACT_RECORD":3,"ANONYMIZE_RECORD":4,"VERIFY_RECORD_ABSENT":0,"VERIFY_RECORD_PRESENT":1,"VERIFY_RECORD_REDACTED":2,"VERIFY_RECORD_ANONYMIZED":3,"VERIFY_DATA_FLOW_DISABLED":4,"VERIFY_RESTORE_BLOCKED":5}
def read(p):
 with open(p,encoding="utf-8-sig",newline="") as f:return list(csv.DictReader(f))
def n(x):return str(x or "").strip().casefold()
def step(ph,sys,res,op,state,eid=""):return {"step_no":0,"phase":ph,"system_id":sys or "unknown","resource_id":res or "unknown","operation":op,"state":state,"evidence_id":eid or ""}
def ordered(ss):
 ss.sort(key=lambda s:(PHASE[s["phase"]],ORDER[s["operation"]],s["system_id"],s["resource_id"]))
 for i,s in enumerate(ss,1):s["step_no"]=i
 return ss
def deletion(r):
 t=n(r.get("request_text"))
 if any(x in t for x in ("do not delete","don't delete","not requesting deletion","keep my account","cancel my deletion")):return False
 return bool(re.search(r"\b(delete|deletion|erase|erasure|remove my account|close my account|close this account|permanent account|exclus[aã]o|supprim|eliminar|borrar)\b",t))
def main():
 req=read(DATA/"deletion_requests.csv"); ids=read(DATA/"user_identities.csv"); audits=read(DATA/"user_audit_log.csv"); acts=read(DATA/"system_activity.csv"); manifest=read(DATA/"evidence_files.csv")
 identity_by_email={n(u.get("email")):u for u in ids if u.get("email")}
 evid=[]
 for m in manifest:
  p=DATA/m["file_path"]
  if p.exists() and p.suffix.lower() in {".txt",".log",".json",".sql",".csv",".md"}:
   try:evid.append((m["file_id"],m["captured_at"],p.read_text(encoding="utf-8",errors="ignore"),p.suffix.lower()))
   except OSError:pass
 out=[]
 for r in req:
  cid=r["case_id"]; email=n(r["email"]); cutoff=r.get("audit_at","")
  if not deletion(r):out.append({"case_id":cid,"deletion_status":"NOT_APPLICABLE","steps_json":"[]"});continue
  # Build transitive identifier closure from current identity and historical field changes.
  user=identity_by_email.get(email); uids={n(user.get("user_id"))} if user else set(); identifiers={email}
  if user:
   identifiers.update(n(user.get(k)) for k in ("user_id","name","phone","email_hash") if user.get(k))
  changed=True
  while changed:
   changed=False
   for a in audits:
    if cutoff and a.get("event_time","")>cutoff:continue
    vals={n(a.get(k)) for k in ("user_id","old_value","new_value") if a.get(k)}
    if (vals & (identifiers|uids)) and n(a.get("user_id")) not in uids:
     uids.add(n(a.get("user_id")));changed=True
    if vals & (identifiers|uids):
     for k in ("old_value","new_value"):
      v=n(a.get(k))
      if v and v not in identifiers:identifiers.add(v);changed=True
  identifiers={x for x in identifiers if len(x)>2}
  findings=[]; remediation=[]; verification=[]
  # Current activity uses event_time/event_type/source_system/target_system/resource_id/reported_result.
  for a in acts:
   if cutoff and a.get("event_time","")>cutoff:continue
   hay=" ".join(n(a.get(k)) for k in ("resource_id","details","source_system","target_system"))
   if not any(v in hay for v in identifiers):continue
   typ=n(a.get("event_type")); result=n(a.get("reported_result")); src=a.get("source_system","unknown"); dst=a.get("target_system","unknown"); res=a.get("resource_id","unknown"); aid=a.get("activity_id","")
   if typ in {"SYNC_RECORD","INDEX_RECORD","REFRESH_CACHE","CREATE_EXPORT","RESTORE_BACKUP","IMPORT_RECORD"} and result not in {"failed","failure"}:
    sys=dst if typ in {"SYNC_RECORD","INDEX_RECORD","REFRESH_CACHE"} else src
    findings.append(step("FINDING",sys,res,"REPORT_ACTIVE_DATA_FLOW","ACTIVE",aid))
    remediation.append(step("REMEDIATION",sys,res,"DISABLE_DATA_FLOW","DISABLED"))
    verification.append(step("VERIFICATION",sys,res,"VERIFY_DATA_FLOW_DISABLED","DISABLED"))
   if typ in {"RESTORE_BACKUP","RESTORE_RECORD"} and result not in {"failed","failure"}:
    findings.append(step("FINDING",src,res,"REPORT_RESTORE_RISK","ACTIVE",aid))
    remediation.append(step("REMEDIATION",src,res,"BLOCK_RESTORE","BLOCKED"))
    verification.append(step("VERIFICATION",src,res,"VERIFY_RESTORE_BLOCKED","BLOCKED"))
  # Parse pipe-delimited operational handover records; these are explicit state observations.
  for fid,captured,txt,suffix in evid:
   if cutoff and captured and captured>cutoff:continue
   for line in txt.splitlines():
    ll=line.casefold()
    if not any(v in ll for v in identifiers):continue
    # Format: timestamp | system | resource | category | state | subject
    m=re.search(r"\|\s*([a-z0-9_-]+)\s*\|\s*([a-z0-9_-]+)\s*\|\s*([a-z0-9_-]+)\s*\|\s*([a-z0-9_-]+)\s*\|",ll)
    if m:
     sys,res,cat,state=m.groups()
     if state in {"found","identifiable","active","present","not_found"}:
      if state=="active":
       op="REPORT_RESTORE_RISK" if "backup" in cat else "REPORT_ACTIVE_DATA_FLOW"
       findings.append(step("FINDING",sys,res,op,"ACTIVE",fid))
       rop="BLOCK_RESTORE" if op=="REPORT_RESTORE_RISK" else "DISABLE_DATA_FLOW"
       vs="BLOCKED" if rop=="BLOCK_RESTORE" else "DISABLED"
       remediation.append(step("REMEDIATION",sys,res,rop,vs)); verification.append(step("VERIFICATION",sys,res,"VERIFY_RESTORE_BLOCKED" if rop=="BLOCK_RESTORE" else "VERIFY_DATA_FLOW_DISABLED",vs))
      elif state in {"found","identifiable","present"}:
       if "security_audit" in cat or "legal_hold" in cat:continue
       if "analytics" in cat or "telemetry" in cat:
        findings.append(step("FINDING",sys,res,"REPORT_EXPOSED_PII","PRESENT",fid)); remediation.append(step("REMEDIATION",sys,res,"ANONYMIZE_RECORD","ANONYMIZED")); verification.append(step("VERIFICATION",sys,res,"VERIFY_RECORD_ANONYMIZED","ANONYMIZED"))
       elif "support_message" in cat or "email_delivery_log" in cat or "tombstone" in cat:
        findings.append(step("FINDING",sys,res,"REPORT_EXPOSED_PII","PRESENT",fid)); remediation.append(step("REMEDIATION",sys,res,"REDACT_RECORD","REDACTED")); verification.append(step("VERIFICATION",sys,res,"VERIFY_RECORD_REDACTED","REDACTED"))
       else:
        findings.append(step("FINDING",sys,res,"REPORT_REMAINING_RECORD","PRESENT",fid)); remediation.append(step("REMEDIATION",sys,res,"DELETE_RECORD","ABSENT")); verification.append(step("VERIFICATION",sys,res,"VERIFY_RECORD_ABSENT","ABSENT"))
  # Parse nested records in structured JSON snapshots. Each snapshot has its own
  # capture timestamp, system, collection and records; use the snapshot timestamp
  # rather than the bundle export timestamp for the audit cutoff.
  for fid,captured,txt,suffix in evid:
   if suffix != ".json": continue
   try: payload=json.loads(txt)
   except (ValueError,TypeError): continue
   snapshots=payload.get("snapshots",[]) if isinstance(payload,dict) else []
   for snap in snapshots:
    snap_time=str(snap.get("captured_at",captured) or captured)
    if cutoff and snap_time and snap_time>cutoff: continue
    sys=str(snap.get("data_store","unknown"))
    collection=n(snap.get("collection",""))
    for rec in snap.get("records",[]):
     if not isinstance(rec,dict): continue
     flat=json.dumps(rec,ensure_ascii=False,sort_keys=True).casefold()
     if not any(v in flat for v in identifiers): continue
     res=str(rec.get("resource_id","unknown"))
     # Inspect nested documents as well as top-level fields, but only treat
     # a record as subject-linked when a scalar identifier matches the case.
     def scalar_values(obj):
      if isinstance(obj,dict):
       for value in obj.values():
        yield from scalar_values(value)
      elif isinstance(obj,list):
       for value in obj:
        yield from scalar_values(value)
      elif obj is not None:
       yield n(obj)
     direct_values=list(scalar_values(rec))
     if not any(v and v in identifiers for v in direct_values): continue
     category=collection
     if any(x in category for x in ("security_audit","audit_ledger")):
      continue  # policy-retained audit evidence is not a deletion target
     if "analytics" in category or "telemetry" in category:
      findings.append(step("FINDING",sys,res,"REPORT_EXPOSED_PII","PRESENT",fid))
      remediation.append(step("REMEDIATION",sys,res,"ANONYMIZE_RECORD","ANONYMIZED"))
      verification.append(step("VERIFICATION",sys,res,"VERIFY_RECORD_ANONYMIZED","ANONYMIZED"))
     elif "support" in category or "message" in category:
      findings.append(step("FINDING",sys,res,"REPORT_EXPOSED_PII","PRESENT",fid))
      remediation.append(step("REMEDIATION",sys,res,"REDACT_RECORD","REDACTED"))
      verification.append(step("VERIFICATION",sys,res,"VERIFY_RECORD_REDACTED","REDACTED"))
     elif "tombstone" in category:
      findings.append(step("FINDING",sys,res,"REPORT_EXPOSED_PII","PRESENT",fid))
      remediation.append(step("REMEDIATION",sys,res,"REDACT_RECORD","REDACTED"))
      verification.append(step("VERIFICATION",sys,res,"VERIFY_RECORD_REDACTED","REDACTED"))
     else:
      findings.append(step("FINDING",sys,res,"REPORT_REMAINING_RECORD","PRESENT",fid))
      remediation.append(step("REMEDIATION",sys,res,"DELETE_RECORD","ABSENT"))
      verification.append(step("VERIFICATION",sys,res,"VERIFY_RECORD_ABSENT","ABSENT"))
  # Deduplicate exact observations and planned actions.
  def dedup(xs):
   d={}
   for s in xs:d[(s["phase"],s["system_id"],s["resource_id"],s["operation"],s["state"],s["evidence_id"])]=s
   return list(d.values())
  findings=dedup(findings);remediation=dedup(remediation);verification=dedup(verification)
  if not findings:
   # Absence cannot be inferred from workflow status; flag the account check as unresolved.
   res="account_"+(next(iter(uids)).replace("user_","") if uids else cid.removeprefix("case_"))
   findings=[step("FINDING","account_service",res,"REPORT_REMAINING_RECORD","PRESENT","")]
   remediation=[step("REMEDIATION","account_service",res,"DELETE_RECORD","ABSENT")]
   verification=[step("VERIFICATION","account_service",res,"VERIFY_RECORD_ABSENT","ABSENT")]
  steps=ordered(findings+remediation+verification)
  out.append({"case_id":cid,"deletion_status":"INCOMPLETE","steps_json":json.dumps(steps,separators=(",",":"))})
 out.sort(key=lambda x:x["case_id"])
 with OUT.open("w",encoding="utf-8",newline="") as f:
  w=csv.DictWriter(f,fieldnames=["case_id","deletion_status","steps_json"]);w.writeheader();w.writerows(out)
 assert len(out)==518 and len({x["case_id"] for x in out})==518
 print(f"Wrote {len(out)} rows to {OUT}")
if __name__=="__main__":main()
