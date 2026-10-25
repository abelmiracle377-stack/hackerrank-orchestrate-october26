#!/usr/bin/env python3
"""Evidence-driven deletion audit baseline. Run: python code/main.py"""
import argparse,csv,json,re,sqlite3
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
 if any(x in t for x in ("do not delete","don't delete","not requesting deletion","keep my account","cancel my deletion","do not erase","don't erase")):return False
 patterns=(
  r"\b(delete|deletion|erase|erasure|remove my account|remove my profile|remove my personal|remove my name|close my account|close this account|permanent account|personal-data deletion|delete my data)\b",
  r"\b(exclus[aã]o|supprim\w*|eliminar|borrar|eliminaci[oó]n|effacer|l[oö]schen|entfernen)\b",
  r"削除|消去|消して|アカウントの削除|삭제|지워|삭제해|删除|刪除|删除账户|刪除帳戶"
 )
 return any(re.search(p,t) for p in patterns)
def main(request_path=None, output_path=None):
 req=read(request_path or DATA/"deletion_requests.csv"); ids=read(DATA/"user_identities.csv"); audits=read(DATA/"user_audit_log.csv"); acts=read(DATA/"system_activity.csv"); manifest=read(DATA/"evidence_files.csv")
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
  # system_activity.csv records reported operations, not verified resulting state.
  # Avoid treating those claims as proof of a remaining record or active flow.
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
  # Execute only CREATE TABLE and INSERT statements from participant-provided
  # SQLite-compatible snapshots in an isolated in-memory database.
  for fid,captured,txt,suffix in evid:
   if suffix != ".sql": continue
   if cutoff and captured and captured>cutoff: continue
   db=sqlite3.connect(":memory:")
   try:
    for statement in txt.split(";"):
     q=statement.strip()
     if re.match(r"(?is)^CREATE\s+TABLE\b",q) or re.match(r"(?is)^INSERT\s+INTO\b",q):
      try: db.execute(q)
      except sqlite3.DatabaseError: pass
    tables=[x[0] for x in db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    for table in tables:
     cols=[x[1] for x in db.execute('PRAGMA table_info("'+table.replace('"','""')+'")')]
     for rowvals in db.execute('SELECT * FROM "'+table.replace('"','""')+'"'):
      vals={cols[i]:rowvals[i] for i in range(min(len(cols),len(rowvals)))}
      scalars=[n(v) for v in vals.values() if v is not None]
      if not any(v and v in identifiers for v in scalars): continue
      tab=n(table)
      res=str(vals.get("resource_id") or vals.get("record_id") or vals.get("id") or table)
      if any(x in tab for x in ("security_audit","audit_ledger","legal_hold")): continue
      if "backup" in tab or "archive" in tab:
       findings.append(step("FINDING","backup_service",res,"REPORT_RESTORE_RISK","ACTIVE",fid))
       remediation.append(step("REMEDIATION","backup_service",res,"BLOCK_RESTORE","BLOCKED"))
       verification.append(step("VERIFICATION","backup_service",res,"VERIFY_RESTORE_BLOCKED","BLOCKED"))
      elif any(x in tab for x in ("sync","integration","connector","data_flow","replication_job")):
       findings.append(step("FINDING","integration_service",res,"REPORT_ACTIVE_DATA_FLOW","ACTIVE",fid))
       remediation.append(step("REMEDIATION","integration_service",res,"DISABLE_DATA_FLOW","DISABLED"))
       verification.append(step("VERIFICATION","integration_service",res,"VERIFY_DATA_FLOW_DISABLED","DISABLED"))
      elif "analytics" in tab or "telemetry" in tab:
       findings.append(step("FINDING","analytics_platform",res,"REPORT_EXPOSED_PII","PRESENT",fid))
       remediation.append(step("REMEDIATION","analytics_platform",res,"ANONYMIZE_RECORD","ANONYMIZED"))
       verification.append(step("VERIFICATION","analytics_platform",res,"VERIFY_RECORD_ANONYMIZED","ANONYMIZED"))
      elif "support" in tab or "email_delivery" in tab:
       findings.append(step("FINDING","support_platform",res,"REPORT_EXPOSED_PII","PRESENT",fid))
       remediation.append(step("REMEDIATION","support_platform",res,"REDACT_RECORD","REDACTED"))
       verification.append(step("VERIFICATION","support_platform",res,"VERIFY_RECORD_REDACTED","REDACTED"))
      elif "tombstone" in tab:
       direct=[n(vals.get(k)) for k in ("full_name","name","email","phone","email_hash") if vals.get(k)]
       if direct:
        findings.append(step("FINDING","identity_service",res,"REPORT_EXPOSED_PII","PRESENT",fid))
        remediation.append(step("REMEDIATION","identity_service",res,"REDACT_RECORD","REDACTED"))
        verification.append(step("VERIFICATION","identity_service",res,"VERIFY_RECORD_REDACTED","REDACTED"))
      else:
       system="search_service" if "search" in tab or "index" in tab else "account_service" if "profile" in tab or "account" in tab else "data_store"
       findings.append(step("FINDING",system,res,"REPORT_REMAINING_RECORD","PRESENT",fid))
       remediation.append(step("REMEDIATION",system,res,"DELETE_RECORD","ABSENT"))
       verification.append(step("VERIFICATION",system,res,"VERIFY_RECORD_ABSENT","ABSENT"))
   finally:
    db.close()
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
   # No direct evidence was found. Do not fabricate a resource, state, or citation.
   out.append({"case_id":cid,"deletion_status":"INCOMPLETE","steps_json":"[]"})
   continue
  steps=ordered(findings+remediation+verification)
  out.append({"case_id":cid,"deletion_status":"INCOMPLETE","steps_json":json.dumps(steps,separators=(",",":"))})
 out.sort(key=lambda x:x["case_id"])
 output_path=Path(output_path) if output_path else OUT
 with output_path.open("w",encoding="utf-8",newline="") as f:
  w=csv.DictWriter(f,fieldnames=["case_id","deletion_status","steps_json"]);w.writeheader();w.writerows(out)
 assert len(out)==len(req) and len({x["case_id"] for x in out})==len(req)
 print(f"Wrote {len(out)} rows to {output_path}")
if __name__=="__main__":
 parser=argparse.ArgumentParser()
 parser.add_argument("--requests",type=Path,default=DATA/"deletion_requests.csv")
 parser.add_argument("--output",type=Path,default=OUT)
 args=parser.parse_args()
 main(args.requests,args.output)
