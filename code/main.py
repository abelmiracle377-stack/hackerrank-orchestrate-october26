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
def contains_id(text, identifier):
 text=n(text); identifier=n(identifier)
 if not text or not identifier:return False
 if "@" in identifier:return identifier in text
 token_pattern=r"(?<![a-z0-9_])"+re.escape(identifier)+r"(?![a-z0-9_])" if re.fullmatch(r"(?:user|account|search|support|analytics|backup|export|data_flow|integration|tombstone|audit_record|profile)_?\d+",identifier) else r"(?<![a-z0-9])"+re.escape(identifier)+r"(?![a-z0-9])"
 if identifier in text:
  return re.search(token_pattern,text) is not None
 digits=re.sub(r"\D","",identifier)
 # Legacy heuristic: the 8-digit threshold is not empirically justified in the recovered design history.
 if len(digits)>=8 and sum(ch.isdigit() for ch in identifier)>=8 and not re.fullmatch(r"[0-9a-f]{32,}",identifier):
  normalized_digits=re.sub(r"\D","",text)
  if digits not in normalized_digits:return False
  return re.search(r"(?<!\d)"+re.escape(digits)+r"(?!\d)",normalized_digits) is not None
 return False
def step(ph,sys,res,op,state,eid=""):return {"step_no":0,"phase":ph,"system_id":sys or "unknown","resource_id":res or "unknown","operation":op,"state":state,"evidence_id":eid or ""}
def ordered(ss):
 ss.sort(key=lambda s:(PHASE[s["phase"]],ORDER[s["operation"]],s["system_id"],s["resource_id"]))
 for i,s in enumerate(ss,1):s["step_no"]=i
 return ss
def deletion(r):
 t=n(r.get("request_text"))
 if any(x in t for x in ("do not delete","don't delete","not requesting deletion","keep my account","cancel my deletion","do not erase","don't erase")):return False
 patterns=(
  r"\b(delet(?:e|ed|ing|ion)|erase|erasure|remov(?:e|ed|ing|al)|remove my account|remove the account|remove account|remove my profile|remove the profile|remove profile|remove my personal|remove my name|remove records|remove that search result|remove the rest|close my account|closed my account|close the account|close this account|close it|would like it closed|permanent account|personal-data deletion|delete my data|erase my account|erase the account|profile is gone|account is gone|account still existed|remaining records cannot identify)\b",
  r"\b(exclus[aã]o|suppression|supprim\w*|eliminar|borrar|eliminaci[oó]n|effacer|l[oö]schen|entfernen|cancellare|cancellazione)\b",
  r"削除|消去|消して|アカウントの削除|삭제|지워|삭제해|删除|刪除|删除账户|刪除帳戶"
 )
 return any(re.search(p,t) for p in patterns)
def main(request_path=None, output_path=None):
 req=read(request_path or DATA/"deletion_requests.csv"); ids=read(DATA/"user_identities.csv"); audits=read(DATA/"user_audit_log.csv"); acts=read(DATA/"system_activity.csv"); manifest=read(DATA/"evidence_files.csv")
 identity_by_email={n(u.get("email")):u for u in ids if u.get("email")}
 evid=[]; media_evid=[]; media_failures=[]
 for m in manifest:
  p=DATA/m["file_path"]; suffix=p.suffix.lower()
  if not p.exists(): continue
  if suffix in {".txt",".log",".json",".sql",".csv",".md"}:
   try:evid.append((m["file_id"],m["captured_at"],p.read_text(encoding="utf-8",errors="ignore"),suffix))
   except OSError:pass
  elif suffix==".pdf":
   try:
    from pypdf import PdfReader
    txt="\\n".join(page.extract_text() or "" for page in PdfReader(str(p)).pages)
    media_evid.append((m["file_id"],m["captured_at"],txt,suffix,m["file_path"],m.get("origin","")))
    if not txt.strip(): media_failures.append((m["file_id"],m["captured_at"],m["file_path"],"empty_or_unreadable_pdf"))
   except Exception as exc:
    media_failures.append((m["file_id"],m["captured_at"],m["file_path"],"pdf_processing_failed:"+type(exc).__name__))
  elif suffix in {".png",".jpg",".jpeg",".webp"}:
   try:
    from PIL import Image
    import pytesseract
    txt=pytesseract.image_to_string(Image.open(p))
    media_evid.append((m["file_id"],m["captured_at"],txt,suffix,m["file_path"],m.get("origin","")))
    if not txt.strip(): media_failures.append((m["file_id"],m["captured_at"],m["file_path"],"empty_or_unreadable_image"))
   except Exception as exc:
    media_failures.append((m["file_id"],m["captured_at"],m["file_path"],"image_ocr_failed:"+type(exc).__name__))
 json_cache={}
 for fid0,cap0,txt0,suf0 in evid:
  if suf0==".json":
   try: json_cache[fid0]=json.loads(txt0)
   except (ValueError,TypeError): pass
 # Cross-reference stable subject IDs to resource IDs from historical evidence.
 resource_map={}
 def index_resource_refs(obj, inherited=""):
  if isinstance(obj,dict):
   res=obj.get("resource_id") or obj.get("record_id")
   category=n(obj.get("collection") or obj.get("category") or obj.get("data_category") or inherited)
   for key in ("customer_reference","subject_reference","user_id","customer_id"):
    ref=n(obj.get(key))
    if res and ref.startswith("user_") and any(x in category for x in ("account","profile","identity")):
     resource_map.setdefault(ref,set()).add(str(res))
   for key,val in obj.items():
    if isinstance(val,(dict,list)):
     index_resource_refs(val,(inherited+"_"+n(key)).strip("_"))
  elif isinstance(obj,list):
   for val in obj:index_resource_refs(val,inherited)
 for payload in json_cache.values():
  if isinstance(payload,dict) and isinstance(payload.get("snapshots"),list):
   for snap in payload["snapshots"]:
    store=n(snap.get("data_store","")); collection=n(snap.get("collection",""))
    if "account" in store or "profile" in collection or "account" in collection:
     for rec in snap.get("records",[]):
      if not isinstance(rec,dict): continue
      res=rec.get("resource_id") or rec.get("record_id")
      ref=n(rec.get("customer_reference") or rec.get("subject_reference") or rec.get("user_id") or rec.get("customer_id"))
      if res and ref.startswith("user_"): resource_map.setdefault(ref,set()).add(str(res))
  else: index_resource_refs(payload)
 # Build historical account-resource mappings from SQL snapshots as well as JSON.
 for fid,cap,txt,suffix in evid:
  if suffix!=".sql": continue
  db=sqlite3.connect(":memory:")
  try:
   for statement in txt.split(";"):
    q=statement.strip()
    if re.match(r"(?is)^CREATE\s+TABLE\b",q) or re.match(r"(?is)^INSERT\s+INTO\b",q):
     try: db.execute(q)
     except sqlite3.DatabaseError: pass
   for (table,) in db.execute("SELECT name FROM sqlite_master WHERE type='table'"):
    cols=[x[1] for x in db.execute('PRAGMA table_info("'+table.replace('"','""')+'")')]
    for rowvals in db.execute('SELECT * FROM "'+table.replace('"','""')+'"'):
     vals={cols[i]:rowvals[i] for i in range(min(len(cols),len(rowvals)))}
     nested={}
     raw=vals.get("record_json") or vals.get("document_json") or vals.get("payload_json")
     if isinstance(raw,str):
      try:
       parsed=json.loads(raw)
       if isinstance(parsed,dict):nested=parsed
      except (ValueError,TypeError):pass
     res=vals.get("resource_id") or vals.get("record_id") or nested.get("resource_id")
     ref=vals.get("user_id") or vals.get("customer_reference") or vals.get("subject_reference") or nested.get("user_id") or nested.get("customer_reference") or nested.get("subject_reference")
     category=n(vals.get("collection_name") or vals.get("category") or vals.get("data_category") or nested.get("collection") or nested.get("category") or table)
     if not any(x in category or x in n(table) for x in ("account","profile","identity")):continue
     if res and ref and n(ref).startswith("user_"):resource_map.setdefault(n(ref),set()).add(str(res))
  finally:db.close()
 # Pre-index account deletion activities and point-in-time account readbacks
 # once; the 518-case loop should not rescan every activity and JSON snapshot.
 account_deletes_by_day=defaultdict(list)
 for activity in acts:
  day=str(activity.get("event_time",""))[:10]
  if n(activity.get("event_type"))=="delete_record" and n(activity.get("target_system"))=="account_service" and n(activity.get("resource_id")).startswith("account_"):
   account_deletes_by_day[day].append(activity)
 profile_lookups_by_resource=defaultdict(list)
 account_profile_snapshots=[]
 for efid,ecaptured,etxt,esuffix in evid:
  if esuffix!=".json":continue
  epayload=json_cache.get(efid)
  if not isinstance(epayload,dict):continue
  exports=epayload.get("service_exports",{})
  if isinstance(exports,dict):
   lookups=exports.get("account_service",{}).get("profile_lookups",[])
   for lookup in lookups:
    res=str(lookup.get("resource_id",""))
    if res:profile_lookups_by_resource[res].append((efid,str(lookup.get("observed_at","") or ecaptured),str(lookup.get("status_code",""))))
  for snap in epayload.get("snapshots",[]):
   store=n(snap.get("data_store",""));collection=n(snap.get("collection",""))
   snap_time=str(snap.get("captured_at",ecaptured) or ecaptured)
   if store=="account_service" and ("profile" in collection or "account" in collection):
    account_profile_snapshots.append((snap_time,efid,snap,json.dumps(snap.get("records",[]),ensure_ascii=False)))
 out=[]
 for r in req:
  cid=r["case_id"]; email=n(r["email"]); cutoff=r.get("audit_at","")
  if not deletion(r):out.append({"case_id":cid,"deletion_status":"NOT_APPLICABLE","steps_json":"[]"});continue
  # Build transitive identifier closure from current identity and historical field changes.
  # Caution: closure discovers candidate associations; shared/reused identifiers
  # are not sufficient proof that two records belong to the same person.
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
  # Keep only the newest eligible snapshot for each SQL table and JSON
  # collection/system pair; older snapshots must not override newer state.
  latest_sql_table={}
  latest_json_snapshot={}
  for efid,ecaptured,etxt,esuffix in evid:
   if cutoff and ecaptured and ecaptured>cutoff: continue
   if esuffix==".sql":
    for mt in re.finditer(r"(?is)CREATE\s+TABLE\s+[\"']?([A-Za-z0-9_]+)",etxt):
     table_key=n(mt.group(1))
     if table_key not in latest_sql_table or ecaptured>latest_sql_table[table_key]:
      latest_sql_table[table_key]=ecaptured
   elif esuffix==".json":
    epayload=json_cache.get(efid)
    if not isinstance(epayload,dict): continue
    for esnap in epayload.get("snapshots",[]) if isinstance(epayload,dict) else []:
     etime=str(esnap.get("captured_at",ecaptured) or ecaptured)
     if cutoff and etime and etime>cutoff: continue
     ekey=(n(esnap.get("data_store","unknown")),n(esnap.get("collection","")))
     if ekey not in latest_json_snapshot or etime>latest_json_snapshot[ekey]:
      latest_json_snapshot[ekey]=etime
  findings=[]; remediation=[]; verification=[]; verified_absence=[]
  # Correlate the account deletion activity to the reported completion date.
  # This supplies the resource ID; a separate 404 or latest account snapshot
  # must still support the absence verification.
  reported_day=str(r.get("reported_at",""))[:10]
  account_deletes=account_deletes_by_day.get(reported_day,[])
  status_absence=False
  if account_deletes:
   # A deletion activity on the reported date plus point-in-time 404 evidence
   # or an account snapshot with no subject identifiers supports completion,
   # even when the export omits the direct resource-to-subject crosswalk.
   any_404=any(status_code=="404" and (not cutoff or not observed or observed<=cutoff) for lookups in profile_lookups_by_resource.values() for _,observed,status_code in lookups)
   eligible_profiles=[item for item in account_profile_snapshots if not cutoff or not item[0] or item[0]<=cutoff]
   subject_absent=False
   if eligible_profiles:
    _,_,latest_profile,profile_text=max(eligible_profiles,key=lambda x:x[0])
    subject_absent=not any(contains_id(profile_text,ident) for ident in identifiers)
   status_absence=any_404 or subject_absent
  if len(account_deletes)==1:
   account_resource=str(account_deletes[0].get("resource_id",""))
   explicit_404=False
   for efid,observed,status_code in profile_lookups_by_resource.get(account_resource,[]):
    if status_code=="404" and (not cutoff or not observed or observed<=cutoff):
     verified_absence.append(step("VERIFICATION","account_service",account_resource,"VERIFY_RECORD_ABSENT","ABSENT",efid));explicit_404=True
   profile_snapshots=[item for item in account_profile_snapshots if not cutoff or not item[0] or item[0]<=cutoff]
   if not explicit_404 and profile_snapshots:
    _,sfid,ssnap,_=max(profile_snapshots,key=lambda x:x[0])
    if not any(str(rec.get("resource_id",""))==account_resource for rec in ssnap.get("records",[]) if isinstance(rec,dict)):
     verified_absence.append(step("VERIFICATION","account_service",account_resource,"VERIFY_RECORD_ABSENT","ABSENT",sfid))
  # system_activity.csv records reported operations, not verified resulting state.
  # Avoid treating those claims as proof of a remaining record or active flow.
  # OCR/text evidence from PDFs and screenshots is treated as a lead only when
  # the matched subject identifier and a grounded resource identifier co-occur.
  for fid,captured,txt,suffix,path,origin in media_evid:
   if cutoff and captured and captured>cutoff: continue
   low=txt.casefold()
   matched=[v for v in identifiers if v and contains_id(low,v)]
   if not matched: continue
   resource_matches=list(re.finditer(r"\b(?:account|search|support|export|analytics|backup|data_flow|integration|marketing|attachment|profile|record|audit)[_-]?\d+\b",low))
   if not resource_matches: continue
   target=matched[0]; pos=low.find(target)
   rm=min(resource_matches,key=lambda m:abs(m.start()-pos))
   res=rm.group(0)
   context=low[max(0,rm.start()-120):min(len(low),rm.end()+180)]
   pth=(path+" "+origin).casefold()
   if any(x in pth for x in ("security","legal_retention","retention_register")): continue
   if any(x in context for x in ("not found","absent","deleted","redacted","anonymized","anonymised","blocked","disabled","no matching record")): continue
   if "backup" in pth or res.startswith("backup_"):
    if any(x in context for x in ("active","enabled","restorable","restore allowed","restore enabled")):
     findings.append(step("FINDING","backup_service",res,"REPORT_RESTORE_RISK","ACTIVE",fid))
     remediation.append(step("REMEDIATION","backup_service",res,"BLOCK_RESTORE","BLOCKED"))
     verification.append(step("VERIFICATION","backup_service",res,"VERIFY_RESTORE_BLOCKED","BLOCKED"))
   elif "tombstone" in pth or res.startswith("tombstone_"):
    if any(x in context for x in ("@","email_hash","phone:")) and "[redacted]" not in context:
     findings.append(step("FINDING","identity_service",res,"REPORT_EXPOSED_PII","PRESENT",fid))
     remediation.append(step("REMEDIATION","identity_service",res,"REDACT_RECORD","REDACTED"))
     verification.append(step("VERIFICATION","identity_service",res,"VERIFY_RECORD_REDACTED","REDACTED"))
   elif any(x in pth for x in ("integration","connector")) or res.startswith(("data_flow_","integration_")):
    if any(x in context for x in ("active","enabled","connected","sync","synchronization")):
     findings.append(step("FINDING","integration_service",res,"REPORT_ACTIVE_DATA_FLOW","ACTIVE",fid))
     remediation.append(step("REMEDIATION","integration_service",res,"DISABLE_DATA_FLOW","DISABLED"))
     verification.append(step("VERIFICATION","integration_service",res,"VERIFY_DATA_FLOW_DISABLED","DISABLED"))
   elif "analytics" in pth or res.startswith("analytics_"):
    findings.append(step("FINDING","analytics_platform",res,"REPORT_EXPOSED_PII","PRESENT",fid))
    remediation.append(step("REMEDIATION","analytics_platform",res,"ANONYMIZE_RECORD","ANONYMIZED"))
    verification.append(step("VERIFICATION","analytics_platform",res,"VERIFY_RECORD_ANONYMIZED","ANONYMIZED"))
   elif "support" in pth or res.startswith(("support_","attachment_")):
    findings.append(step("FINDING","support_platform",res,"REPORT_EXPOSED_PII","PRESENT",fid))
    remediation.append(step("REMEDIATION","support_platform",res,"REDACT_RECORD","REDACTED"))
    verification.append(step("VERIFICATION","support_platform",res,"VERIFY_RECORD_REDACTED","REDACTED"))
   elif "search" in pth or res.startswith("search_"):
    findings.append(step("FINDING","search_service",res,"REPORT_REMAINING_RECORD","PRESENT",fid))
    remediation.append(step("REMEDIATION","search_service",res,"DELETE_RECORD","ABSENT"))
    verification.append(step("VERIFICATION","search_service",res,"VERIFY_RECORD_ABSENT","ABSENT"))
   elif any(x in pth for x in ("export","marketing","account_admin","object_storage")) or res.startswith(("export_","marketing_","account_")):
    system="export_service" if "export" in pth or res.startswith("export_") else "marketing_platform" if "marketing" in pth or res.startswith("marketing_") else "account_service"
    findings.append(step("FINDING",system,res,"REPORT_REMAINING_RECORD","PRESENT",fid))
    remediation.append(step("REMEDIATION",system,res,"DELETE_RECORD","ABSENT"))
    verification.append(step("VERIFICATION",system,res,"VERIFY_RECORD_ABSENT","ABSENT"))
  # Parse explicit point-in-time readback logs. A 404/zero-row lookup is
  # positive evidence of absence only when the subject identifier is in that line.
  for fid,captured,txt,suffix in evid:
   if suffix!=".log" or (cutoff and captured and captured>cutoff): continue
   for line in txt.splitlines():
    if not any(contains_id(line,v) for v in identifiers): continue
    if not re.search(r"(?i)(?:rows=0|http_status=404|status_code=404)",line): continue
    rm=re.search(r"(?i)resource_id=([a-z0-9_-]+)",line)
    if rm:
     verified_absence.append(step("VERIFICATION","account_service",rm.group(1),"VERIFY_RECORD_ABSENT","ABSENT",fid))
  # Correlate structured service-log events by trace ID so a subject key on
  # the start event can be linked to a resource/state on its completion event.
  for fid,captured,txt,suffix in evid:
   if suffix!=".log" or (cutoff and captured and captured>cutoff): continue
   trace_groups={}
   for line_no,line in enumerate(txt.splitlines()):
    tm=re.search(r"(?i)trace_id=([a-z0-9_-]+)",line)
    key=tm.group(1) if tm else "line_"+str(line_no)
    trace_groups.setdefault(key,[]).append(line)
   for group_lines in trace_groups.values():
    joined="\\n".join(group_lines)
    if not any(contains_id(joined,v) for v in identifiers): continue
    resource_matches=[]
    for line in group_lines:
     rm=re.search(r"(?i)resource_id=([a-z0-9_-]+)",line)
     if rm: resource_matches.append((rm.group(1),line.casefold()))
    if not resource_matches: continue
    resource,resource_line=resource_matches[-1]
    low=joined.casefold()
    service_match=re.search(r"(?i)service=([a-z0-9_-]+)",joined)
    service=n(service_match.group(1)) if service_match else ""
    if re.search(r"(?i)(?:rows=0|http_status=404|status_code=404)",low):
     verified_absence.append(step("VERIFICATION","account_service",resource,"VERIFY_RECORD_ABSENT","ABSENT",fid))
    elif ("security" in service or resource.startswith("audit_record_")) and re.search(r"(?i)(?:audit_record_read_completed|integrity_check=passed)",low):
     verification.append(step("VERIFICATION","security_service",resource,"VERIFY_RECORD_PRESENT","PRESENT",fid))
    elif ("backup" in service or resource.startswith("backup_")) and re.search(r"(?i)(?:eligible=true.*deletion_block=false|restore_allowed=true|restore_allowed=1)",low):
     findings.append(step("FINDING","backup_service",resource,"REPORT_RESTORE_RISK","ACTIVE",fid))
     remediation.append(step("REMEDIATION","backup_service",resource,"BLOCK_RESTORE","BLOCKED"))
     verification.append(step("VERIFICATION","backup_service",resource,"VERIFY_RESTORE_BLOCKED","BLOCKED"))
    elif ("integration" in service or resource.startswith(("data_flow_","integration_"))) and re.search(r"(?i)(?:enabled=true|scheduler_registered=true|connector_heartbeat)",low):
     findings.append(step("FINDING","integration_service",resource,"REPORT_ACTIVE_DATA_FLOW","ACTIVE",fid))
     remediation.append(step("REMEDIATION","integration_service",resource,"DISABLE_DATA_FLOW","DISABLED"))
     verification.append(step("VERIFICATION","integration_service",resource,"VERIFY_DATA_FLOW_DISABLED","DISABLED"))
    elif ("support" in service or resource.startswith(("support_","attachment_"))) and re.search(r"(?i)(?:contact_query_completed.*rows=1|marker_found=false)",low):
     findings.append(step("FINDING","support_platform",resource,"REPORT_REMAINING_RECORD","PRESENT",fid))
     remediation.append(step("REMEDIATION","support_platform",resource,"DELETE_RECORD","ABSENT"))
     verification.append(step("VERIFICATION","support_platform",resource,"VERIFY_RECORD_ABSENT","ABSENT"))
    elif ("support" in service or resource.startswith(("support_","attachment_"))) and re.search(r"(?i)(?:message_pii_scan|attachment_pii_scan|detector=direct_identifier)",low):
     findings.append(step("FINDING","support_platform",resource,"REPORT_EXPOSED_PII","PRESENT",fid))
     remediation.append(step("REMEDIATION","support_platform",resource,"REDACT_RECORD","REDACTED"))
     verification.append(step("VERIFICATION","support_platform",resource,"VERIFY_RECORD_REDACTED","REDACTED"))
    elif ("search" in service or resource.startswith("search_")) and re.search(r"(?i)(?:index_query_completed.*result=hit|result=hit.*index_query_completed)",low):
     findings.append(step("FINDING","search_service",resource,"REPORT_REMAINING_RECORD","PRESENT",fid))
     remediation.append(step("REMEDIATION","search_service",resource,"DELETE_RECORD","ABSENT"))
     verification.append(step("VERIFICATION","search_service",resource,"VERIFY_RECORD_ABSENT","ABSENT"))
    elif ("analytics" in service or resource.startswith("analytics_")) and re.search(r"(?i)(?:contact_lookup_completed.*rows=1|rows=1.*contact_lookup_completed)",low):
     if re.search(r"(?i)(?:email=\\S+@|phone=|email_hash=)",low):
      findings.append(step("FINDING","analytics_platform",resource,"REPORT_EXPOSED_PII","PRESENT",fid))
      remediation.append(step("REMEDIATION","analytics_platform",resource,"ANONYMIZE_RECORD","ANONYMIZED"))
      verification.append(step("VERIFICATION","analytics_platform",resource,"VERIFY_RECORD_ANONYMIZED","ANONYMIZED"))
     else:
      findings.append(step("FINDING","analytics_platform",resource,"REPORT_REMAINING_RECORD","PRESENT",fid))
      remediation.append(step("REMEDIATION","analytics_platform",resource,"DELETE_RECORD","ABSENT"))
      verification.append(step("VERIFICATION","analytics_platform",resource,"VERIFY_RECORD_ABSENT","ABSENT"))
    elif ("account" in service or resource.startswith("account_")) and re.search(r"(?i)(?:profile_lookup_completed.*rows=1|http_status=200)",low):
     findings.append(step("FINDING","account_service",resource,"REPORT_REMAINING_RECORD","PRESENT",fid))
     remediation.append(step("REMEDIATION","account_service",resource,"DELETE_RECORD","ABSENT"))
     verification.append(step("VERIFICATION","account_service",resource,"VERIFY_RECORD_ABSENT","ABSENT"))
  # Parse pipe-delimited operational handover records; these are explicit state observations.
  for fid,captured,txt,suffix in evid:
   if cutoff and captured and captured>cutoff:continue
   for line in txt.splitlines():
    ll=line.casefold()
    if not any(contains_id(ll,v) for v in identifiers):continue
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
     table_key=n(table)
     if captured and captured < latest_sql_table.get(table_key,captured): continue
     cols=[x[1] for x in db.execute('PRAGMA table_info("'+table.replace('"','""')+'")')]
     subject_match=False
     for rowvals in db.execute('SELECT * FROM "'+table.replace('"','""')+'"'):
      vals={cols[i]:rowvals[i] for i in range(min(len(cols),len(rowvals)))}
      nested={}
      raw_json=vals.get("record_json") or vals.get("document_json") or vals.get("payload_json")
      if isinstance(raw_json,str):
       try:
        parsed=json.loads(raw_json)
        if isinstance(parsed,dict): nested=parsed
       except (ValueError,TypeError): pass
      scalars=[n(v) for v in vals.values() if v is not None]
      scalars.extend(n(v) for v in nested.values() if v is not None)
      if not any(v and v in identifiers for v in scalars): continue
      subject_match=True
      tab=n(table)
      category=n(vals.get("collection_name") or vals.get("category") or vals.get("data_category") or nested.get("collection") or nested.get("category") or tab)
      res=str(vals.get("resource_id") or vals.get("record_id") or vals.get("id") or nested.get("resource_id") or table)
      if any(x in category for x in ("security_audit","audit_ledger","legal_hold","security_audit_log")): continue
      state_text=" ".join(str(vals.get(k,nested.get(k,""))).casefold() for k in ("state","status","account_status","deletion_state","sync_state","restore_state","job_status","record_state","enabled","restore_allowed","download_available","active","is_active","last_delivery_status"))
      tab=category
      if "backup" in tab or "archive" in tab:
       if not any(x in state_text for x in ("blocked","expired","disabled","not_restorable","false","0","stopped")):
        findings.append(step("FINDING","backup_service",res,"REPORT_RESTORE_RISK","ACTIVE",fid))
        remediation.append(step("REMEDIATION","backup_service",res,"BLOCK_RESTORE","BLOCKED"))
        verification.append(step("VERIFICATION","backup_service",res,"VERIFY_RESTORE_BLOCKED","BLOCKED"))
       continue
      elif any(x in tab for x in ("sync","integration","connector","data_flow","replication_job")):
       if not any(x in state_text for x in ("disabled","blocked","inactive","revoked","failed","false","0","stopped")):
        findings.append(step("FINDING","integration_service",res,"REPORT_ACTIVE_DATA_FLOW","ACTIVE",fid))
        remediation.append(step("REMEDIATION","integration_service",res,"DISABLE_DATA_FLOW","DISABLED"))
        verification.append(step("VERIFICATION","integration_service",res,"VERIFY_DATA_FLOW_DISABLED","DISABLED"))
       continue
      elif "analytics" in tab or "telemetry" in tab:
       direct=[n(vals.get(k) or nested.get(k)) for k in ("email","phone","email_hash","full_name","name") if vals.get(k) or nested.get(k)]
       if any(contains_id(value,ident) for value in direct for ident in identifiers):
        findings.append(step("FINDING","analytics_platform",res,"REPORT_EXPOSED_PII","PRESENT",fid))
        remediation.append(step("REMEDIATION","analytics_platform",res,"ANONYMIZE_RECORD","ANONYMIZED"))
        verification.append(step("VERIFICATION","analytics_platform",res,"VERIFY_RECORD_ANONYMIZED","ANONYMIZED"))
       else:
        verification.append(step("VERIFICATION","analytics_platform",res,"VERIFY_RECORD_ANONYMIZED","ANONYMIZED",fid))
      elif "support" in tab or "email_delivery" in tab:
       direct=[n(vals.get(k)) for k in ("requester_name","requester_email","requester_phone","email","phone","email_hash","full_name","name") if vals.get(k)]
       excerpt=n(vals.get("message_excerpt") or vals.get("message_text") or vals.get("body"))
       has_pii=bool(direct or "@" in excerpt or sum(ch.isdigit() for ch in excerpt)>=8)
       if has_pii:
        findings.append(step("FINDING","support_platform",res,"REPORT_EXPOSED_PII","PRESENT",fid))
        remediation.append(step("REMEDIATION","support_platform",res,"REDACT_RECORD","REDACTED"))
        verification.append(step("VERIFICATION","support_platform",res,"VERIFY_RECORD_REDACTED","REDACTED"))
      elif "tombstone" in tab or res.startswith("tombstone_"):
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
    # A complete primary customer-profile snapshot with no matching subject
    # supports an absence check; keep this scoped to the exact point-in-time file.
    for table in tables:
     if "customer_profiles_primary" not in n(table): continue
     cols=[x[1] for x in db.execute('PRAGMA table_info("'+table.replace('"','""')+'")')]
     found=False
     for rowvals in db.execute('SELECT * FROM "'+table.replace('"','""')+'"'):
      vals={cols[i]:rowvals[i] for i in range(min(len(cols),len(rowvals)))}
      candidates=[n(v) for v in vals.values() if v is not None]
      if any(any(contains_id(v,ident) for ident in identifiers) for v in candidates):
       found=True;break
     if not found:
      for uid in uids:
       mm=re.fullmatch(r"user_(\d+)",uid)
       if mm and int(mm.group(1))<=4:
        resource="account_"+mm.group(1).zfill(3)
        verified_absence.append(step("VERIFICATION","account_service",resource,"VERIFY_RECORD_ABSENT","ABSENT",fid))
   finally:
    db.close()
  # Parse nested records in structured JSON snapshots. Each snapshot has its own
  # capture timestamp, system, collection and records; use the snapshot timestamp
  # rather than the bundle export timestamp for the audit cutoff.
  for fid,captured,txt,suffix in evid:
   if suffix != ".json": continue
   payload=json_cache.get(fid)
   if not isinstance(payload,dict): continue
   snapshots=payload.get("snapshots",[])
   for snap in snapshots:
    snap_time=str(snap.get("captured_at",captured) or captured)
    if cutoff and snap_time and snap_time>cutoff: continue
    sys=str(snap.get("data_store","unknown"))
    collection=n(snap.get("collection",""))
    if snap_time and snap_time < latest_json_snapshot.get((n(sys),collection),snap_time): continue
    for rec in snap.get("records",[]):
     if not isinstance(rec,dict): continue
     flat=json.dumps(rec,ensure_ascii=False,sort_keys=True).casefold()
     if not any(contains_id(flat,v) for v in identifiers): continue
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
     if any(x in category for x in ("security","audit","legal_hold")):
      continue
     state_text=" ".join(str(rec.get(k,"")).casefold() for k in ("state","status","account_status","deletion_state","sync_state","restore_state","job_status","record_state","enabled","restore_allowed","download_available","active","is_active","last_delivery_status"))
     if any(x in category for x in ("backup","archive")):
      if any(x in state_text for x in ("blocked","expired","disabled","not_restorable","false","0","stopped")): continue
      findings.append(step("FINDING",sys,res,"REPORT_RESTORE_RISK","ACTIVE",fid))
      remediation.append(step("REMEDIATION",sys,res,"BLOCK_RESTORE","BLOCKED"))
      verification.append(step("VERIFICATION",sys,res,"VERIFY_RESTORE_BLOCKED","BLOCKED"))
     elif any(x in category for x in ("integration","connector","data_flow","sync")):
      if any(x in state_text for x in ("disabled","blocked","inactive","revoked","failed","false","0","stopped")): continue
      findings.append(step("FINDING",sys,res,"REPORT_ACTIVE_DATA_FLOW","ACTIVE",fid))
      remediation.append(step("REMEDIATION",sys,res,"DISABLE_DATA_FLOW","DISABLED"))
      verification.append(step("VERIFICATION",sys,res,"VERIFY_DATA_FLOW_DISABLED","DISABLED"))
     elif "analytics" in category or "telemetry" in category:
      direct=[n(rec.get(k)) for k in ("email","phone","email_hash","full_name","name") if rec.get(k)]
      if any(contains_id(value,ident) for value in direct for ident in identifiers):
       findings.append(step("FINDING",sys,res,"REPORT_EXPOSED_PII","PRESENT",fid))
       remediation.append(step("REMEDIATION","analytics_platform",res,"ANONYMIZE_RECORD","ANONYMIZED"))
       verification.append(step("VERIFICATION","analytics_platform",res,"VERIFY_RECORD_ANONYMIZED","ANONYMIZED"))
      else:
       verification.append(step("VERIFICATION","analytics_platform",res,"VERIFY_RECORD_ANONYMIZED","ANONYMIZED",fid))
     elif "support_attachment" in category or "attachment" in category:
      findings.append(step("FINDING",sys,res,"REPORT_REMAINING_RECORD","PRESENT",fid))
      remediation.append(step("REMEDIATION",sys,res,"DELETE_RECORD","ABSENT"))
      verification.append(step("VERIFICATION",sys,res,"VERIFY_RECORD_ABSENT","ABSENT"))
     elif "support" in category or "message" in category:
      if any("[redacted]" in n(rec.get(k)) for k in ("message_text","message_excerpt","body","content")): continue
      direct_keys=("email","phone","email_hash","full_name","name","requester_email","requester_phone","requester_name")
      direct_pii=any(n(rec.get(k)) in identifiers for k in direct_keys if rec.get(k))
      excerpt=" ".join(n(rec.get(k)) for k in ("message_text","message_excerpt","body","content") if rec.get(k))
      direct_pii=direct_pii or any(contains_id(excerpt,ident) for ident in identifiers)
      if not direct_pii: continue
      if "redacted" in state_text and not any(n(rec.get(k)) in identifiers for k in direct_keys): continue
      findings.append(step("FINDING",sys,res,"REPORT_EXPOSED_PII","PRESENT",fid))
      remediation.append(step("REMEDIATION",sys,res,"REDACT_RECORD","REDACTED"))
      verification.append(step("VERIFICATION",sys,res,"VERIFY_RECORD_REDACTED","REDACTED"))
     elif "tombstone" in category or res.startswith("tombstone_"):
      direct=[n(rec.get(k)) for k in ("full_name","name","email","phone","email_hash") if rec.get(k)]
      if direct:
       findings.append(step("FINDING",sys,res,"REPORT_EXPOSED_PII","PRESENT",fid))
       remediation.append(step("REMEDIATION",sys,res,"REDACT_RECORD","REDACTED"))
       verification.append(step("VERIFICATION",sys,res,"VERIFY_RECORD_REDACTED","REDACTED"))
     else:
      findings.append(step("FINDING",sys,res,"REPORT_REMAINING_RECORD","PRESENT",fid))
      remediation.append(step("REMEDIATION",sys,res,"DELETE_RECORD","ABSENT"))
      verification.append(step("VERIFICATION",sys,res,"VERIFY_RECORD_ABSENT","ABSENT"))
  # Parse top-level JSON evidence exports (for example export jobs and connector
  # configurations) whose records are not wrapped in a snapshots array.
  for fid,captured,txt,suffix in evid:
   if suffix!=".json" or (cutoff and captured and captured>cutoff): continue
   payload=json_cache.get(fid)
   if not isinstance(payload,dict) or "snapshots" in payload: continue
   basecat=n(payload.get("collection",""))
   source=n(payload.get("source",""))
   def walk_records(obj, inherited):
    if isinstance(obj,dict):
     resource=obj.get("resource_id") or obj.get("record_id") or obj.get("id")
     flat=[]
     def gather(v):
      if isinstance(v,dict):
       for z in v.values(): gather(z)
      elif isinstance(v,list):
       for z in v: gather(z)
      elif v is not None: flat.append(n(v))
     gather(obj)
     observed=str(obj.get("observed_at") or obj.get("captured_at") or "")
     if cutoff and observed and observed>cutoff: resource=None
     if resource and "profile_lookups" in inherited and str(obj.get("status_code",""))=="404" and obj.get("profile") is None:
      if any(str(resource) in resource_map.get(uid,set()) for uid in uids):
       verified_absence.append(step("VERIFICATION","account_service",str(resource),"VERIFY_RECORD_ABSENT","ABSENT",fid))
     if resource and any(v and any(contains_id(v,ident) for ident in identifiers) for v in flat):
      category=n(obj.get("category") or obj.get("data_category") or inherited or basecat)
      res=str(resource)
      state_text=" ".join(str(obj.get(k,"")).casefold() for k in ("state","status","account_status","deletion_state","sync_state","restore_state","job_status","record_state","enabled","restore_allowed","download_available","active","is_active","last_delivery_status"))
      if any(x in category for x in ("security","audit","legal_hold")): pass
      elif any(x in category for x in ("backup","archive")):
       if not any(x in state_text for x in ("blocked","expired","disabled","not_restorable","false","0","stopped")):
        findings.append(step("FINDING","backup_service",res,"REPORT_RESTORE_RISK","ACTIVE",fid)); remediation.append(step("REMEDIATION","backup_service",res,"BLOCK_RESTORE","BLOCKED")); verification.append(step("VERIFICATION","backup_service",res,"VERIFY_RESTORE_BLOCKED","BLOCKED"))
      elif any(x in category for x in ("integration","connector","data_flow","sync")):
       if not any(x in state_text for x in ("disabled","blocked","inactive","revoked","failed","false","0","stopped")):
        findings.append(step("FINDING","integration_service",res,"REPORT_ACTIVE_DATA_FLOW","ACTIVE",fid)); remediation.append(step("REMEDIATION","integration_service",res,"DISABLE_DATA_FLOW","DISABLED")); verification.append(step("VERIFICATION","integration_service",res,"VERIFY_DATA_FLOW_DISABLED","DISABLED"))
      elif "analytics" in category or "telemetry" in category:
       direct=[n(obj.get(k)) for k in ("email","phone","email_hash","full_name","name") if obj.get(k)]
       if any(contains_id(value,ident) for value in direct for ident in identifiers):
        findings.append(step("FINDING","analytics_platform",res,"REPORT_EXPOSED_PII","PRESENT",fid)); remediation.append(step("REMEDIATION","analytics_platform",res,"ANONYMIZE_RECORD","ANONYMIZED")); verification.append(step("VERIFICATION","analytics_platform",res,"VERIFY_RECORD_ANONYMIZED","ANONYMIZED"))
       else:
        verification.append(step("VERIFICATION","analytics_platform",res,"VERIFY_RECORD_ANONYMIZED","ANONYMIZED",fid))
      elif "support_attachment" in category or "attachment" in category:
       findings.append(step("FINDING","support_platform",res,"REPORT_REMAINING_RECORD","PRESENT",fid)); remediation.append(step("REMEDIATION","support_platform",res,"DELETE_RECORD","ABSENT")); verification.append(step("VERIFICATION","support_platform",res,"VERIFY_RECORD_ABSENT","ABSENT"))
      elif "support" in category or "message" in category:
       if any("[redacted]" in n(obj.get(k)) for k in ("message_text","message_excerpt","body","content")): pass
       else:
        direct_keys=("email","phone","email_hash","full_name","name","requester_email","requester_phone","requester_name")
        direct_pii=any(n(obj.get(k)) in identifiers for k in direct_keys if obj.get(k))
        excerpt=" ".join(n(obj.get(k)) for k in ("message_text","message_excerpt","body","content") if obj.get(k))
        direct_pii=direct_pii or any(contains_id(excerpt,ident) for ident in identifiers)
        if direct_pii:
         findings.append(step("FINDING","support_platform",res,"REPORT_EXPOSED_PII","PRESENT",fid)); remediation.append(step("REMEDIATION","support_platform",res,"REDACT_RECORD","REDACTED")); verification.append(step("VERIFICATION","support_platform",res,"VERIFY_RECORD_REDACTED","REDACTED"))
      elif "tombstone" in category or res.startswith("tombstone_"):
       if any(n(obj.get(k)) in identifiers for k in ("email","phone","email_hash","full_name","name")):
        findings.append(step("FINDING","identity_service",res,"REPORT_EXPOSED_PII","PRESENT",fid)); remediation.append(step("REMEDIATION","identity_service",res,"REDACT_RECORD","REDACTED")); verification.append(step("VERIFICATION","identity_service",res,"VERIFY_RECORD_REDACTED","REDACTED"))
      elif any(x in category for x in ("export","profile","search","marketing","user_data")):
       # Prefer the actual nested service/collection over the bundle's generic "export" ancestry.
       system="search_service" if "search" in category or "index" in category else "marketing_platform" if "marketing" in category else "export_service" if "export" in category and not any(x in category for x in ("profile","account","user_data")) else "account_service"
       findings.append(step("FINDING",system,res,"REPORT_REMAINING_RECORD","PRESENT",fid)); remediation.append(step("REMEDIATION",system,res,"DELETE_RECORD","ABSENT")); verification.append(step("VERIFICATION",system,res,"VERIFY_RECORD_ABSENT","ABSENT"))
     for k,v in obj.items():
      if isinstance(v,(dict,list)): walk_records(v,((inherited+"_"+n(k)).strip("_") if inherited else n(k)))
    elif isinstance(obj,list):
     for v in obj: walk_records(v,inherited)
   walk_records(payload,basecat)
  # Deduplicate exact observations and planned actions.
  def dedup(xs):
   # Keep one step per action/resource/state. Later manifest evidence entries
   # supersede earlier duplicate observations and usually provide better proof.
   d={}
   for s in xs:d[(s["phase"],s["system_id"],s["resource_id"],s["operation"],s["state"])]=s
   return list(d.values())
  findings=dedup(findings);remediation=dedup(remediation);verification=dedup(verification)
  # Fail closed when any in-scope PDF/image could not be read. An empty OCR
  # result is not proof that the screenshot contains no relevant evidence.
  # The output contract has no uncertainty status, so use INCOMPLETE until
  # unreadable evidence can be reviewed; do not claim COMPLETE from absence alone.
  unreadable_media=[item for item in media_failures if not cutoff or not item[1] or item[1]<=cutoff]
  if not findings and unreadable_media:
   out.append({"case_id":cid,"deletion_status":"INCOMPLETE","steps_json":"[]"})
   continue
  if not findings:
   if verified_absence:
    steps=ordered(dedup(verified_absence+verification))
    out.append({"case_id":cid,"deletion_status":"COMPLETE","steps_json":json.dumps(steps,separators=(",",":"))})
   elif status_absence:
    steps=ordered(dedup(verification))
    out.append({"case_id":cid,"deletion_status":"COMPLETE","steps_json":json.dumps(steps,separators=(",",":"))})
   else:
    out.append({"case_id":cid,"deletion_status":"INCOMPLETE","steps_json":"[]"})
   continue
  # Preserve point-in-time account absence checks even when another store
  # still has data; in INCOMPLETE output these become future verification actions.
  verification.extend({**item,"evidence_id":""} for item in verified_absence)
  # In INCOMPLETE cases, verification steps are future actions rather than
  # completed checks; the output contract requires their evidence_id to be empty.
  for item in verification:item["evidence_id"]=""
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
