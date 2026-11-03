#!/usr/bin/env python3
"""Evidence-first baseline for the Ghost Data Still Exists deletion audit.

This runner resolves current/historical aliases, scans machine-readable evidence,
applies the supplied deletion policy conservatively, and emits the required CSV.
PDF/image evidence needs OCR/vision review and is intentionally not guessed.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

ROOT = Path(__file__).resolve().parents[1]
DATA, EVIDENCE, OUTPUT = ROOT / "dataset", ROOT / "dataset/evidence", ROOT / "output.csv"
PHASE = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OP = {"REPORT_REMAINING_RECORD":0,"REPORT_EXPOSED_PII":1,"REPORT_ACTIVE_DATA_FLOW":2,
      "REPORT_RESTORE_RISK":3,"DISABLE_DATA_FLOW":4,"BLOCK_RESTORE":5,"DELETE_RECORD":6,
      "REDACT_RECORD":7,"ANONYMIZE_RECORD":8,"VERIFY_RECORD_ABSENT":9,
      "VERIFY_RECORD_PRESENT":10,"VERIFY_RECORD_REDACTED":11,
      "VERIFY_RECORD_ANONYMIZED":12,"VERIFY_DATA_FLOW_DISABLED":13,"VERIFY_RESTORE_BLOCKED":14}

@dataclass
class Evidence:
    file_id: str
    path: str
    system: str
    resource: str
    captured: str
    payload: Any
    category: str
    search_values: set[str]

@dataclass
class Step:
    phase: str
    system: str
    resource: str
    operation: str
    state: str
    evidence_id: str = ""
    def json(self, n: int) -> dict[str, Any]:
        return {"step_no":n,"phase":self.phase,"system_id":self.system,
                "resource_id":self.resource,"operation":self.operation,
                "state":self.state,"evidence_id":self.evidence_id}

def csv_rows(path: Path) -> list[dict[str,str]]:
    if not path.exists(): return []
    with path.open(encoding="utf-8-sig", newline="") as f: return list(csv.DictReader(f))

def norm(x: Any) -> str: return re.sub(r"\s+"," ",str(x or "")).strip().casefold()
def when(x: Any) -> datetime | None:
    try:
        dt=datetime.fromisoformat(str(x).replace("Z","+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError,TypeError): return None
def sha_email(email: str) -> str: return hashlib.sha256(norm(email).encode()).hexdigest()

def identity_index():
    by_user: dict[str,set[str]]={}
    for row in csv_rows(DATA/"user_identities.csv"):
        uid=row.get("user_id","")
        vals={norm(row.get(k)) for k in ("name","email","phone","email_hash")}
        vals.add(norm(uid)) # stable internal user reference appears in retained evidence
        by_user.setdefault(uid,set()).update(v for v in vals if v)
    for row in csv_rows(DATA/"user_audit_log.csv"):
        uid=row.get("user_id","")
        if norm(row.get("field_name")) in {"email","phone","name","email_hash"}:
            by_user.setdefault(uid,set()).update(norm(row.get(k)) for k in ("old_value","new_value") if norm(row.get(k)))
    reverse={}
    for uid,vals in by_user.items():
        for val in vals: reverse.setdefault(val,set()).add(uid)
    return by_user,reverse

def infer_system(path: str, obj: Any) -> str:
    rid=norm(obj.get("resource_id") or obj.get("record_id") or "") if isinstance(obj,dict) else ""
    # Resource namespace is a stronger system signal than an incidental log service field.
    for prefix,logical in (("account_","account_service"),("analytics_","analytics_platform"),
        ("search_","search_service"),("support_","support_platform"),("export_","export_service"),
        ("data_flow_","integration_service"),("backup_","backup_service"),("cache_","cache_service"),
        ("audit_record_","security_service"),("tombstone_","identity_service")):
        if rid.startswith(prefix): return logical
    explicit=norm(obj.get("system") or obj.get("data_store") or obj.get("system_id") or obj.get("source_system")) if isinstance(obj,dict) else ""
    if explicit:
        return {"support_replica":"support_platform","customer_data_read_replica":"database_replica",
                "customer_data_reporting_replica":"database_replica"}.get(explicit,explicit)
    s=norm(path+" "+json.dumps(obj,ensure_ascii=False,default=str)[:900])
    for token,system in (("account","account_service"),("profile","profile_service"),
        ("search","search_service"),("analytics","analytics_platform"),("support","support_platform"),
        ("export","export_service"),("marketing","marketing_service"),("email_delivery","email_delivery_service"),
        ("security","security_service"),("backup","backup_service"),("archive","archive_service"),
        ("replica","database_replica"),("telemetry","telemetry_service"),("cache","cache_service")):
        if token in s: return system
    return "evidence_store"

def infer_category(path: str, system: str, obj: Any) -> str:
    explicit=norm(obj.get("record_type") or obj.get("data_category") or obj.get("category")) if isinstance(obj,dict) else ""
    category_map={"user_profile":"USER_PROFILE","secondary_identifier":"SECONDARY_IDENTIFIER",
      "search_index_entry":"SEARCH_INDEX_ENTRY","cache_entry":"CACHE_ENTRY",
      "support_message":"SUPPORT_MESSAGE","support_attachment":"SUPPORT_ATTACHMENT",
      "analytics_profile":"ANALYTICS_PROFILE","product_telemetry":"PRODUCT_TELEMETRY",
      "user_export":"USER_EXPORT","marketing_profile":"MARKETING_PROFILE",
      "email_delivery_log":"EMAIL_DELIVERY_LOG","security_audit_log":"SECURITY_AUDIT_LOG",
      "legal_hold_record":"LEGAL_HOLD_RECORD","backup_archive":"BACKUP_ARCHIVE",
      "account_tombstone":"ACCOUNT_TOMBSTONE"}
    if explicit in category_map: return category_map[explicit]
    if isinstance(obj,dict):
        rid=norm(obj.get("resource_id"))
        status=norm(obj.get("status_code") or obj.get("http_status") or obj.get("result") or obj.get("rows"))
        if status in {"404","0","not_found","absent","no_hit"} or "rows=0" in norm(obj.get("line")): return "ABSENT_RECORD"
        if rid.startswith("data_flow_") or "connector_name" in obj: return "ACTIVE_DATA_FLOW"
        if rid.startswith("backup_") or "restore_allowed" in obj: return "BACKUP_ARCHIVE"
        if rid.startswith("tombstone_"): return "ACCOUNT_TOMBSTONE"
        if system=="analytics_platform" and ("correlation_key" in obj or "contact_lookup" in norm(obj.get("event"))):
            return "ANALYTICS_CONTACT_LOOKUP"
        if "contact_query" in norm(obj.get("line")) or "deletion_marker_check" in norm(obj.get("line")):
            return "SUPPORT_CONTACT_INDEX"
        if rid.startswith("audit_record_") or "retention_until" in obj: return "SECURITY_AUDIT_LOG"
        if system=="analytics_platform" or rid.startswith("analytics_"): return "ANALYTICS_PROFILE"
        if system=="search_service" or rid.startswith("search_"): return "SEARCH_INDEX_ENTRY"
        if system=="account_service" or rid.startswith("account_"): return "USER_PROFILE"
        if system=="support_platform" and "attachment" in norm(path): return "SUPPORT_ATTACHMENT"
        if system=="support_platform" or rid.startswith("support_"): return "SUPPORT_MESSAGE"
        if system=="export_service" or rid.startswith("export_"): return "USER_EXPORT"
        if system=="cache_service" or rid.startswith("cache_"): return "CACHE_ENTRY"
    s=norm(path+" "+system+" "+json.dumps(obj,ensure_ascii=False,default=str)[:1000])
    for category,terms in (
        ("SEARCH_INDEX_ENTRY",("search","index")),("USER_EXPORT",("export",)),
        ("SUPPORT_ATTACHMENT",("support","attachment")),("SUPPORT_MESSAGE",("support","message")),
        ("ANALYTICS_PROFILE",("analytics",)),("PRODUCT_TELEMETRY",("telemetry",)),
        ("MARKETING_PROFILE",("marketing",)),("EMAIL_DELIVERY_LOG",("email_delivery",)),
        ("SECURITY_AUDIT_LOG",("security","audit")),("BACKUP_ARCHIVE",("backup",)),
        ("ACCOUNT_TOMBSTONE",("tombstone",)),("USER_PROFILE",("account","profile"))):
        if all(t in s for t in terms): return category
    return "UNKNOWN"

def walk(x: Any, inherited: Mapping[str,Any]|None=None):
    """Walk nested evidence without leaking sibling records into each record."""
    inherited=dict(inherited or {})
    meta_keys={"captured_at","observed_at","event_time","recorded_at","data_store",
               "system","system_id","source_system","collection","record_type"}
    if isinstance(x,dict):
        meta={k:v for k,v in x.items() if k in meta_keys and not isinstance(v,(dict,list))}
        context={**inherited,**meta}
        merged={**context,**x}
        yield merged
        for key,child in x.items():
            if not isinstance(child,(dict,list)): continue
            child_context=dict(context)
            service_keys={"account_service","analytics_platform","backup_service","export_service",
                          "integration_service","search_service","security_service","support_platform",
                          "cache_service","marketing_service","email_delivery_service"}
            if key in service_keys: child_context["system"]=key
            yield from walk(child,child_context)
    elif isinstance(x,list):
        for child in x:
            yield from walk(child,inherited)

def evidence_values(value: Any) -> set[str]:
    """Extract exact scalar identifiers; never use substring identity matching."""
    found=set()
    if isinstance(value,dict):
        for item in value.values(): found.update(evidence_values(item))
    elif isinstance(value,(list,tuple,set)):
        for item in value: found.update(evidence_values(item))
    elif value is not None:
        raw=str(value).strip()
        if raw: found.add(norm(raw))
        # Log lines embed identifiers inside key=value text. Extract only complete values.
        for pattern in (r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
                        r"\buser_\d+\b",r"\b[a-fA-F0-9]{64}\b"):
            for match in re.findall(pattern,raw,re.I): found.add(norm(match))
        kv=r"(?:lookup_key|customer_reference|subject_reference|user_id|email|customer_email|owner_email|requester_email|email_hash|phone|full_name|requester_name)\s*[=:]\s*['\"]?([^,\s'\"]+)"
        for match in re.findall(kv,raw,re.I): found.add(norm(match))
    return found

def match_value(match):
    if not match: return ""
    return match.group(1) if match.lastindex else match.group(0)

def evidence_records():
    records=[]
    for m in csv_rows(DATA/"evidence_files.csv"):
        rel=m.get("file_path","")
        if not rel: continue
        p=EVIDENCE/rel.removeprefix("evidence/")
        suffix=p.suffix.casefold()
        try:
            if suffix==".json":
                root=json.loads(p.read_text(encoding="utf-8",errors="replace"))
                objects=walk(root)
            elif suffix==".csv":
                objects=csv_rows(p)
            elif suffix==".pdf":
                text_content=""
                try:
                    from pypdf import PdfReader
                    text_content="\\n".join(page.extract_text() or "" for page in PdfReader(str(p)).pages)
                except (ImportError, OSError, ValueError):
                    pass
                if not text_content:
                    try:
                        import fitz
                        from PIL import Image
                        import pytesseract
                        pages=[]
                        with fitz.open(str(p)) as document:
                            for page in document:
                                pix=page.get_pixmap(dpi=220,alpha=False)
                                image=Image.frombytes("RGB",(pix.width,pix.height),pix.samples)
                                pages.append(pytesseract.image_to_string(image))
                        text_content="\\n".join(pages)
                    except (ImportError, OSError, RuntimeError):
                        pass
                    rid_match=re.search(r"\b(?:resource_id|resource|record_id)\s*[=:]\s*([A-Za-z0-9_.-]+)",line,re.I)
                if not rid_match:
                        rid_match=re.search(r"\b(?:account|search|support|analytics|export|data_flow|backup|audit_record|tombstone)_\d+\b",line,re.I)
                objects=[{"resource_id":match_value(rid_match) if rid_match else p.stem,"line":text_content,"system":infer_system(rel,text_content)}] if text_content else []
            elif suffix in {".png",".jpg",".jpeg",".tif",".tiff",".webp"}:
                text_content=""
                try:
                    from PIL import Image
                    import pytesseract
                    text_content=pytesseract.image_to_string(Image.open(p))
                except (ImportError, OSError, RuntimeError):
                    pass
                    rid_match=re.search(r"\b(?:resource_id|resource|record_id)\s*[=:]\s*([A-Za-z0-9_.-]+)",line,re.I)
                if not rid_match:
                        rid_match=re.search(r"\b(?:account|search|support|analytics|export|data_flow|backup|audit_record|tombstone)_\d+\b",line,re.I)
                objects=[{"resource_id":match_value(rid_match) if rid_match else p.stem,"line":text_content,"system":infer_system(rel,text_content)}] if text_content else []
            elif suffix in {".txt",".log",".sql"}:
                parsed=[]
                sql_columns={
                  "customer_profiles":["resource_id","customer_reference","full_name","email","phone","email_hash","account_status","updated_at"],
                  "customer_search_documents":["resource_id","customer_reference","display_name","email","phone","email_hash","index_name","updated_at"],
                  "customer_analytics_profiles":["resource_id","customer_reference","email","phone","email_hash","audience_cohort","updated_at"],
                  "support_records":["resource_id","customer_reference","requester_name","requester_email","requester_phone","message_excerpt","updated_at"],
                  "customer_exports":["resource_id","customer_reference","owner_email","owner_phone","object_key","updated_at"],
                  "connector_subscriptions":["resource_id","customer_reference","customer_email","connector_name","enabled","last_delivery_status","updated_at"],
                  "backup_restore_entries":["resource_id","customer_reference","customer_email","archive_key","restore_allowed","updated_at"],
                  "security_audit_records":["resource_id","subject_reference","event_code","retention_until","updated_at"]}
                for i,line in enumerate(p.read_text(encoding="utf-8",errors="replace").splitlines(),1):
                    if not line.strip(): continue
                    item={"line":line,"line_number":i}
                    for key,value in re.findall(r"([A-Za-z_][A-Za-z0-9_]*)=([^\s]+)",line):
                        item[key]=value.strip("'\\\"")
                    rid_match=re.search(r"\b(?:resource_id|resource|record_id)\s*[=:]\s*([A-Za-z0-9_.-]+)",line,re.I)
                    if not rid_match:
                        rid_match=re.search(r"\b(?:account|search|support|analytics|export|data_flow|backup|audit_record|tombstone)_\d+\b",line,re.I)
                    if rid_match: item["resource_id"]=match_value(rid_match)
                    svc=re.search(r"\bservice=([A-Za-z0-9_.-]+)",line,re.I)
                    if svc: item["system"]=svc.group(1)
                    if suffix==".sql":
                        insert=re.search(r"INSERT\s+INTO\s+(\w+)\s+VALUES\s*\((.*)\)\s*;?",line,re.I)
                        if insert and insert.group(1) in sql_columns:
                            values=next(csv.reader([insert.group(2)],delimiter=",",quotechar="'",skipinitialspace=True))
                            item.update(dict(zip(sql_columns[insert.group(1)],(v.strip() for v in values))))
                            table_system={"customer_profiles":"account_service","customer_search_documents":"search_service",
                              "customer_analytics_profiles":"analytics_platform","support_records":"support_platform",
                              "customer_exports":"export_service","connector_subscriptions":"integration_service",
                              "backup_restore_entries":"backup_service","security_audit_records":"security_service"}
                            item["system"]=table_system[insert.group(1)]
                    parsed.append(item)
                if suffix!=".sql":
                    trace_context={}
                    for item in parsed:
                        trace=norm(item.get("trace_id"))
                        if not trace: continue
                        context=trace_context.setdefault(trace,{})
                        for key,value in item.items():
                            if key not in {"line","line_number"} and norm(value) not in {"","null","none"}:
                                context[key]=value
                    parsed=[{**trace_context.get(norm(item.get("trace_id")),{}),**item}
                            if norm(item.get("trace_id")) else item for item in parsed]
                objects=[item for item in parsed if item.get("resource_id")]
            else: continue # Do not infer OCR/image/PDF contents.
            for obj in objects:
                resource=obj.get("resource_id") or obj.get("record_id") or obj.get("id")
                if not resource: continue
                system=infer_system(rel,obj)
                if system=="evidence_store":
                    origin=norm(m.get("origin"))
                    origin_map={"support_platform":"support_platform","analytics_platform":"analytics_platform",
                      "identity_service":"identity_service","backup_service":"backup_service",
                      "export_service":"export_service","search_index_service":"search_service",
                      "account_history_service":"account_service","security_service":"security_service",
                      "customer_account_service":"account_service","customer_export_service":"export_service"}
                    system=origin_map.get(origin,infer_system(rel,origin))
                records.append(Evidence(m.get("file_id",""),rel,system,str(resource),
                    str(m.get("captured_at","")),
                    obj,infer_category(rel,system,obj),evidence_values(obj)))
        except (OSError,ValueError,TypeError,csv.Error):
            continue
    return records

def deletion_intent(text: str) -> bool:
    t=norm(text)
    if any(x in t for x in ("do not delete","don't delete","not requesting deletion","keep my account")): return False
    if any(x in t for x in ("profile is gone","cannot identify me","account still existed",
                            "check the latest state","check latest state","deletion audit")): return True
    # Explicit deletion vocabulary from the multilingual request set.
    intents=("delet","deletion","erase","erasure","remove","remov","close","closed","closing",
      "eliminar","eliminación","eliminacion","borrar","suprimir","supresión","suppression","supprimer",
      "effacer","effacement","löschen","loeschen","entfernen","删除","削除","삭제")
    return any(x in t for x in intents)

def matches_alias(payload: Any, aliases: set[str]) -> bool:
    text=norm(json.dumps(payload,ensure_ascii=False,default=str))
    return any(a and a in text for a in aliases)

def relevant(records, aliases, audit_at):
    """Resolve resource identity across all evidence, but evaluate state at audit_at."""
    cutoff=when(audit_at)
    linked={(r.system,r.resource) for r in records if aliases.intersection(r.search_values)}
    candidates=[]
    for r in records:
        ts=when(r.captured)
        if cutoff and ts and ts>cutoff: continue
        if aliases.intersection(r.search_values) or (r.system,r.resource) in linked:
            candidates.append(r)
    # Keep the freshest available point-in-time observation per resource.
    latest={}
    for r in candidates:
        key=(r.system,r.resource)
        current=latest.get(key)
        rt=when(r.captured); ct=when(current.captured) if current else None
        def quality(record):
            payload=record.payload if isinstance(record.payload,dict) else {}
            state_keys=("status_code","http_status","rows","result","enabled","restore_allowed",
                        "last_delivery_status","email","phone","email_hash","customer_reference")
            has_state=sum(1 for name in state_keys if name in payload)
            line_no=int(payload.get("line_number") or 0)
            return (has_state,line_no,len(payload))
        if current is None or (rt and (ct is None or rt>ct)) or (rt==ct and quality(r)>quality(current)):
            latest[key]=r
    return list(latest.values())

def has_direct_pii(payload: Any) -> bool:
    """Whether a retained record still contains direct identifiers requiring treatment."""
    keys={"name","full_name","email","phone","email_hash","requester_name","requester_email",
          "requester_phone","owner_email","owner_phone","customer_email","display_name"}
    def visit(value):
        if isinstance(value,dict):
            for key,item in value.items():
                if norm(key) in keys and item is not None and norm(item) not in {"","null","none"}:
                    return True
                if visit(item): return True
        elif isinstance(value,(list,tuple)):
            return any(visit(item) for item in value)
        elif isinstance(value,str):
            for key in keys:
                if re.search(r"\b"+re.escape(key)+r"\s*[=:]\s*(?!null\b|none\b|['\"]?null)",value,re.I):
                    return True
        return False
    return visit(payload)

def has_stable_user_link(payload: Any) -> bool:
    keys={"user_id","customer_reference","subject_reference"}
    def visit(value):
        if isinstance(value,dict):
            return any(norm(k) in keys and item is not None and norm(item) not in {"","null","none"}
                       or visit(item) for k,item in value.items())
        if isinstance(value,(list,tuple)): return any(visit(item) for item in value)
        if isinstance(value,str):
            return any(re.search(r"\b"+k+r"\s*[=:]\s*(?!null\b|none\b|['\"]?null)",value,re.I)
                       for k in keys)
        return False
    return visit(payload)

def plan(found: list[Evidence]) -> list[Step]:
    out=[]; seen=set()
    for r in found:
        if r.category=="ABSENT_RECORD":
            out.append(Step("VERIFICATION",r.system,r.resource,"VERIFY_RECORD_ABSENT","ABSENT",r.file_id))
            continue
        if r.category=="ACTIVE_DATA_FLOW":
            enabled=norm(r.payload.get("enabled")) in {"true","1","yes"} or norm(r.payload.get("last_delivery_status")) in {"delivered","active","running"}
            if not enabled:
                out.append(Step("VERIFICATION",r.system,r.resource,"VERIFY_DATA_FLOW_DISABLED","DISABLED",r.file_id))
                continue
        if r.category=="BACKUP_ARCHIVE":
            allowed=norm(r.payload.get("restore_allowed")) in {"true","1","yes"}
            if not allowed:
                out.append(Step("VERIFICATION",r.system,r.resource,"VERIFY_RESTORE_BLOCKED","BLOCKED",r.file_id))
                continue
        pii=has_direct_pii(r.payload)
        stable_link=has_stable_user_link(r.payload)
        if r.category in {"USER_PROFILE","SECONDARY_IDENTIFIER","SEARCH_INDEX_ENTRY","CACHE_ENTRY","USER_EXPORT","MARKETING_PROFILE","SUPPORT_ATTACHMENT","SUPPORT_CONTACT_INDEX","ANALYTICS_CONTACT_LOOKUP"}:
            remediation,state,verify="DELETE_RECORD","ABSENT","VERIFY_RECORD_ABSENT"
        elif r.category in {"ANALYTICS_PROFILE","PRODUCT_TELEMETRY"}:
            if not pii and not stable_link:
                out.append(Step("VERIFICATION",r.system,r.resource,"VERIFY_RECORD_ANONYMIZED","ANONYMIZED",r.file_id))
                continue
            remediation,state,verify="ANONYMIZE_RECORD","ANONYMIZED","VERIFY_RECORD_ANONYMIZED"
        elif r.category in {"SUPPORT_MESSAGE","EMAIL_DELIVERY_LOG","ACCOUNT_TOMBSTONE"}:
            if not pii:
                out.append(Step("VERIFICATION",r.system,r.resource,"VERIFY_RECORD_REDACTED","REDACTED",r.file_id))
                continue
            remediation,state,verify="REDACT_RECORD","REDACTED","VERIFY_RECORD_REDACTED"
        elif r.category=="ACTIVE_DATA_FLOW":
            remediation,state,verify="DISABLE_DATA_FLOW","DISABLED","VERIFY_DATA_FLOW_DISABLED"
        elif r.category=="BACKUP_ARCHIVE":
            remediation,state,verify="BLOCK_RESTORE","BLOCKED","VERIFY_RESTORE_BLOCKED"
        elif r.category=="SECURITY_AUDIT_LOG":
            out.append(Step("VERIFICATION",r.system,r.resource,"VERIFY_RECORD_PRESENT","PRESENT",r.file_id))
            continue
        else: continue
        key=(r.system,r.resource,remediation)
        if key in seen: continue
        seen.add(key)
        finding=("REPORT_ACTIVE_DATA_FLOW" if remediation=="DISABLE_DATA_FLOW" else
                 "REPORT_RESTORE_RISK" if remediation=="BLOCK_RESTORE" else
                 "REPORT_EXPOSED_PII" if remediation in {"REDACT_RECORD","ANONYMIZE_RECORD"} else "REPORT_REMAINING_RECORD")
        finding_state="ACTIVE" if remediation in {"DISABLE_DATA_FLOW","BLOCK_RESTORE"} else "PRESENT"
        out.extend((Step("FINDING",r.system,r.resource,finding,finding_state,r.file_id),
                    Step("REMEDIATION",r.system,r.resource,remediation,state),
                    Step("VERIFICATION",r.system,r.resource,verify,state)))
    # A resource may be repeated in logs and snapshots; emit each logical step once.
    unique={}
    for step in out:
        key=(step.phase,step.system,step.resource,step.operation,step.state)
        old=unique.get(key)
        if old is None or (not old.evidence_id and step.evidence_id):
            unique[key]=step
    return list(unique.values())

def sort_steps(steps: Iterable[Step]):
    return sorted(steps,key=lambda s:(PHASE[s.phase],OP.get(s.operation,99),s.system,s.resource))

def solve(case, records, by_user, reverse):
    email=norm(case.get("email",""))
    if not deletion_intent(case.get("request_text","")): return "NOT_APPLICABLE",[]
    aliases={email,sha_email(email)}
    for uid in reverse.get(email,set()): aliases.update(by_user.get(uid,set()))
    found=relevant(records,aliases,case.get("audit_at",""))
    steps=plan(found)
    status="INCOMPLETE" if any(s.phase=="REMEDIATION" for s in steps) else "COMPLETE"
    if status=="COMPLETE":
        steps=[s for s in steps if s.phase=="VERIFICATION"]
        for s in steps:
            s.evidence_id=next((r.file_id for r in found if r.system==s.system and r.resource==s.resource),"")
    ordered=sort_steps(steps)
    return status,[s.json(i) for i,s in enumerate(ordered,1)]

def main():
    parser=argparse.ArgumentParser(description="Run the deletion evidence audit")
    parser.add_argument("--requests",type=Path,default=DATA/"deletion_requests.csv")
    parser.add_argument("--output",type=Path,default=OUTPUT)
    args=parser.parse_args()
    requests=csv_rows(args.requests)
    by_user,reverse=identity_index()
    evidence=evidence_records()
    results=[]
    for case in requests:
        status,steps=solve(case,evidence,by_user,reverse)
        results.append({"case_id":case["case_id"],"deletion_status":status,
                        "steps_json":json.dumps(steps,ensure_ascii=False,separators=(",",":"))})
    results.sort(key=lambda r:r["case_id"])
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open("w",encoding="utf-8",newline="") as f:
        w=csv.DictWriter(f,fieldnames=("case_id","deletion_status","steps_json"));w.writeheader();w.writerows(results)
    print(f"Created {args.output} with {len(results)} case rows.")
if __name__=="__main__": main()
