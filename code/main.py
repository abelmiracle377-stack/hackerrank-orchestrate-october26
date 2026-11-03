#!/usr/bin/env python3
"""Evidence-first baseline for the Ghost Data Still Exists deletion audit.

This runner resolves current/historical aliases, scans machine-readable evidence,
applies the supplied deletion policy conservatively, and emits the required CSV.
PDF/image evidence needs OCR/vision review and is intentionally not guessed.
"""
from __future__ import annotations
import csv, hashlib, json, re
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
    explicit=norm(obj.get("system") or obj.get("data_store") or obj.get("system_id") or obj.get("source_system")) if isinstance(obj,dict) else ""
    if explicit: return explicit
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
        if rid.startswith("data_flow_") or "connector_name" in obj: return "ACTIVE_DATA_FLOW"
        if rid.startswith("backup_") or "restore_allowed" in obj: return "BACKUP_ARCHIVE"
        if rid.startswith("tombstone_"): return "ACCOUNT_TOMBSTONE"
        if rid.startswith("audit_record_") or "retention_until" in obj: return "SECURITY_AUDIT_LOG"
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
    inherited=dict(inherited or {})
    if isinstance(x,dict):
        merged={**inherited,**x}; yield merged
        for v in x.values():
            if isinstance(v,(dict,list)): yield from walk(v,merged)
    elif isinstance(x,list):
        for v in x: yield from walk(v,inherited)

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
            elif suffix in {".txt",".log",".sql"}:
                parsed=[]
                for i,line in enumerate(p.read_text(encoding="utf-8",errors="replace").splitlines(),1):
                    if not line.strip(): continue
                    rid_match=re.search(r"\\bresource_id\\s*[=:]\\s*['\\\"]?([\\w.-]+)",line,re.I)
                    if not rid_match and suffix==".sql":
                        rid_match=re.search(r"VALUES\\s*\\(\\s*['\\\"](\\w+_\\d+)['\\\"]",line,re.I)
                    rid=rid_match.group(1) if rid_match else f"{p.stem}:line_{i}"
                    svc=re.search(r"\\bservice=([\\w.-]+)",line,re.I)
                    system=svc.group(1) if svc else infer_system(rel,line)
                    # SQL table names map to their logical source systems.
                    for table,logical in (("customer_profiles","account_service"),("customer_search_documents","search_service"),
                        ("customer_analytics_profiles","analytics_platform"),("support_records","support_platform"),
                        ("customer_exports","export_service"),("connector_subscriptions","integration_service"),
                        ("backup_restore_entries","backup_service"),("security_audit_records","security_service")):
                        if table in line: system=logical
                    parsed.append({"resource_id":rid,"line":line,"system":system,"line_number":i})
                objects=parsed
            else: continue # Do not infer OCR/image/PDF contents.
            for obj in objects:
                resource=obj.get("resource_id") or obj.get("record_id") or obj.get("id")
                if not resource: continue
                system=infer_system(rel,obj)
                records.append(Evidence(m.get("file_id",""),rel,system,str(resource),
                    str(obj.get("captured_at") or obj.get("event_time") or obj.get("recorded_at") or m.get("captured_at","")),
                    obj,infer_category(rel,system,obj)))
        except (OSError,ValueError,TypeError,csv.Error):
            continue
    return records

def deletion_intent(text: str) -> bool:
    t=norm(text)
    if any(x in t for x in ("do not delete","don't delete","not requesting deletion","keep my account")): return False
    # Explicit deletion vocabulary from the multilingual request set.
    intents=("delete","deletion","erase","erasure","remove my","close my account","close this account",
      "eliminar","eliminación","eliminacion","borrar","suprimir","supresión","suppression","supprimer",
      "effacer","effacement","löschen","loeschen","entfernen","删除","削除","삭제")
    return any(x in t for x in intents)

def matches_alias(payload: Any, aliases: set[str]) -> bool:
    text=norm(json.dumps(payload,ensure_ascii=False,default=str))
    return any(a and a in text for a in aliases)

def relevant(records, aliases, audit_at):
    cutoff=when(audit_at); found=[]
    for r in records:
        ts=when(r.captured)
        if cutoff and ts and ts>cutoff: continue
        if matches_alias(r.payload,aliases): found.append(r)
    return found

def plan(found: list[Evidence]) -> list[Step]:
    out=[]; seen=set()
    for r in found:
        if r.category in {"USER_PROFILE","SECONDARY_IDENTIFIER","SEARCH_INDEX_ENTRY","CACHE_ENTRY","USER_EXPORT","MARKETING_PROFILE"}:
            remediation,state,verify="DELETE_RECORD","ABSENT","VERIFY_RECORD_ABSENT"
        elif r.category in {"ANALYTICS_PROFILE","PRODUCT_TELEMETRY"}:
            remediation,state,verify="ANONYMIZE_RECORD","ANONYMIZED","VERIFY_RECORD_ANONYMIZED"
        elif r.category in {"SUPPORT_MESSAGE","SUPPORT_ATTACHMENT","EMAIL_DELIVERY_LOG","ACCOUNT_TOMBSTONE"}:
            remediation,state,verify="REDACT_RECORD","REDACTED","VERIFY_RECORD_REDACTED"
        elif r.category=="ACTIVE_DATA_FLOW":
            enabled=norm(r.payload.get("enabled")) in {"true","1","yes"} or norm(r.payload.get("last_delivery_status")) in {"delivered","active","running"}
            if not enabled: continue
            remediation,state,verify="DISABLE_DATA_FLOW","DISABLED","VERIFY_DATA_FLOW_DISABLED"
        elif r.category=="BACKUP_ARCHIVE":
            allowed=norm(r.payload.get("restore_allowed")) in {"true","1","yes"}
            if not allowed: continue
            remediation,state,verify="BLOCK_RESTORE","BLOCKED","VERIFY_RESTORE_BLOCKED"
        elif r.category=="SECURITY_AUDIT_LOG":
            # Retention is a policy-preserved record, not a deletion target.
            out.append(Step("VERIFICATION",r.system,r.resource,"VERIFY_RECORD_PRESENT","PRESENT",r.file_id))
            continue
        else: continue # Retention/unknown classes need explicit policy evidence.
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
    return out

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
    requests=csv_rows(DATA/"deletion_requests.csv")
    by_user,reverse=identity_index()
    evidence=evidence_records()
    results=[]
    for case in requests:
        status,steps=solve(case,evidence,by_user,reverse)
        results.append({"case_id":case["case_id"],"deletion_status":status,
                        "steps_json":json.dumps(steps,ensure_ascii=False,separators=(",",":"))})
    results.sort(key=lambda r:r["case_id"])
    with OUTPUT.open("w",encoding="utf-8",newline="") as f:
        w=csv.DictWriter(f,fieldnames=("case_id","deletion_status","steps_json"));w.writeheader();w.writerows(results)
    print(f"Created {OUTPUT} with {len(results)} case rows.")
if __name__=="__main__": main()
