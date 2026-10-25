#!/usr/bin/env python3
import csv,json,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"code"))
from main import main,deletion
def rows(p):
 with open(p,encoding="utf-8-sig",newline="") as f:return list(csv.DictReader(f))
truth=rows(ROOT/"dataset"/"sample_output.csv")
with tempfile.TemporaryDirectory() as td:
 out=Path(td)/"sample.csv"
 main(ROOT/"dataset"/"sample_deletion_requests.csv",out)
 pred=rows(out)
T={r["case_id"]:r for r in truth};P={r["case_id"]:r for r in pred};ids=sorted(T.keys() & P.keys())
sc=sum(T[i]["deletion_status"]==P[i]["deletion_status"] for i in ids)
mismatch_ids=[i for i in ids if T[i]["deletion_status"]!=P[i]["deletion_status"]]
seq=0;step_total=step_correct=field_total=field_correct=0
for cid in ids:
 a=json.loads(T[cid]["steps_json"]);b=json.loads(P[cid]["steps_json"])
 seq+=a==b;step_total+=max(len(a),len(b))
 for j in range(min(len(a),len(b))):
  step_correct+=a[j]==b[j]
  for k in set(a[j])|set(b[j]):field_total+=1;field_correct+=a[j].get(k)==b[j].get(k)
custom=[
 ("Non-deletion export request",{"request_text":"Please export a copy of my data, do not delete my account."},False),
 ("English profile and contact deletion",{"request_text":"Please delete my profile and remove my name and contact details."},True),
 ("Japanese deletion request",{"request_text":"このアカウントの完全な削除を依頼します。"},True),
 ("Korean deletion request",{"request_text":"계정을 삭제해 주세요."},True)]
custom_pass=sum(deletion(r)==e for _,r,e in custom)
(ROOT/"evaluation").mkdir(exist_ok=True)
report=f"""# Evaluation Report

## Public sample benchmark

- Public sample cases compared: {len(ids)} of {len(truth)}.
- Deletion-status accuracy: {sc}/{len(ids)} ({sc/len(ids)*100 if ids else 0:.2f}%).
- Status mismatch case IDs: {", ".join(mismatch_ids)}.
- Step-level exact accuracy at paired positions: {step_correct}/{step_total} ({step_correct/step_total*100 if step_total else 0:.2f}%).
- Field-level accuracy at paired step positions: {field_correct}/{field_total} ({field_correct/field_total*100 if field_total else 0:.2f}%).
- Exact sequence accuracy: {seq}/{len(ids)} ({seq/len(ids)*100 if ids else 0:.2f}%).

These public-sample metrics are not estimates of hidden-set accuracy.

## Participant-created additional cases

"""
for name,r,e in custom: report+=f"- {name}: {'PASS' if deletion(r)==e else 'FAIL'} (expected deletion={e}).\n"
report+=f"""
- Synthetic decision checks passed: {custom_pass}/{len(custom)}.

## Status mismatch diagnostics

"""
for cid in mismatch_ids:
 a=json.loads(T[cid]["steps_json"]); b=json.loads(P[cid]["steps_json"])
 preview="; ".join(f"{x.get('phase')}:{x.get('system_id')}/{x.get('resource_id')}:{x.get('operation')}[{x.get('evidence_id','')}]" for x in b[:8]) or "(no predicted steps)"
 report+=f"- {cid}: expected {T[cid]['deletion_status']}, predicted {P[cid]['deletion_status']}; expected steps={len(a)}, predicted steps={len(b)}; predicted preview: {preview}.\\n"

report+="""
## Failures found and improvements made

The evaluator compares predictions with public sample outputs. The parser checks nested JSON values, parses SQLite-compatible SQL snapshots, recognizes deletion requests in several represented languages, and avoids fabricating resource IDs or evidence citations when no direct finding is supported. Known gaps remain in PDF/image interpretation and proving absence across every relevant data store. CI contract success is not proof of hidden-case accuracy.
"""
(ROOT/"evaluation"/"evaluation_report.md").write_text(report,encoding="utf-8")
print(report)
