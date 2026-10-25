#!/usr/bin/env python3
"""Compare generated predictions with public samples and run synthetic request checks."""
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
T={r["case_id"]:r for r in truth};P={r["case_id"]:r for r in pred}; ids=sorted(T.keys() & P.keys())
sc=sum(T[i]["deletion_status"]==P[i]["deletion_status"] for i in ids)
seq=0;st=sp=fc=ft=0
for cid in ids:
 a=json.loads(T[cid]["steps_json"]);b=json.loads(P[cid]["steps_json"])
 seq+=a==b; st+=max(len(a),len(b))
 for j in range(min(len(a),len(b))):
  sp+=a[j]==b[j]
  for k in set(a[j])|set(b[j]):ft+=1;fc+=a[j].get(k)==b[j].get(k)
custom=[
 ("Non-deletion export request",{"request_text":"Please export a copy of my data, do not delete my account."},False),
 ("English profile and contact deletion",{"request_text":"Please delete my profile and remove my name and contact details."},True),
 ("Japanese deletion request",{"request_text":"このアカウントの完全な削除を依頼します。"},True),
 ("Korean deletion request",{"request_text":"계정을 삭제해 주세요."},True)]
cp=sum(deletion(r)==e for _,r,e in custom)
(ROOT/"evaluation").mkdir(exist_ok=True)
report=f"""# Evaluation Report

## Public sample benchmark

- Public sample cases compared: {len(ids)} of {len(truth}.
- Deletion-status accuracy: {sc}/{len(ids)} ({sc/len(ids)*100 if ids else 0:.2f}%).
- Step-level exact accuracy at paired positions (extra/missing steps counted in denominator): {sp}/{st} ({sp/st*100 if st else 0:.2f}%).
- Field-level accuracy at paired step positions: {fc}/{ft} ({fc/ft*100 if ft else 0:.2f}%).
- Exact sequence accuracy: {seq}/{len(ids)} ({seq/len(ids)*100 if ids else 0:.2f}%).

These public-sample metrics are not estimates of hidden-set accuracy.

## Participant-created additional cases

"""
for name,r,e in custom: report+=f"- {name}: {'PASS' if deletion(r)==e else 'FAIL'} (expected deletion={e}).\n"
report+=f"""
- Synthetic decision checks passed: {cp}/{len(custom)}.

## Failures found and improvements made

The evaluator compares predictions with the public sample rather than assuming correctness. The parser now checks nested JSON values, recognizes deletion requests in several represented languages, and avoids fabricating resource IDs or evidence citations when no direct finding is supported. Known gaps remain in PDF/image/SQLite interpretation and in proving absence across every relevant data store. CI contract success must not be confused with hidden-case accuracy.
"""
# Correctly emit the sample count expression without requiring any private labels.
report=report.replace(f"of {len(truth}.",f"of {len(truth)}.")
(ROOT/"evaluation"/"evaluation_report.md").write_text(report,encoding="utf-8")
print(report)
