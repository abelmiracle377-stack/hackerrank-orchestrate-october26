#!/usr/bin/env python3
"""Run public-sample and synthetic decision checks; write evaluation_report.md."""
import csv, json, sys, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"code"))
from main import main, deletion

def rows(path):
    with open(path,encoding="utf-8-sig",newline="") as f:
        return list(csv.DictReader(f))

sample_req=ROOT/"dataset"/"sample_deletion_requests.csv"
sample_truth=rows(ROOT/"dataset"/"sample_output.csv")
with tempfile.TemporaryDirectory() as td:
    generated=Path(td)/"sample_output.csv"
    main(sample_req,generated)
    pred=rows(generated)

truth={r["case_id"]:r for r in sample_truth}
actual={r["case_id"]:r for r in pred}
ids=sorted(set(truth)&set(actual))
status_correct=sum(truth[i]["deletion_status"]==actual[i]["deletion_status"] for i in ids)
sequence_correct=0
step_total=step_correct=field_total=field_correct=0
for cid in ids:
    expected=json.loads(truth[cid]["steps_json"])
    got=json.loads(actual[cid]["steps_json"])
    if expected==got: sequence_correct+=1
    step_total+=max(len(expected),len(got))
    for idx in range(max(len(expected),len(got))):
        if idx>=len(expected) or idx>=len(got): continue
        a,b=expected[idx],got[idx]
        if a==b: step_correct+=1
        keys=set(a)|set(b)
        for key in keys:
            field_total+=1
            if a.get(key)==b.get(key): field_correct+=1

custom=[
 ("non-deletion export request",{"request_text":"Please export a copy of my data, do not delete my account."},False),
 ("English personal-data deletion",{"request_text":"Please delete my profile and remove my name and contact details."},True),
 ("Japanese deletion request",{"request_text":"このアカウントの完全な削除を依頼します。"},True),
 ("Korean deletion request",{"request_text":"계정을 삭제해 주세요."},True),
]
custom_pass=sum(deletion(r)==expected for _,r,expected in custom)
report=f"""# Evaluation Report

## Public sample benchmark

- Public sample cases compared: {len(ids)} of {len(sample_truth)}.
- Deletion-status accuracy: {status_correct}/{len(ids)} ({(status_correct/len(ids)*100 if ids else 0):.2f}%).
- Step-level exact accuracy (paired positions; missing/extra steps count as incorrect): {step_correct}/{step_total} ({(step_correct/step_total*100 if step_total else 0):.2f}%).
- Field-level accuracy across paired step positions: {field_correct}/{field_total} ({(field_correct/field_total*100 if field_total else 0):.2f}%).
- Exact sequence accuracy (entire step arrays match): {sequence_correct}/{len(ids)} ({(sequence_correct/len(ids)*100 if ids else 0):.2f}%).

These are public-sample metrics only; they are not estimates of hidden-set accuracy.

## Participant-created additional cases

"""
for name,_,expected in custom:
    report += f"- {name}: {'PASS' if deletion(dict(_))==expected else 'FAIL'} (expected deletion={expected}).\n"
report+=f"""
- Synthetic decision checks passed: {custom_pass}/{len(custom)}.

## Failures and improvements

The evaluator reports exact mismatches rather than assuming the baseline is accurate. The parser was improved to match nested JSON scalar values, recognize several represented language families, and avoid fabricating a resource ID or evidence citation when no direct finding is found. Remaining known limitations include incomplete OCR/PDF/SQLite evidence interpretation and conservative evidence matching. Review the detailed sample diffs and do not treat structural CI success as proof of hidden-case accuracy.
"""
(ROOT/"evaluation").mkdir(exist_ok=True)
(ROOT/"evaluation"/"evaluation_report.md").write_text(report,encoding="utf-8")
print(report)
