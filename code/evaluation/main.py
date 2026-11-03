#!/usr/bin/env python3
"""Evaluate generated output.csv against supplied sample answers; not hidden-test scoring."""
import argparse, csv, json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
FIELDS=("step_no","phase","system_id","resource_id","operation","state","evidence_id")
def load(path):
    result={}
    with Path(path).open(encoding="utf-8-sig",newline="") as f:
        for row in csv.DictReader(f):
            try:
                steps=json.loads(row.get("steps_json",""))
                if not isinstance(steps,list): raise ValueError("steps_json must be a JSON array")
                row["steps"]=steps
            except (ValueError,json.JSONDecodeError) as exc:
                row["steps"]=None; row["_error"]=str(exc)
            result[row.get("case_id","")]=row
    return result
def evaluate(pred,exp):
    shared=sorted(set(pred)&set(exp)); n=len(shared)
    status=sum(pred[c].get("deletion_status")==exp[c].get("deletion_status") for c in shared)
    exact=0; correct=total=0; pcount=ecount=0
    for c in shared:
        p,e=pred[c].get("steps"),exp[c].get("steps")
        if p is None or e is None: continue
        exact += p==e; pcount+=len(p); ecount+=len(e)
        for i in range(max(len(p),len(e))):
            ps=p[i] if i<len(p) and isinstance(p[i],dict) else {}
            es=e[i] if i<len(e) and isinstance(e[i],dict) else {}
            for key in FIELDS:
                total+=1; correct+=ps.get(key)==es.get(key)
    status_mismatches=[c for c in shared if pred[c].get("deletion_status")!=exp[c].get("deletion_status")]
    sequence_mismatches=[c for c in shared if pred[c].get("steps")!=exp[c].get("steps")]
    step_count_deltas={c:{"predicted":len(pred[c]["steps"] or []),"expected":len(exp[c]["steps"] or [])}
      for c in shared if pred[c].get("steps") is not None and exp[c].get("steps") is not None
      and len(pred[c]["steps"])!=len(exp[c]["steps"])}
    return dict(expected=len(exp),predicted=len(pred),matched=n,status_correct=status,
      status_mismatches=status_mismatches,sequence_mismatches=sequence_mismatches,
      step_count_deltas=step_count_deltas,
      status_accuracy=status/n if n else 0,exact=exact,sequence_accuracy=exact/n if n else 0,
      fields_correct=correct,fields_total=total,field_accuracy=correct/total if total else 0,
      pred_steps=pcount,expected_steps=ecount,missing=sorted(set(exp)-set(pred)),
      unexpected=sorted(set(pred)-set(exp)),errors={c:pred[c]["_error"] for c in pred if "_error" in pred[c]})
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--predicted",type=Path,default=ROOT/"output.csv")
    ap.add_argument("--expected",type=Path,default=ROOT/"dataset/sample_output.csv")
    ap.add_argument("--report",type=Path,default=ROOT/"code/evaluation/evaluation_report.md")
    a=ap.parse_args()
    if not a.predicted.exists(): ap.error(f"missing prediction file: {a.predicted}")
    if not a.expected.exists(): ap.error(f"missing expected file: {a.expected}")
    m=evaluate(load(a.predicted),load(a.expected))
    lines=["# Sample Evaluation Report","","This measures the supplied sample only; it is not a hidden-test score.","",
      "| Metric | Result |","|---|---:|",f"| Expected cases | {m['expected']} |",
      f"| Predicted cases | {m['predicted']} |",f"| Matched cases | {m['matched']} |",
      f"| Status accuracy | {m['status_accuracy']:.2%} ({m['status_correct']}/{m['matched']}) |",
      f"| Exact ordered step accuracy | {m['sequence_accuracy']:.2%} ({m['exact']}/{m['matched']}) |",
      f"| Step field accuracy | {m['field_accuracy']:.2%} ({m['fields_correct']}/{m['fields_total']}) |",
      f"| Predicted steps | {m['pred_steps']} |",f"| Expected steps | {m['expected_steps']} |","",
      "## Data checks","",f"- Missing cases: {', '.join(m['missing']) or 'None'}",
      f"- Unexpected cases: {', '.join(m['unexpected']) or 'None'}",
      f"- Invalid steps_json rows: {len(m['errors'])}","",
      "## Mismatch triage","",
      f"- Status mismatches: {', '.join(m['status_mismatches']) or 'None'}",
      f"- Exact-sequence mismatches (first 20): {', '.join(m['sequence_mismatches'][:20]) or 'None'}",
      f"- Cases with differing step counts (first 20): {', '.join(m['step_count_deltas']) or 'None'}","",
      "Exact sequence matching includes order and evidence IDs. Field accuracy compares fields by position and penalizes omitted or extra steps.",""]
    a.report.parent.mkdir(parents=True,exist_ok=True); a.report.write_text("\n".join(lines),encoding="utf-8")
    print("\n".join(lines))
if __name__=="__main__": main()
