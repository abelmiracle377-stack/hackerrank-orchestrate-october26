# Ghost Data Still Exists — working solution

## Run

Use Python 3.10+ from the repository root with the participant-provided `dataset/` directory present:

```bash
python -m pip install -r requirements.txt
python code/main.py
python evaluation/evaluate.py
```

The script writes `output.csv` at the repository root. The evidence pipeline reads CSV/text/JSON/SQL, extracts selectable PDF text, and OCRs screenshots when Tesseract is installed. GitHub Actions installs the required extraction tools automatically.

## Method and limitations

This is a deterministic evidence-matching baseline, not a validated high-accuracy agent. It resolves current and historical identifiers, applies audit cutoffs, and uses text/JSON/SQL plus limited PDF/image text extraction. The public sample benchmark in `evaluation/evaluation_report.md` measures the current behavior against public examples; it does not estimate hidden-case accuracy. Verify the report before relying on predictions.

Only participant-facing files under `dataset/` are used. Organizer-only truth is not used.

## Reliability gaps identified during interview review

The following are known limitations, not solved production guarantees:

- **Unreadable media:** PDF/image extraction failures and empty OCR results are now recorded. If no positive finding exists and an in-scope media file is unreadable by the audit cutoff, the current baseline fails closed to `INCOMPLETE` with `steps_json: []` rather than inferring completion from absence. Because the current evidence schema does not map every media item to each case, this is intentionally conservative and may create false `INCOMPLETE` results. A next iteration should map media evidence to cases and expose a dedicated uncertainty/manual-review state if the output contract permits it.
- **Identifier closure:** the audit-log closure loop discovers candidate links but does not itself prove identity. Shared or recycled emails/phone numbers can overlink records. The implementation does not yet have a complete temporal ownership model or confidence-based link confirmation.
- **Hard-coded heuristics:** the `user_1`–`user_4` account mapping cutoff and the 8-digit numeric identifier threshold are present in code, but the recovered development history does not document empirical justification for either. They require schema-backed mappings and targeted collision/reuse tests.
- **Status versus steps:** the recorded public sample results showed strong status accuracy but substantially lower exact step-sequence accuracy. Prioritize preventing false `COMPLETE` decisions before optimizing action ordering.
- **Evaluation limits:** case_26 was discussed as an illustrative example of cutoff/latest-snapshot behavior, but it was not verified as one of the six exact sequence matches, and no controlled baseline comparison was run. Do not claim that case as a measured improvement.
- **Authorship provenance:** the recovered log is not a verbatim trace. It cannot establish which exact code sections were human-authored versus AI-suggested.

These changes and notes do not establish hidden-set accuracy or production readiness. Re-run the public evaluation and CI after code changes, inspect the generated report, and test unreadable-media, recycled-identifier, and cutoff-boundary scenarios before relying on the output.
