# Deletion audit solution

## Run locally

Requires Python 3.11+ and only the standard library.

```bash
python code/main.py
python code/evaluation/main.py --predicted output.csv --expected dataset/sample_output.csv
```

The runner creates `output.csv` at the repository root. It resolves identities from the current identity table and historical audit log, inspects manifest-listed machine-readable evidence, and emits the required ordered JSON steps. Image and PDF evidence are not OCR'd by this deterministic runner; review those evidence items separately before treating a result as final.

## Validation

GitHub Actions compiles the Python files, runs the full request set, validates the 518-row output contract, and writes a sample benchmark report. The sample benchmark is a development aid only; hidden canonical results are unavailable.

## Limitations to address before final submission

- Integrate OCR/vision extraction for relevant image/PDF evidence.
- Use richer event/state interpretation and request-specific policy evaluation.
- Review sample exact-sequence and field-level mismatches.
- Complete the required three additional team-created evaluation cases.
- Produce and inspect the final `code.zip`, `output.csv`, evaluation report, and usage report.
