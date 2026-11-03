# Deletion audit solution

## Run locally

Requires Python 3.11+, the packages in `code/requirements.txt`, and Tesseract OCR for scanned documents/images. The runner can still execute without OCR dependencies, but those evidence types will be skipped.

```bash
python -m pip install -r code/requirements.txt
# Install tesseract-ocr with your operating system package manager
python code/main.py
python code/evaluation/main.py --predicted output.csv --expected dataset/sample_output.csv
```

The runner creates `output.csv` at the repository root. It resolves identities from the current identity table and historical audit log, inspects manifest-listed machine-readable evidence, and emits the required ordered JSON steps. PDF text is extracted with pypdf; scanned PDFs use PyMuPDF rendering plus Tesseract OCR. Image evidence uses Pillow and Tesseract. OCR output is treated as evidence text and must still be checked against the source when it affects a decision.

## Validation

GitHub Actions compiles the Python files, runs the full request set, validates the 518-row output contract, and writes a sample benchmark report. The sample benchmark is a development aid only; hidden canonical results are unavailable.

## Limitations to address before final submission

- Integrate OCR/vision extraction for relevant image/PDF evidence.
- Use richer event/state interpretation and request-specific policy evaluation.
- Review sample exact-sequence and field-level mismatches.
- Complete the required three additional team-created evaluation cases.
- Produce and inspect the final `code.zip`, `output.csv`, evaluation report, and usage report.
