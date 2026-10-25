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