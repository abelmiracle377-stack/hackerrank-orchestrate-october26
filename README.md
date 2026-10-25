# Ghost Data Still Exists — working solution

## Run

Use Python 3.10+ from the repository root, with the participant-provided `dataset/` directory present:

```bash
python code/main.py
```

The script writes `output.csv` at the repository root. To evaluate the public sample separately:

```bash
python code/main.py --requests dataset/sample_deletion_requests.csv --output /tmp/sample-output.csv
python evaluation/evaluate.py
```

## Method and limitations

This is a deterministic evidence-matching baseline, not a validated high-accuracy agent. It resolves current and historical identifiers from participant-facing files, applies the case audit cutoff, and parses selected text and JSON evidence. It does not fully interpret screenshots, PDFs, or SQLite data, and absence of a matching record is not proof that deletion is complete. Review `evaluation/evaluation_report.md` for public-sample results before relying on predictions.

Only participant-facing files under `dataset/` are used. Organizer-only truth files are not used.