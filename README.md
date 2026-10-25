# Ghost Data Still Exists — working solution

## Run

Use Python 3.10+ from the repository root with the participant-provided `dataset/` directory present:

```bash
python code/main.py
python evaluation/evaluate.py
```

To run against the public sample request file separately:

```bash
python code/main.py --requests dataset/sample_deletion_requests.csv --output /tmp/sample-output.csv
```

## Method and limitations

This is a deterministic evidence-matching baseline, not a validated high-accuracy agent. It resolves current and historical identifiers, applies audit cutoffs, and parses selected text and JSON evidence. It does not fully interpret screenshots, PDFs, or SQLite snapshots. Absence of a matching record is not proof that deletion is complete. See `evaluation/evaluation_report.md` for measured public-sample results; these do not estimate hidden-case accuracy.

Only participant-facing files under `dataset/` are used. Organizer-only truth is not used.