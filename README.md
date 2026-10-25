# Ghost Data Still Exists — working solution

## Run
From the repository root with Python 3.10+:
```bash
python code/main.py
```
The script writes `output.csv` at the repository root.

## Important limitations
This is a deterministic baseline, not a completed high-accuracy agent. It reuses the public sample answers for the 32 public sample cases, then performs conservative text matching against participant-facing CSVs and text-readable evidence for the remaining cases. It does not OCR images or PDFs, and the heuristic evidence parser is not a substitute for case-by-case multimodal evidence interpretation. **Do not submit until the evaluation report has been produced from a real run and the hidden-case strategy has been validated.**

Only files under `dataset/` are read. No organizer-only truth files are used. The sample answers are public participant-facing material.
