# Token usage and cost report

## Run method

The submitted baseline is a deterministic Python program. It does not call a hosted or local language model, and it does not make external API calls during the full dataset run.

| Metric | Value |
|---|---:|
| Model provider | None |
| Model name | None |
| Model calls | 0 |
| Input tokens | 0 |
| Output tokens | 0 |
| Total tokens | 0 |
| Average tokens per request (518 cases) | 0 |
| Estimated total model cost | $0.00 |
| Estimated model cost per request | $0.00 |

The zero-token figures are for this deterministic implementation only. They do not include development-time use of ChatGPT or any separate model-assisted evaluation that may be performed outside the runner.

## Reproducibility

Run the complete dataset using:

```bash
python code/main.py
```

The program reads the dataset and writes the 518-case `output.csv`. The CI workflow validates its row count and JSON schema. This report should be updated if a model-backed component is introduced; include the provider/model, call counts, token counts, and pricing basis for that run.
