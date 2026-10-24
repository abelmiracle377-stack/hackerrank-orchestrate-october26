# Evaluation report

## Current state
Not yet evaluated. No full-dataset execution or comparison against the public sample outputs has been run in this repository branch from this coding session.

## Required metrics
After running the solution, compare the 32 public cases against `dataset/sample_output.csv` and record:
- case-level deletion-status accuracy;
- step-level accuracy (phase, system_id, resource_id, operation, state, evidence_id);
- field-level accuracy;
- exact sequence accuracy;
- counts of missing, extra, and misordered steps.

## Additional evaluation cases
Add at least three authored tests covering:
1. a request that is clearly not a deletion request (expect `NOT_APPLICABLE` and `[]`);
2. a retained security audit record that must remain available while prohibited identifiers are removed;
3. an active synchronization or restore path that could recreate deleted data.

## Known failures and improvements
Known gaps: no OCR for image/PDF evidence; evidence line parsing is heuristic; activity schemas may vary; historical identity matching is approximate; rule-specific retention/tombstone logic is incomplete; current fallback intentionally returns INCOMPLETE when evidence is insufficient. Improve by parsing every evidence format, normalizing event schemas, resolving identities transitively, applying rules per resource, and validating all 518 cases.
