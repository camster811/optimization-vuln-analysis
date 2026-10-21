# Phase 9 final results

Exploratory family-cluster intervals; ten families. Shared missingness remains in the primary denominator.

| Method | A | Correct | Incorrect | Abstain | Unavailable | C/A | Coverage | Selective accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 160 | 18 | 0 | 142 | 0 | 0.1125 | 0.1125 | 1 |
| llm | 160 | 125 | 28 | 7 | 0 | 0.7812 | 0.9563 | 0.817 |

Full intervals, optimization/CWE dispositions, class balance, matched contrasts, per-family and collision sensitivities, confidence and compute accounting are in `evaluation.json`.

Private localization and Codex oracle review were used; there was no independent human adjudication.
