# Completed study results

The primary results are in `representation/`:

| Directory | Contents |
|---|---|
| `analysis/` | Accepted `analysis-v2` tables, figures, evaluation, compute costs and qualitative review |
| `execution/` | Completed 1,440-slot final execution, requests, raw responses and journals |
| `pilot/` | Completed 18-slot engineering pilot |
| `runtime/{pilot,preflight,final}/` | Saved runtime/startup records for the actual runs |
| `records/` | Phase 6–9 accounting, checks, completion records and qualitative notes |

These directories contain saved study data and model outputs. Their contents were
moved unchanged; no model was rerun and no results were regenerated. Results remain
outside the Python package. Git includes the final summary CSV tables, figures,
`evaluation.json` and `audit.json` from `analysis/`. It excludes `attempts.csv`,
qualitative/raw response exports, manifests, method snapshots, runtime records and
complete execution/pilot directories. The committed exports are a readable report,
rather than a complete execution dataset. The full local directory is still intact.
See the
[data migration record](../documentation/llm-redesign/data_migration.md) for old paths.
