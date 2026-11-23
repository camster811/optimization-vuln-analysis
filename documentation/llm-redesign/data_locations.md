# Study data locations

The active layout is `src/` for Python, `data/` for inputs and original sources,
`results/` for completed runs and accepted analysis, and `artifacts/history/` for
older work products. The former `redesign/` directory contains only a deletion
notice and is safe to remove. See the [migration record](data_migration.md).

## Inputs and fixtures

The small `data/sources/` workspace contains the configurations, source corpus,
provenance records and 32 public pilot bundles needed by the tests. Its inner
`corpus/` and `data/pilot/` names are preserved for the existing relative manifests.
Tests create their own final-study data and fake transport responses; they do not
need a model, GPU, compiler or separately supplied private campaign.

| Data | Current location |
|---|---|
| Original input/source workspace and pilot fixtures | `data/sources/` |
| Earlier study's complete parent campaign | `data/parent-study/` |
| Accepted final public bundles and private evaluation ledger | `data/representation/inputs/` |
| Accepted 480 public views and line maps | `data/representation/views/` |
| Self-contained accepted pilot inputs | `data/representation/pilot/` |

## Results and run artifacts

| Data | Current location |
|---|---|
| Accepted final tables, figures and analysis | `results/representation/analysis/` |
| Completed final execution, requests and raw responses | `results/representation/execution/` |
| Completed engineering pilot | `results/representation/pilot/` |
| Saved pilot, preflight and final runtime records | `results/representation/runtime/` |
| Phase 6–9 checks, token accounting and qualitative notes | `results/representation/records/` |
| All other former workspace files | `artifacts/history/redesign/` |

Large research datasets, raw runs and historical artifacts remain local, separate
from source and wheels. The final summary CSV tables, figures, `evaluation.json`
and `audit.json` are committable under `results/representation/analysis/`.
The remaining report exports and complete execution data stay local.
A source-only checkout needs a supplied copy of the relevant directories only to
inspect or analyze the actual study. No download registry or freeze package is
required. Existing model binaries are external to these datasets.

## Commands

Install with `pip install '.[test]'` and run `python -m pytest -q` from the checkout.
The corpus CLI defaults to `data/sources/`; input preparation defaults to
`data/parent-study/`. Every command accepts explicit input/output paths.

Reporting uses `--inputs data/representation/inputs`,
`--projection data/representation/views`, `--execution results/representation/execution`
and an unused output `--directory`. Scoring takes the first three paths. Report
`verify --directory results/representation/analysis` checks stored export hashes
without rebuilding results. Pilot preparation can use
`--accepted data/representation/pilot` instead of the original build workspace.

Protocol files and historical manifests retain their original metadata and relative
paths. Current commands do not use the old `redesign/` root. Earlier phase reports
contain dated path examples; their Markdown links and the migration table point to
the relocated material. Historical copies and archives are passive data, with no
active repository restoration, freeze or release workflow.
