# Study data migration

Moved November 23, 2026, America/New_York. Every original file has been moved out of
`redesign/`. Current sources/inputs are under `data/`, completed runs and accepted
analysis under `results/`, and other artifacts under `artifacts/history/`.
Only a deletion notice remains in `redesign/`; the directory is safe to remove.

## Complete path mapping

The specific routes below take precedence over the final historical catch-all.
Directory contents keep their existing filenames and relative layout.

| Former location under `redesign/` | Current location |
|---|---|
| `config.json`, `context_policy.json`, `llm_policy.json`, `corpus/`, `data/` | Same names under `data/sources/` |
| `campaigns/final-v2-context12288/` | `data/parent-study/` |
| `experiments/llm-representation-v1/representation-v1-context12288-final-v1/inputs/` | `data/representation/inputs/` |
| `experiments/llm-representation-v1/representation-v1-context12288-final-v1/projection/` | `data/representation/views/` |
| `build/extensions/representation-study/phase6-pilot-v1/` | `data/representation/pilot/` |
| `experiments/llm-representation-v1/representation-v1-context12288-final-v1-analysis-v2/` | `results/representation/analysis/` |
| `build/extensions/representation-study/phase7-final-v1/` | `results/representation/execution/` |
| `build/extensions/representation-study/phase6-execution-v1/` | `results/representation/pilot/` |
| `build/extensions/representation-study/phase6-runtime-v1/` | `results/representation/runtime/pilot/` |
| `build/extensions/representation-study/phase7-runtime-v1/` | `results/representation/runtime/preflight/` |
| `build/extensions/representation-study/phase8-runtime-v1/` | `results/representation/runtime/final/` |
| `build/extensions/representation-study/phase6*.json` through `phase9*.json` | Same basenames under `results/representation/records/` |
| Every other original file | `artifacts/history/redesign/<original relative path>` |

The catch-all includes older workspaces, alternate analyses, archives, original
protocol files, maintenance records, saved source copies, and the former README.
No original files were discarded, including material outside the known critical set.
Historical metadata and archived contents were not rewritten or regenerated.

## File accounting

Before moving, every original file was inventoried with its destination, byte size
and SHA-256. After moving, every destination was checked against that inventory,
and the complete destination file set was compared with the original set.

| Destination | Original files preserved | Bytes preserved |
|---|---:|---:|
| `data/` | 12,856 | 245,892,536 |
| `results/` | 6,391 | 94,792,842 |
| `artifacts/history/redesign/` | 28,078 | 770,956,334 |
| **Total** | **47,325** | **1,111,641,712** |

All original files were present and byte-identical after the move. New navigation
README files and this report are additional files, not replacements for research data.

The relocated critical data also contain:

- 160 final observations and 160 private evaluation rows;
- 480 accepted views and 480 observation-condition result rows;
- all 1,440 terminal final slots: 1,382 valid, six length-limited, 16 schema-invalid
  and 36 input-blocked, with their saved response files present;
- 160 control result rows and the complete 18-slot engineering pilot;
- the original corpus, original parent campaign, source/provenance records,
  accepted pilot inputs, final token accounting, runtime logs and qualitative notes.

## Active consumers and deletion readiness

The corpus default is now `data/sources/`; input preparation defaults to
`data/parent-study/`. Explicit CLI paths still take precedence. Original protocol
metadata retains its dated workspace string, which current commands do not use
as a filesystem default. Research manifests keep their inner relative paths intact.

The source distribution includes the small `data/sources/` test fixtures. Ignore
rules expose those fixtures and the navigation README files while leaving large
datasets, outputs and historical artifacts outside automatic source additions.
Nothing was staged or committed.

Current documentation links now point to the relocated data, canonical source, or
historical source copies as appropriate. Dated prose and code examples remain
historical references; use the [data guide](data_locations.md) for current commands.
The original corpus CLI successfully read the new default source workspace and
validated its 32 pilot observations.

The full suite passed against the relocated fixtures, with no skips or exclusions:

```text
.venv/bin/python -m pytest -q --tb=short
422 passed in 341.59s (0:05:41)
```

A separately installed wheel also validated the 32 pilot observations using the
new default workspace. All current documentation links resolve, and
`git diff --check` passed. A final exhaustive hash check after the documentation
and test work again confirmed all 47,325 original files were unchanged.

`redesign/README.md` is the only remaining entry under `redesign/`. It is a deletion
notice linking to the new locations. No active Python consumer or test needs the
old directory. No model, freeze, restoration or result-generation workflow was run.
