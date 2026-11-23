# R6 standalone study cleanup

Data location update: current inputs/sources are now in `data/`, completed runs and
accepted analysis in `results/`, and older material in `artifacts/history/`.
The [migration record](data_migration.md) accounts for every former `redesign/` file.

Completed November 23, 2026, America/New_York. The user's final scope supersedes
the original R6 automation/reproduction plan: this repository is a standalone
college research study. Current work needs readable study code, retained data and
a passing test suite, without maintaining frozen repositories or automated releases.

## Simplified active code

- Removed the study freeze/release modules, common source/environment provenance
  scanner, deterministic archive-writing helpers and the old `redesign.*` aliases.
  The installable package now contains 27 Python modules under one namespace.
- Input, view, pilot and request preparation no longer copy Python source or
  capture installed distributions. Execution no longer compares current source
  with a saved method. Data/protocol hashes, private-truth separation, runtime
  identity, no-retry dispatch and interrupted-request handling remain.
- Reporting takes input, projection, execution and output paths directly. It
  retains scientific scoring, independent recounts, compute summaries, tables and
  figures without requiring a freeze, archived repository or matching historical
  environment. Export verification checks file integrity without rebuilding results.
- Replaced the reporting fixture's freeze/pilot/publication setup with a small
  synthetic study. Removed 52 cases specific to retired preservation/compatibility
  infrastructure and its archive helper. All 422 remaining cases run by default;
  there is no excluded evidence marker or separate reproduction test job.

The historical parent adapter still reads the original parent dataset's manifest
format, including its existing `freeze.json` field. This interprets accepted input
data; it does not create or manage new freezes. Corpus/input provenance remains
research attribution, rather than Python source/environment snapshot machinery.

## Data and documentation

The [data guide](data_locations.md) identifies source/test fixtures, final inputs,
public projections, completed execution, accepted analysis and older workspaces.
The existing CLI path arguments are the configuration; no registry, location
framework, CI, scheduled job, downloader or evidence replay automation was added.

Existing research data, results, archives and earlier maintenance records remain
in place as passive artifacts. R6 removes their active preservation tooling rather
than moving or deleting research data. New package builds include source and
protocol resources, without the research dataset or old compatibility packages.
Stale generated packaging output was removed so retired modules cannot enter a wheel.

The [repository guide](../../README.md), workspace README, study navigation and
[refactor plan](refactor_plan.md) now state the current scope. Earlier phase and
R0–R5 reports remain dated records; their reproduction obligations and former
command paths no longer describe the active project.

## Validation

The full suite passed on the final code:

```text
.venv/bin/python -m pytest -q --tb=short
422 passed in 344.33s (0:05:44)
```

There were no skipped, deselected or expected-failure cases. `pytest.ini` specifies
only the test directory and source import path. Documentation link checks and
`git diff --check` also passed.

Manual packaging checks passed in a separate temporary installation, outside the
checkout: all three representations find their schemas/prompts and construct/decode
synthetic requests; all seven remaining CLI entry points load; reporting rejects
missing preparation inputs. The installed wheel contains none of the retired
freeze/release/provenance modules or `redesign` compatibility package.

No model execution, historical result reproduction, new freeze or release archive
was performed. No staging or commits were performed.
