# Buffer-overflow representation study

This college research project compares assembly, Ghidra decompilation and their
combination as inputs to a local LLM under GCC optimization and symbol stripping.
The completed study uses the same 160 reviewed binary observations for all three
representations and an always-safe control.

Exact correctness was 45.00% for assembly, 77.50% for decompilation, 71.25% for
combined inputs and 62.50% for the control. The primary combined-minus-decompilation
effect was −6.25 percentage points. See the [study overview](documentation/llm-redesign/README.md)
and [analysis report](documentation/llm-redesign/phase9_report.md) for methods,
uncertainty and limitations. The accepted tables and figures are retained with the
study data.

Active Python code lives in [`src/optimization_vuln_analysis/`](src/optimization_vuln_analysis/):

- `common/`: serialization, paths, artifact writes and metric arithmetic.
- `inference/`: transport, sampling, attempts, runtime launch and identity.
- `inputs/`: public bundle validation and historical input adapters.
- `studies/representation/`: projection, response decoding, execution inspection,
  scoring, pilot integration and reporting, with packaged prompts and schemas.

`tests/support/` contains synthetic builders; shared fixtures live in `tests/conftest.py`.
The [data guide](documentation/llm-redesign/data_locations.md) identifies study inputs,
accepted outputs and older working directories. Current inputs and sources live in `data/`; completed runs and analysis live in
`results/`; older material lives in `artifacts/history/`. The former `redesign/`
directory is ready for deletion. See the [migration record](documentation/llm-redesign/data_migration.md).

[R6](documentation/llm-redesign/refactor_r6_report.md) finishes the cleanup for a
standalone college research study. Active freeze/release tools, source snapshots,
environment locks and the old `redesign.*` command aliases have been removed.
New model runs and result collection are not planned. Earlier phase and refactor
reports are historical records; current usage is described here.

Install and run all tests:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install '.[test]'
.venv/bin/python -m pytest -q
```

All tests run by default. They use the retained small fixtures, synthetic study
inputs and fake transport responses; no model, GPU, compiler, inference server or
separately supplied private campaign is required. There is no CI, evidence replay
job, freeze workflow or automatic data download to configure.

Commands keep their existing argparse interfaces under the single package:

```sh
.venv/bin/python -m optimization_vuln_analysis.studies.representation.reporting --help
.venv/bin/python -m optimization_vuln_analysis.studies.representation.scoring --help
```

Reporting takes `--inputs`, `--projection`, `--execution` and `--directory` directly.
It exports tables and figures from saved study data. Its `verify --directory ...`
command checks exported file hashes without rebuilding results or loading an old
environment. Input preparation similarly takes explicit parent/pilot paths.
Package prompts and schemas are resolved independently of the working directory.

Commit the source, tests, documentation, packaging files, `data/sources/` fixtures,
navigation README files and the selected final exports allowed by `.gitignore` in
`results/representation/analysis/`. Keep full datasets, raw runs, history, models,
virtual environments and archives local. Include the tracked deletions from the
old `pipeline/` and `redesign/` layout when committing this refactor.
