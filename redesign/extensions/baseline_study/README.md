# Baseline strengthening: checkpoint A

This isolated post-hoc extension implements Track A of the [study plan](../../../documentation/juliet-redesign/baseline_strengthening_plan.md). Historical Phase 9 methods, inputs, raw attempts, evaluation and releases stay unchanged. Track B's v3 library contracts are not implemented here.

`controls.py` predicts only from a configured fixed label and shared availability. Four controls always return `not_vulnerable`, `vulnerable_CWE-121`, `vulnerable_CWE-122` or `uncertain` when eligible. Their outputs include no evidence, confidence or voting record. Opaque IDs attach predictions to inventory outside the pure prediction function. Control input files contain eligibility only; the evaluator separately joins private truth and saved method outputs.

`scoring.py` explicitly identifies the saved LLM, saved baseline v2 and four controls. It imports the unchanged frozen `outcomes`, `statistics` and `interval` functions and reproduces the frozen family-weight generator: 10,000 PCG64 draws, seed 20261019, shared family multiplicities. Historical primary, common-input and subgroup estimates/intervals must match before publication. Binary and source-label endpoints remain separate. All comparisons are supplementary and descriptive.

From the repository root:

```bash
.venv/bin/python -m pytest -q \
  tests/test_baseline_study.py tests/test_pilot_evaluation.py tests/test_phase9_closeout.py \
  --junitxml=redesign/build/extensions/baseline-study/tests/checkpoint-a-v1.xml

MPLCONFIGDIR=/tmp/juliet-baseline-study-matplotlib \
  .venv/bin/python -m redesign.extensions.baseline_study.study run \
  --run-id checkpoint-a-v1 \
  --tests redesign/build/extensions/baseline-study/tests/checkpoint-a-v1.xml

MPLCONFIGDIR=/tmp/juliet-baseline-study-matplotlib \
  .venv/bin/python -m redesign.extensions.baseline_study.study verify \
  --run-id checkpoint-a-v1
```

The first run writes `redesign/build/extensions/baseline-study/checkpoint-a-v1/` and publishes `redesign/experiments/baseline-strengthening-v1/checkpoint-a-v1/`. Existing runs/publications are never replaced. Verification checks original locks/input freeze/execution/analysis/results package and regenerates supplementary outputs byte for byte. It needs no live model server or new lifting. Set `MPLCONFIGDIR` to a writable path for the original Phase 9 figure replay.

The publication contains control-only input/prediction files, a separate historical evaluation snapshot, comparison JSON/CSV, report, claims/manuscript note, plan/method/test snapshots, original artifact hash references and test evidence. `study-manifest.json` binds the files; `release.json` binds exact archive membership and hashes. Keep `release.json` with `checkpoint-a.tar.gz`. The evaluation snapshot contains private truth and is not control input.

For a fresh restore, extract `checkpoint-a.tar.gz` into an empty directory, copy the accompanying `release.json` and original archive alongside its `study-manifest.json`, then run `study verify --directory /path/to/restored-study` in the same repository/environment. The unchanged original campaign and releases remain verification dependencies. No prediction is recomputed by invoking an LLM or Ghidra.
