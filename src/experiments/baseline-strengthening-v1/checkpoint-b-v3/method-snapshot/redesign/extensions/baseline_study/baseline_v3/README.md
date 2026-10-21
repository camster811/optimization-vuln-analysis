# Checkpoint B: bounded library contracts v3

Post-hoc method `ghidra-library-contract-bounds-v3` adds exactly wmemset, wcslen, wcscpy, strcat and a limited wprintf contract. See [the specification](specification.md). Original methods, corpus, oracle, context, saved LLM attempts and Checkpoint A remain unchanged. The original lifter is reused with explicit four-byte-wide prototypes and every corpus input is relifted. The v2 interpreter, stack heuristic/native-store fallback and resource limits are inherited.

Workflow from the repository root (existing directories are never overwritten):

```bash
# Independent compiled smoke validation preceded the full 176-cell matrix.
.venv/bin/python -m redesign.extensions.baseline_study.baseline_v3.fixtures \
  --stage full --directory redesign/build/extensions/baseline-study/v3-fixtures-a

.venv/bin/python -m pytest -q tests/test_baseline_v3.py tests/test_bounds.py \
  tests/test_stack_bounds.py tests/test_baseline_study.py \
  tests/test_pilot_evaluation.py tests/test_phase9_closeout.py \
  --junitxml=redesign/build/extensions/baseline-study/tests/v3-tests.xml

MPLCONFIGDIR=/tmp/juliet-baseline-study-matplotlib \
  .venv/bin/python -m redesign.extensions.baseline_study.baseline_v3.campaign freeze \
  --fixtures redesign/build/extensions/baseline-study/v3-fixtures-a \
  --tests redesign/build/extensions/baseline-study/tests/v3-tests.xml
.venv/bin/python -m redesign.extensions.baseline_study.baseline_v3.campaign run
.venv/bin/python -m redesign.extensions.baseline_study.baseline_v3.release analyze
MPLCONFIGDIR=/tmp/juliet-baseline-study-matplotlib \
  .venv/bin/python -m redesign.extensions.baseline_study.baseline_v3.release publish
```

Resume only the same `campaign run`: durable dispatch without completion becomes failed, never retried. A corpus-motivated code change requires a new revision; no tuning of this frozen implementation is permitted. No LLM requests are made. Predictor workers receive only opaque public-input paths and generic policy, with private truth joined after all 160 results are durable.

Same-IR ablations disable the four new memory/string effects or new wide-output effect; disabled effects abstain. Prototypes stay identical, so the ablations are not equivalent to the saved v2 lifter. Separate binary/source-label scoring and common-input/subgroup/alert/paired-family results preserve original denominators and exploratory intervals.

The publication is `redesign/experiments/baseline-strengthening-v1/checkpoint-b-v3/`. Verify with:

```bash
MPLCONFIGDIR=/tmp/juliet-baseline-study-matplotlib \
  .venv/bin/python -m redesign.extensions.baseline_study.baseline_v3.release verify
```

For replay extract `checkpoint-b.tar.gz` into a fresh directory, copy the accompanying `release.json` and original archive alongside `freeze.json`, and pass `release verify --directory /path/to/restored`. Imported repository methods and original campaign releases remain dependencies. Saved IR/results and tables regenerate without a model server or fresh Ghidra lifting. The archive includes private evaluation truth; it is not a worker input mount.
