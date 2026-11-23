# Phase 7: complete pilot and method lock

The 32-observation pilot is complete under the existing Phase 5 v2 baseline and Phase 6 LLM configuration. All 96 LLM slots are terminal: {'context_unavailable': 18, 'schema_invalid': 1, 'valid': 77}. There were 78 actual requests. Context-blocked slots made no request; failed requests were not retried. The three earlier Phase 6 requests remain part of this pilot. No predictor, prompt, sampler, source program, oracle, or public bundle changed from answer inspection.

The [decision log](phase7_decisions.md) records the method choices and limitations. The [method lock](../../redesign/provenance/method-lock.json) binds them after verification. This permits Phase 8 final preparation; it is not a final-input freeze or authorization to run final predictors. Ten final pairs remain unassigned.

## Primary pilot accounting

Six observations exceed the shared 8,192-token context with the full 4,096-token completion reservation. Both methods receive unavailable scoring status on those observations. The denominator remains all 32 adjudicated observations; raw baseline outputs are preserved.

| Method | A | Correct | Incorrect | Abstained | Unavailable | Correct/A | Coverage | Selective accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 32 | 8 | 0 | 18 | 6 | 0.250 | 0.250 | 1.000 |
| llm | 32 | 15 | 11 | 0 | 6 | 0.469 | 0.812 | 0.577 |

The LLM-minus-baseline correct-rate difference is 0.219; its exploratory family-bootstrap interval is [-0.125, 0.562]. Only **two development families** underlie this pilot. These figures check accounting and reveal method limitations; they do not estimate the final study's effect size. The conditional common-input denominator is 26. The [complete evaluation](../../redesign/results/pilot/phase7-evaluation.json) includes common-input scores, exact and alert metrics, source-label recovery, optimization/symbol/CWE/class/family subgroups, matched contrasts, transformation and availability transitions, leave-one-family-out results, collision sensitivity, source-variant discrimination, confidence, and compute accounting.

Bootstrap replicates resample whole families with shared multiplicities across methods and contrasts. The pilot draws two families per replicate; the planned final design draws ten. There are 10,000 PCG64 replicates with seed 20261019 and linear 2.5th/97.5th percentiles. Undefined rates remain NA and intervals disclose the number of defined replicates. Unresolved truth is not a model error or abstention. Wrong-CWE vulnerable predictions are exact-label errors but can be true-positive alerts.

## Joint evidence review

- **Source preservation:** all seven imported upstream files and eight recorded transformation checks verify. Original logic, compiler treatments, support code, and private oracle remain unchanged.
- **Independent reproduction:** a separate workspace rebuilt 16 private references and 32 symbol derivatives. All binary bytes and private instruction evidence matched. Fresh Ghidra projects extracted all 32 bundles byte for byte. Raw commands and workspace paths are provenance, not claimed deterministic content. The [rebuild summary](../../redesign/provenance/phase7-rebuild.json) and [163-file archive](../../redesign/provenance/phase7-rebuild.tar.gz) preserve evidence.
- **Symbol treatment:** all 16 symbol pairs preserve code/data scope and lose meaningful developer names. No retained/stripped bundle pair is identical. Four exact-input collision groups span optimization cells; none conflicts in source or binary label. Fourteen code/data-scope equality groups are also disclosed.
- **Transformations and recovery:** at the reference-build level, 11 selected operations remain present, three are inlined/merged, and two are eliminated. All 32 binary labels are resolved and all 32 public extractions are available. Exact token eligibility is a separate six-observation limitation.
- **Baseline support:** all 32 saved v2 predictions replay from public bundles and archived P-code. Before the shared overlay, eight classifications are correct and 24 paths abstain. Every stack pilot path abstains. The independent 36-cell stack matrix previously produced 15 correct classifications, nine false negatives, and 12 abstentions. These known heuristic limitations remain disclosed; neither oracle capacities nor testcase-specific fixes are added.
- **Failures and compute:** the attempt statuses above are terminal. Complete responses, validation errors, finish reasons, usage, dispatch markers and requests are retained in the [full pilot archive](../../redesign/provenance/llm/phase7-pilot.tar.gz). Recorded LLM request elapsed time sums to 1284.197 seconds, with 207603 prompt tokens and 73392 completion tokens. This sum excludes orchestration/preflight overhead. Historical baseline lifting/prediction times are reported separately in JSON. LLM outputs are preserved, not claimed bitwise reproducible.
- **Adjudication:** Codex reviewed 16 references and assigned their 32 symbol-partner truths using source, emitted assembly and private DWARF. No independent human adjudicator was available. Review hours were not recorded. Localization assistance and model pretraining exposure remain limitations.

## Implementation and validation

`evaluate.py` is a private post-prediction join. Neither predictor receives labels or private bounds. It verifies the complete inventories and shared public input identities before scoring. `pilot_rebuild.py` performs isolated build/extraction and refuses an existing destination. `method_lock.py` creates an exclusive lock only after a complete, reproducible evaluation, independent reproduction, and test gates; it verifies hashes for methods and pilot evidence. It also binds the model/template/runtime binary and libraries, Python/dependency environment, selection contract, context/baseline policies, schemas, scoring, and missingness. A new final server PID requires new runtime evidence while preserving the locked computational configuration.

The Ghidra-enabled full suite passed **256 tests and 80 subtests, with no skips** in 488.22 seconds. Final targeted evaluation/lock checks passed **11 tests**, including four added after the full suite collected tests (260 distinct tests covered overall). The [test provenance](../../redesign/provenance/phase7-tests.json) records commands and test-source hashes. Checks cover exact-label versus alert arithmetic, common eligibility, zero denominators, matched missing predictions, family resampling, input collisions, incomplete-pilot rejection, artifact mutation, runtime identity, and immutable raw-attempt archives.

## Reproduction and next boundary

Verify the method lock and regenerate scoring without inference:

```bash
.venv/bin/python -m redesign.pipeline.method_lock verify
.venv/bin/python -m redesign.pipeline.evaluate --run-directory redesign/build/pilot/llm/phase6-a --check redesign/results/pilot/phase7-evaluation.json
```

The full pilot tar archive contains the run directory contents at its root and can be extracted into a fresh directory for offline verification/scoring. The Phase 6 partial archive remains unchanged. For an independent rebuild, select a new destination:

```bash
GHIDRA_HOME=/path/to/ghidra_12.1.4_PUBLIC .venv/bin/python -m redesign.pipeline.pilot_rebuild --destination /path/to/new-workspace
```

Method decisions are locked by the verified manifest; earlier hash-bound configuration files keep their historical pending markers. Phase 8 must review source-only eligibility and prior exposure, assign final families, prepare and adjudicate all cells, capture final runtime evidence, and freeze the complete final input inventory before either final predictor runs. The local lock timestamp and hashes are not an independent timestamped deposit or external preregistration.
