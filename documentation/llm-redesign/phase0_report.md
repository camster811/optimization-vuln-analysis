# Phase 0 — study design locked

November 21, 2026. Phase 0 is complete for design `representation-study-v1`, study
`llm-representation-v1` and initial configuration `representation-v1-context12288`.
This records the design before new study answers. Phases 1–10 remain pending.

## Deliverables

| Deliverable | Location |
|---|---|
| Dated analysis contract, decisions D01–D08 and dependency map | [analysis_plan.md](analysis_plan.md) |
| Initial recursive field allowlists, line references and response boundary | [representation_spec.md](representation_spec.md) |
| Initial machine-readable configuration | [policy.json](../../src/optimization_vuln_analysis/studies/representation/policy.json) |
| Implementation sequence and completion gates | [implementation_plan.md](implementation_plan.md) |

The design compares fresh `assembly`, `decompilation` and `combined` requests on
the same 160 observations. The primary contrast is combined minus decompilation
in exact correct/adjudicated rate. All methods retain the same adjudicated
denominator, including blocked inputs and failed predictions. The unconditional
`always_not_vulnerable` control remains available when LLM inputs are blocked.
Three repetitions per condition produce 1,440 final slots; the separate two-cell
smoke run has 18 engineering slots. No winner or accuracy threshold determines
acceptance.

The contract declares exploratory status and prior inspection of the corpus,
judgments, historical results and method failures. It fixes voting, terminal
failure handling, four-method metrics, shared family resampling, matched treatment
contrasts and deterministic disagreement-example selection. The representation
specification fixes shared data/closure, omitted fields and visible-line evidence.

The initial policy copies the parent's full 24-field sampler configuration and
llama.cpp settings. Its LLM settings differ from the parent only in schedule seed
20261121. Context remains 12,288, completion reservation 4,096, temperature 0.2,
top-p 0.95 and request timeout 600 seconds. The retained 8,192-token pilot policy
and all existing methods, data, judgments and historical releases were left unchanged.

## Gate evidence

The main comparison, full denominator, representation boundaries and resource
rules are specified. The decision record and dependency map identify what must
be reused and what needs local adaptation. No executable framework, new inference
request, view projection or result was created in this phase.

Offline policy/document checks passed: strict JSON, parent freeze/policy/archive
identities, complete inherited sampler/runtime settings, derived 80/160/480/1,440
counts, condition/control/contrast alignment, unconditional control, expected truth
totals, shared family resampling, nine-slot blocking, separate 18-slot pilot,
unbound execution identities, document links and whitespace. These are Phase 0
consistency checks, not Phase 1's complete per-file/oracle binding gate.

The existing regression suite passed **100 tests** with
`.venv/bin/python -m pytest -q`. It establishes the retained bundle, transport,
identity, voting, persistence, token-budget and metric contracts described in the
[cleanup record](cleanup_report.md). `git diff --check` passes. No new tests that
merely restate document text or configuration constants were added.

The checked Phase 0 content identities are:

| Artifact | SHA-256 |
|---|---|
| Analysis contract | `88fa2dec41ebfa75443d3f117b6dd9d87cb158687f54089611a7f1f21d9a805c` |
| Initial representation specification | `8d151b6f5f77cae20a3da9eb7ec5886dc47244020f5cfdef6247405c25b41c10` |
| Initial policy | `2db6fda625a827789f0d2cfba4f914b77fb4891145175d048c171b824dd6bf93` |

These hashes identify local content, not an independent timestamp or external
preregistration. Dated amendments must preserve the distinction.

## Remaining boundary

`execution_ready` is false. Actual model-file verification, server/library/source,
tokenizer/template identities, prompt/response schema, scorer, input/oracle/view
bindings and final dependency snapshots remain explicitly pending. Phase 0 does
not establish fit or runtime feasibility of the new views. Those must pass the
later preparation, pilot and freeze gates before final dispatch.

Next is Phase 1: bind the verified parent inputs, preserve opaque observation IDs,
stage public/private inputs separately and account for all 480 condition units and
1,440 unique slot identities without calling old predictors.
