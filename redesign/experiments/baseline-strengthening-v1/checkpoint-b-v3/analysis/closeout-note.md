# Baseline strengthening: checkpoint B complete

Checkpoint B implements and evaluates the declared bounded library revision as a separate post-hoc study. The outcome is negative on the inspected final corpus: **v3 produces the same 18 correct classifications and 142 abstentions as v2, with no errors or unavailable cells**. No stronger-detector claim is supported. Preserve the revision as a documented negative engineering result and stop expansion at the five contracts; do not add a solver, new stack guesses or new corpus-specific rules to force coverage.

The publication is `redesign/experiments/baseline-strengthening-v1/checkpoint-b-v3/`, containing `analysis/comparison.json`, `analysis/comparison.csv`, `analysis/report.md`, `analysis/decision.md`, `analysis/independent-audit.json`, all 160 public inputs/new IR/results/ablations, fixture evidence, policy/schema/specification, source/test snapshots, and a content-addressed archive with detached `release.json`. The completed Phase 9 experiment and Checkpoint A remain unchanged.

## B1: declared scope and preservation

Method `ghidra-library-contract-bounds-v3` adds only `wmemset`, `wcslen`, `wcscpy`, `strcat` and a restricted `wprintf` contract. Wide elements are explicitly four bytes in policy/prototypes, with compiler macros validating wchar_t/int = 4 and pointers/long = 8 on the pinned Linux x86-64 GCC target. Integer/byte conversion, full footprints, terminators, source readability, lifetime, permissions and overlap checks are bounded and tested. Unknown bytes/terminators remain unknown. `%n`, dynamic/positional formats and undeclared conversions abstain.

The v2 interpreter, stack-array heuristic, native-store fallback, allocation failure paths, control-flow/resource limits and witness ordering are inherited. The existing public-only Ghidra lifter is unchanged; its policy-supplied prototypes differ. No application wrapper names, private capacities or oracle labels enter workers. Original methods, configurations, source selections, oracle, extraction scope, shared context eligibility, raw attempts and historical releases are preserved. No new LLM requests ran.

The new code, policy, schema, specification, imported methods, Python/compiler/Ghidra identities, tests, fixture inventory and deterministic 160-cell schedule were frozen at `2026-10-21T18:56:44.407564+00:00`, before new corpus predictions. Freeze SHA-256: `116383b8a3dc1055844a1885d14e89b18abeeb2c46c8e0427207a1e9241d9cdf`. No v3 code or policy was changed after that freeze or after inspecting its corpus predictions.

## B2: semantic and independent compiled verification

The semantic/regression gate passed **106 tests without failures/errors/skips**, covering all five effects and existing bounds, stack, control-scoring and closeout regressions. New cases include exact fit/overflow, zero/unknown values, four-byte versus byte termination, invalid/oversized counts, resource boundaries, pointer offsets and one-past-end identity, caller/helper flow, read-only/overlapping windows, freed/dangling objects, unknown termination, concatenation prefixes/overlap, supported/rejected output formats and argument counts, earlier unsupported effects versus established witnesses, typed result validation and durable no-retry recovery.

After a 20-observation O0/O2 smoke check, the accepted independent matrix contains **176 observations**: eleven fixture cases × O0–O3 × retained/stripped × ordinary/contract-forcing builds. Fixtures cover heap fills, wcslen-derived counts, copies, concatenation with a nonempty prefix, output wrappers, unknown capacity and an anchored stack overflow. The required 16 O2 contract-forcing heap cells correctly distinguish safe and overflowing writes. A fresh repeat of public-only lifting/prediction reproduces identical IR/results.

The full matrix has 54 safe classifications, 42 heap-vulnerable classifications, 12 stack-vulnerable classifications and 68 abstentions. There are no incorrect classifications against the declared fixture behaviors; unknown-capacity fixture truth remains unresolved. O0 parameter-spill/stack recovery and ordinary-build unmatched writes remain explicit support limits. All sixteen stack fixtures retain their recovered extents: four O0 abstentions and twelve optimized overflow detections. These anchored fixtures do not erase the inherited heuristic's previously documented padding-related false negatives.

Fixture-only `-fno-builtin`, a volatile neighboring stack scalar, and literal padding are disclosed. Early extraction probes hit the unchanged 16-byte unknown-data window at an ELF section boundary; independent literal padding fixed fixture availability without changing the copied string. Earlier failed smoke directories remain preserved. No research source or extraction budget was changed. Original source/ELF paths were removed before public-only lifting; source/declared truth remain separate fixture provenance.

## B3: one complete frozen corpus run and same-IR ablations

All **160 new worker jobs complete without runtime failures**. Every available bundle was relifted under v3 prototypes, rather than reusing v2 IR. Exactly 56 IR digests differ from v2; the other 104 were independently regenerated identically. Raw worker commands/input hashes, policy, lifting traces, result schema and IR bindings verify, and all dispatches postdate the freeze. Dispatch times range from `18:57:06` to `19:02:26` UTC on October 21. Recorded worker time totals 645.77 seconds, including fresh lifting and evaluator ablations; two workers ran concurrently, so this is not elapsed session time.

Private truth and saved LLM outputs were joined only after all new predictions were durable. Every new result regenerates from saved v3 IR. The two ablations disable the new memory/string effects or new wide-output effect on that identical IR/prototype representation; disabled effects abstain. Neither ablation is equivalent to the old v2 lifter.

| Method | Correct | Incorrect | Abstain | Unavailable | Correct / 160 | Coverage | Vulnerability recall | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| v3 | 18 | 0 | 142 | 0 | 11.25% | 11.25% | 0% | 0% |
| Original v2 | 18 | 0 | 142 | 0 | 11.25% | 11.25% | 0% | 0% |
| Without new memory/string effects | 18 | 0 | 142 | 0 | 11.25% | 11.25% | 0% | 0% |
| Without new wide-output effect | 18 | 0 | 142 | 0 | 11.25% | 11.25% | 0% | 0% |
| Saved LLM | 125 | 28 | 7 | 0 | 78.125% | 95.625% | 65% | 7% |
| Constant no overflow | 100 | 60 | 0 | 0 | 62.5% | 100% | 0% | 0% |

V3, v2 and both ablations have identical decisions/statuses on every cell. There are zero new classifications, correct gains, corrected errors or new errors. All 18 classifications remain safe eliminated-operation cells; 100% selective accuracy on them is not evidence of a useful vulnerability detector. All 60 actually vulnerable binary cells remain abstentions.

The v3-minus-v2 correct-rate difference is zero with interval [0, 0]; full-minus-ablation differences are also zero on every cell. These are descriptive equalities on this matrix, not population equivalence results. Saved-LLM-minus-v3 correct rate remains 66.875 percentage points, exploratory interval [54.375, 78.75]. Comparisons use the unchanged metric definitions, 10,000 shared PCG64 family-cluster draws, seed 20261019, complete denominators and NA rules.

Source-label recovery remains separate: v3 and v2 each have C/E/U/M = 12/6/142/0. Common-input, CWE, optimization, symbol, family, actual binary class, operation and API breakdowns and input-collision sensitivity are saved with alert metrics and paired intervals. API/reason counts overlap. By optimization, v3 has C/U = 0/40 at O0 and 6/34 at each optimized level; retained and stripped each have C/U = 9/71. Source-CWE stack/heap counts are 6/74 and 12/68.

## Why the added contracts did not improve final coverage

The five contracts work on their independent supported fixtures but do not remove the other blockers in this corpus. V3 reasons include unaccounted native writes (48 observations), missing stack extents (24), cyclic flow (18), unknown contract sources (24), unresolved stack offsets (12), unsupported P-code (4), unknown destinations (4), unknown copy sources (4) and unknown narrow-string extents (4). The old `unsupported_library_call` reason disappears, but it is replaced by deeper support failures rather than classifications. Reason/assumption counts are not mutually exclusive.

The contract event audit records 40 completed wmemset events, twelve wcscpy events stopping on unknown sources and twelve wprintf events stopping on unknown sources. No wcslen/strcat event is reached on these corpus paths. Presence of an API in a bundle is not evidence that interpretation reaches it.

Two concrete public-evidence examples explain the conservative stops:

- `r726e476c1a9bdcb4ce362124`, O1 retained: Ghidra recovers the source as a 396-byte `uint[99]` array plus a separate four-byte scalar terminator. The wide-copy contract cannot read the scalar as though it were inside the inferred array. The revision does not merge objects or import the source's real capacity, so it abstains.
- `r561722891cdf3eed09079a67`, O1 retained: the exported format window is 16 bytes, containing the four wide characters `%ls` and newline, without the following four-byte NUL. Wprintf cannot establish the complete format under the fixed public window and abstains. It would be unsafe to assume an omitted suffix or silently ignore potential format effects.

The new prototypes change some recovered IR and remove two native-write guard blockers, but these changes do not produce additional final decisions. Identical ablation classifications therefore mean zero marginal prediction gain under this fixed v3 representation; they do not mean the library effects are universally irrelevant.

## Complexity and decision

The added engine is 141 Python lines, and the worker/schema adapter is 61. Including execution, comparison, release handling and package initialization, added production Python totals 670 lines; independent fixture tooling adds 116. Five contracts and their prototypes, tests and 176-cell fixture matrix add maintenance/reproducibility cost. Modified historical lines and new lifter-Java lines are zero; the 531-line interpreter and 116-line stack helper are reused.

This revision has supported independent behavior but **no incremental final-corpus coverage or detection benefit**. Do not promote it as the stronger comparator sought by the study. Retain its frozen inputs, outputs and negative result; stop expansion as the plan directs. Any further attempt requiring new stack recovery, solver/loop analysis or representation changes is a new method, and meaningful prospective evidence requires additional held-out families. No numerical outcome threshold on these already inspected families is a confirmatory acceptance test.

The original limits remain: ten similar Juliet families, private-assisted localization, incomplete heuristic stack bounds, no independent human oracle adjudication, possible pretraining exposure and one toolchain/platform. The study is post-hoc. It does not establish sound safety detection, superiority over static analysis generally, or production-binary generalization.

## Reproduce and preserve

```bash
# Offline IR/result/table replay; no new LLM requests or Ghidra lifting.
.venv/bin/python -m redesign.extensions.baseline_study.baseline_v3.campaign verify
MPLCONFIGDIR=/tmp/juliet-baseline-study-matplotlib \
  .venv/bin/python -m redesign.extensions.baseline_study.baseline_v3.release verify
```

Keep `checkpoint-b.tar.gz` and its detached `release.json` together. A fresh restore with `release verify --directory /path/to/restored` verifies exact archive membership/content, source/environment bindings, all saved predictions/ablations and regenerated comparison bytes. Imported repository methods and the original campaign/Checkpoint A remain dependencies. The archive includes private evaluation truth separately from worker inputs.
