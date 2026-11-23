# Baseline strengthening: implementation and testing plan

Prepared October 21, 2026. This is a plan for a supplementary study after Phase 9, not an amendment to the completed campaign's results or a claim that the work below has run.

## Objective and recommendation

Implement two tracks in order:

1. Preserve the completed experiment, narrow its claims, and add transparent constant-prediction controls.
2. Implement one bounded analyzer revision addressing five generic missing library contracts, then measure its incremental coverage, errors, and implementation cost.

Complete Track A regardless of Track B's outcome. Keep the original baseline and LLM results as the primary historical experiment. Report Track B as a separately versioned post-hoc extension. Do not replace the original baseline in the existing tables or describe the revised comparison as prospectively locked before final-answer inspection.

A successful revision needs defensible, tested behavior on its stated support boundary. It does not need perfect accuracy. Runtime failures, guesses from private bounds, or silently skipped effects are not acceptable ways to increase coverage.

## Starting evidence

The accepted campaign is `redesign/campaigns/final-v2-context12288`, execution `phase9-a`.

| Method or descriptive control | Correct | Incorrect | Abstained | Unavailable |
|---|---:|---:|---:|---:|
| Saved LLM aggregate | 125 | 28 | 7 | 0 |
| Saved v2 baseline | 18 | 0 | 142 | 0 |
| Constant no-overflow control | 100 | 60 | 0 | 0 |

The constant no-overflow control has 62.5% exact-label correctness and zero vulnerability recall. The saved LLM is 15.625 percentage points above it. These control values are arithmetic expectations to verify during Track A, not newly executed predictions.

All 18 existing baseline classifications are safe, eliminated-operation cells. Important abstention reasons include unsupported library contracts, unmatched native writes, missing stack-array extents, and cyclic control flow. Reason codes may overlap and must not be summed as distinct observations.

A read-only census of the 160 public bundles found these external APIs absent from the current policy:

| API | Observations containing the external API |
|---|---:|
| `wmemset` | 48 |
| `wprintf` | 48 |
| `wcscpy` | 16 |
| `strcat` | 8 |
| `wcslen` | 4 |

Counts are presence counts, can overlap, and do not establish the first blocking operation or promise a coverage gain. This census used public inputs, not oracle labels. Final-result inspection has nevertheless already occurred, so the extension remains post-hoc.

## Preservation and isolation

- Verify the existing method lock, amended input freeze, execution, analysis, and results package before starting. Save their hashes in a new extension manifest.
- Leave all locked methods, configurations, source selections, oracle reviews, public records, raw attempts, archives, and Phase 9 outputs unchanged. In particular, do not edit the locked `bounds.py`, `baseline_policy.json`, `evaluate.py`, or baseline result schema in place.
- Put new implementation under `redesign/extensions/baseline_study/`, with an isolated `baseline_v3/` package and versioned policy/schema. Reuse unchanged validators and scoring through explicit imports; version the small set of affected engine/worker files where extension is impractical. Avoid global monkeypatching or a general plugin-framework refactor.
- Put generated work under `redesign/build/extensions/baseline-study/` and publish a separate release under `redesign/experiments/baseline-strengthening-v1/`. Refuse existing run IDs and differing existing publications.
- Predictor workers receive only public bundles and generic policies. Join private truth, source provenance, and saved LLM outputs afterward in the evaluator process.
- Do not run new LLM requests. Reuse the 480 saved attempts and their unchanged aggregation.
- Do not modify the ten families, build flags, extraction scope, token eligibility, or source programs to accommodate the extension.

## Track A: claims and trivial controls

### A1. Define deterministic controls

Implement pure prediction functions for four constant labels: `not_vulnerable`, `vulnerable_CWE-121`, `vulnerable_CWE-122`, and `uncertain`.

Use the same shared eligibility as the saved methods. Unavailable context yields unavailable status. Otherwise the first three controls always classify and the fourth always abstains. A control must not inspect labels, source names, family IDs, treatment IDs, class proportions, or neighboring predictions. It has no invented instruction evidence, confidence, or three-slot voting record; identify it explicitly as an uninformative control.

Lead the supplementary report with the constant no-overflow control. Publishing the other fixed-label controls makes their behavior transparent without choosing a favorable constant from final labels. Do not present an oracle-selected majority-class rule as a trained deployable model.

### A2. Add supplementary scoring

Create a thin comparison adapter around the frozen metric and family-bootstrap definitions. Preserve 10,000 PCG64 replicates, seed 20261019, shared family multiplicities, exact-label correctness, alert scoring, missingness, and NA rules. Keep output method identifiers explicit when adapting the existing two-method evaluator.

Report, for the LLM, original baseline, and controls:

- C/E/U/M counts, correct/adjudicated rate, coverage, selective accuracy, and common-input results.
- Alert TP/TN/FP/FN, recall, false-positive rate, precision, F1, and balanced accuracy.
- Actual-binary-class, source-CWE, optimization, symbol-condition, and family breakdowns.
- Paired LLM-minus-control correct-rate differences with family-cluster intervals; descriptive results remain supplementary.
- Binary-truth scoring separately from source-label recovery.

Reproduce the original 125/28/7/0 and 18/0/142/0 partitions before trusting any added table. Expected constant-control correct counts on this corpus are 100, 28, and 32 for no-overflow, CWE-121, and CWE-122 respectively. The always-uncertain control has 160 abstentions. Zero-denominator precision or selective accuracy is NA, not zero or one.

### A3. Revise claim language in a new supplement

Retain the original report as historical evidence. Write a new claim/limitations note and proposed manuscript wording:

- Supported: this configured LLM recognized more adjudicated behaviors than this bounded custom heuristic on these ten Juliet-derived families.
- Supported: quantify the gain over fixed controls, detection/error tradeoffs, and treatment-specific patterns.
- Unsupported: superiority over static analysis generally, a sound safety detector, or generalization to arbitrary production binaries.

Explain that original baseline abstention is neither an incorrect explicit label nor a safety conclusion. Explain that safe-only correctness can be high under the observed binary class imbalance. Keep the known oracle/adjudication, localization, template similarity, pretraining exposure, and small-family limitations.

### A4. Tests and acceptance

Use independent small fixtures for exact CWE versus alert scoring, unknown truth, shared unavailability, always-abstain output, and empty denominators. Test that adding or changing private labels cannot change a control prediction. Compare integer recounts with evaluator counts. Validate paired family resampling with hand-checkable two-family examples.

Track A passes when all controls have the exact declared inventory, historical scores reproduce, supplementary outputs regenerate byte for byte, and all original artifact hashes still verify. It requires no model server or new lifting.

## Track B: one bounded library-contract revision

### B1. Declare the revision before corpus evaluation

Use method ID `ghidra-library-contract-bounds-v3` and a separate result/policy version. Freeze a short specification of supported signatures, units, return values, read/write effects, and abstention reasons before running this revision on the 160 observations.

Scope the first revision to the five APIs in the public census. Retain the v2 stack-array heuristic and existing native-store fallback unchanged, including their qualifications and known errors. Keep engine/ABI, allocation outcomes, feasibility checks, step/path/call-depth limits, native-write coverage guard, and no-retry behavior unchanged.

Do not add loop induction, a symbolic solver, alias analysis, instruction decoding, new stack-size guesses, testcase-specific summaries, or a new engine in this revision. Do not expand the five-API scope merely because later corpus evaluation reveals another blocker.

### B2. Implement the five contracts

| API | Bounded behavior |
|---|---|
| `wmemset` | Constant element count; write repeated 32-bit wide-character values; validate destination and the entire byte footprint before updating memory; return destination. |
| `wcslen` | Scan known, readable four-byte wide elements to a zero element within the byte budget; return an element count; otherwise abstain. |
| `wcscpy` | Establish a readable terminated wide source; copy all elements including the terminator; check `(length + 1) * 4` destination bytes; return destination. |
| `strcat` | Establish a readable terminated destination prefix and source; append source plus terminator at the prefix length, preserving the original destination-object identity; reject unsupported overlap; return the original destination. |
| `wprintf` | Support only explicitly documented constant formats and recovered argument types/counts. For supported wide-string conversions, establish readable termination of the corresponding argument. Model no selected application-memory writes; keep the return value unknown. Reject `%n`, dynamic/positional formats, unsupported conversions, or unrecovered arguments. |

The fixed Linux x86-64 treatment uses four-byte `wchar_t`. Validate that assumption against the pinned target and use explicitly four-byte Ghidra prototype types where needed; do not assume the analysis host's wide-character width. Centralize checked element-to-byte conversion and byte-budget enforcement. A zero-valued byte is not necessarily a zero wide character.

Keep existing allocation-failure branches and read-only-write protection. Preserve source-readability, lifetime, overlap, and permission checks before claiming a feasible write. Unknown values may remain unknown when an operation does not need them; do not manufacture known bytes or termination. Record inferred stack bounds separately from allocation-request bounds.

For `wprintf`, first enumerate the literal formats present in public development inputs, then document a small standard-format subset. Do not special-case application names such as `printWLine`. An application wrapper is analyzed through its body. If argument recovery cannot support the declared contract, abstain rather than broadening the contract to ignore effects.

### B3. Test semantics before Ghidra integration

Add unit fixtures covering:

- Safe, exact-boundary, and one-element overflow writes; terminators are included where the API writes them.
- Four-byte element counts versus byte counts, zero count, negative/oversized represented counts, arithmetic overflow, and resource limits.
- Wide values containing zero bytes but not a zero element; unknown/missing terminators and reads crossing available storage.
- Heap and inferred stack destinations, pointer offsets, one-past-end identity, and caller/helper argument flow.
- Read-only static destinations, unknown capacities, freed allocations, dangling frames, and overlapping data windows.
- Concatenation with an existing prefix, empty strings, exact fit, overflowing append, unknown prefix, and overlapping source/destination.
- Supported wide-output formats, invalid argument count, `%n`, unsupported formats, and unknown string arguments.
- A faulting/unsupported operation before a potential overflow; an established witness before a later unsupported operation.

Preserve the existing permission, overlap, feasibility, stack-recovery, native-write, and arithmetic regressions. Tests should check externally meaningful contract behavior and failure boundaries, not mirror implementation helpers.

### B4. Verify independent compiled fixtures

Use independent source fixtures outside the research corpus, with truth recorded separately from predictor input. Include safe and overflowing wide fills/copies, concatenation with a nonempty prefix, wide-output wrappers, ambiguous capacities, and cross-function argument passing.

Start with representative O0/O2 retained/stripped checks to expose signature/ABI issues cheaply. After those pass, run the declared fixture matrix across O0–O3 and both symbol treatments. Include contract-forcing fixtures with builtins disabled, and ordinary-optimization fixtures without those flags. Disclose fixture-only flags; never alter campaign flags.

Require a real safe/overflow distinction on supported heap fixtures. For stack fixtures, record recovered extents and retain measured heuristic errors rather than forcing every source overflow to be detected. As in earlier tests, remove original source/ELF paths before public-only lifting. Test repeat lifting for deterministic IR and predictions where claimed.

If signature or argument recovery makes a contract impractical, document that support limit and leave it unsupported. Do not turn this work into a general interpreter to force a result.

### B5. Freeze, then perform one complete post-hoc evaluation

After fixture validation, freeze v3 code, policy, prototypes, tests, environment identities, and a deterministic schedule. Run all 160 public observations under a new run ID. Relift all available observations because new external signatures can change parameter recovery and high P-code. Do not reinterpret old IR as if it had been produced under the new contracts.

Use the existing 12,288-token shared eligibility and unchanged bundles. Dispatch workers with no private labels or oracle paths. Preserve inputs, IR, raw worker output, timings, failures, hashes, and all planned cells. Resume only never-dispatched work; preserve terminal failures. Do not run new LLM requests.

Only after predictions are durable, join the private oracle and compare v3 with v2 and the saved LLM:

- New classifications, remaining abstentions, runtime failures, correct gains, new errors, and corrected errors.
- Vulnerability recall and false-positive rate, not coverage alone. Separate gained safe classifications from gained vulnerability detections.
- Per-API/support reasons, CWE, optimization, symbol, and family results; overlapping reason counts remain explicit.
- Paired rate differences with the same family-bootstrap rules and complete denominators.
- Source-label recovery and input-collision sensitivity remain secondary.
- Runtime, added production code, new contracts, regression burden, and reproducibility cost.

If final-corpus results motivate another code change, preserve v3 and declare a new revision/run. Never combine results produced under different implementations. Both evaluations on these inspected families remain post-hoc; stronger prospective validation needs additional held-out families.

### B6. Ablation and complexity decision

Use one unchanged lifting representation for evaluator-only ablations when the prototypes stay identical: v3 with the added wide-memory/string effects disabled, and v3 with the added wide-output effect disabled. These measure the marginal effect of those contracts under a common recovered IR. They are not equivalent to the old v2 lifter; the preserved v2 run remains the actual v2 comparison.

Do not change lifting prototypes between an enabled/disabled evaluator comparison without relifting and labeling that as a separate representation comparison. Preserve unsupported effects as abstentions in every ablation.

Keep v3 as an additional useful comparator if it provides correct supported behavior across independent fixtures and a material, explainable coverage/detection gain at modest maintenance cost. A gain confined to safe eliminated cases is weaker evidence of a stronger detector. If coverage stays similar, errors offset the benefit, or implementation expands beyond standard contracts, retain the experiment as a documented negative result and stop expansion.

No outcome threshold on the already inspected final corpus is a confirmatory acceptance test. Complexity decisions and accuracy observations are descriptive engineering judgments.

## Deliverables and checkpoints

| Checkpoint | Deliverables | Proceed when |
|---|---|---|
| A | Constant controls, supplementary metrics, claim note, regression tests | Historical results and all control counts reproduce; original hashes verify. |
| B1 | v3 specification and five-contract scope | Units, prototypes, unsupported cases, and limits are explicit. |
| B2 | Isolated implementation and independent fixture report | Contract/ABI tests pass; known stack-recovery errors are disclosed; no private-input dependence. |
| B3 | Complete v3 run, archived IR/results, ablations and comparison report | All 160 cells are accounted for and predictions replay; failures remain visible. |
| Closeout | Complexity/benefit decision and deterministic supplementary release | Archive restore regenerates results/tables; original campaign and method lock still verify. |

Suggested supplementary release contents: `study-plan.md`, `study-manifest.json`, `claims.md`, control predictions, original-input/result hash references, v3 method snapshot, fixture provenance, public-input hashes, IR/results, comparison JSON/CSV, test evidence, and a private results archive with exact membership/digest verification. Keep private truth out of worker directories and public predictor inputs.

## Estimated effort and stop points

- Track A: approximately one focused working day, including scoring checks and writing.
- Track B specification/implementation: approximately two to three focused working days.
- Fixture integration, complete post-hoc run, ablations, and packaging: approximately one to two additional days. Argument recovery can extend this estimate.

Review scope after roughly two days of Track B implementation. If progress requires solver work, new stack-layout inference, or broad native-P-code emulation, stop that expansion and complete the supported-contract evaluation. Track A remains independently useful if Track B is discontinued.

The plan authorizes no edits to the historical campaign. Implementation, analyzer execution, and publication of new supplementary results are subsequent work items; this document records their proposed scope and verification gates.
