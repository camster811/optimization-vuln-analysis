# Phase 5 stack heuristic revision

October 20, 2026. Revision `ghidra-inferred-stack-bounds-v2` replaces the development v1 baseline before method lock. The [specification](baseline_spec.md) now explicitly permits inferred stack bounds and imperfect classifications. Method lock remains pending. Sources, build treatments, public bundles, private oracle reviews, final assignments and model settings are unchanged.

## Implementation

The public-only lifter exports recovered stack symbols using Ghidra's local-symbol/storage API: signed entry-SP-relative offsets, lengths, array kinds and storage-lifetime information. These are inferred extents, not source/DWARF object capacities. No source-shaped decompilation text, variable names or testcase-specific summaries choose bounds.

The evaluator preserves stack invocation and recovered-variable identities through constant offsets and direct caller/helper arguments. Constant copies, direct stores and compiler-inlined stores compare their extents with the inferred array. Eleven bytes into an inferred ten-byte array produce CWE-121 with `inferred_stack_object_extent`; a one-byte overflow need not reach a saved frame or return address. Each check records its bound basis, original stack-object offset, relative destination offset, size and capacity. Missing arrays, overlapping/reused variables, unresolved offsets and unsupported paths abstain. Recovered scalar slots account only for wholly contained scalar writes and cannot produce CWE-121.

The native-write guard remains. A narrow instruction-P-code projection restores erased stores only when stack-relative destinations, complete native write extents and placement within the high CFG are recoverable. It propagates constants and affine stack offsets, without decoding x86 mnemonics or rebuilding the historical simulator. Raw loads invalidate projection facts; flags, branches, loads, memory aliasing and call arguments are not solved by the fallback. Restored stores still undergo the ordinary bounds/permission checks and carry `instruction_pcode_store_fallback`. Partial coverage, unknown destinations, ambiguous placement and unsupported recovery retain the guard.

Result and IR envelopes are schema 2; the policy retains its schema-1 representation and has a new method identifier. [baseline-result-v2.json](../../redesign/schemas/baseline-result-v2.json) distinguishes inferred-array outcomes from allocation-request outcomes. Library contracts and resource limits otherwise remain unchanged. The earlier read-only-write and overlapping-data-window regressions remain covered.

## Independent O0–O3 evaluation

The [36-cell fixture artifact](../../redesign/provenance/phase5-v2-stack-fixtures.json) records source truth, recovered variables, every prediction/check, input/IR hashes and final method identities. Nine development cases run at each optimization: safe/overflowing copies, a one-byte padding overflow, safe/overflowing optimized stores, ambiguous pointer selection, an infeasible write, and safe/overflowing copies with an adjacent recovered scalar field. Every fixture removes original source and ELF paths before baseline lifting. All saved IR was re-evaluated with the final method.

| Fixture group | O0 | O1–O3 |
|---|---|---|
| Safe copy and safe stores | Abstain | Correct no-overflow |
| Unanchored overflowing copy, padding byte and optimized stores | Abstain | False negative: inferred array includes padding |
| Ambiguous pointer selection between safe arrays | Abstain | Abstain |
| Infeasible write | Abstain | Correct no-overflow |
| Adjacent-field safe copy | Abstain | Correct no-overflow |
| Adjacent-field overflowing copy | Abstain | Correct CWE-121 |

Across 36 cells, 24 are classified and twelve abstain. Fifteen classifications match fixture truth: three CWE-121 and twelve no-overflow. Nine false negatives remain; no false positives occurred in these fixtures. In those missed cases Ghidra recovers eighteen bytes for a ten-byte source array, absorbing padding. The method uses that estimate as specified rather than substituting the private/source capacity. O0 retains parameter spills with no recovered local extent and abstains explicitly. These are measured weaknesses of the comparator, not repaired or excluded cases.

Independent IR fixtures additionally require exact behavior for ten-byte inferred bounds versus ten/eleven-byte writes, original pointer identity at one-past-end, caller/callee writes, missing/nonarray extents, overlapping variables, reused storage, unknown offsets, infeasible/unknown branches, erased-store fallback, unestablished stack reads and raw-load invalidation. These establish the rule's behavior separately from Ghidra's sometimes incorrect recovery.

## Unchanged private pilot oracle comparison

Preparation run: `phase5-v2-lift-a`. Accepted prediction run: `phase5-v2-c`. All 32 cells complete, with four CWE-122 predictions, four no-overflow predictions and 24 abstentions. All eight classifications match the unchanged private binary oracle. Every pilot decision matches v1, although checks, annotations, representations and abstention reasons differ. The sixteen stack pilot observations still abstain: twelve for missing array extents and four for unsupported P-code. This revision does not claim improved stack pilot accuracy.

Native-write-guard abstentions decrease from twenty to four. Sixteen observations now contain inferred-array checks and instruction-P-code fallback annotations; later unsupported recovery still prevents classification. The remaining heap abstentions comprise four unmatched native-write cases and four cyclic paths. The [validation artifact](../../redesign/provenance/phase5-validation.json) reports the oracle/prediction confusion counts and classified disagreements explicitly, with abstentions retained in the denominator.

Preparation took about 70.52 seconds; accepted prediction dispatch/evaluation took about 1.30 seconds. These are local development times, excluding validation, not final-run forecasts.

## Preservation and reproduction

The [development history](../../redesign/provenance/phase5-development-history.json) retains every attempt. V1 code, policy, schemas and replay artifacts are preserved under `redesign/provenance/baseline-v1-method/`, with source hashes. Earlier published results are unchanged. V2 development attempts `phase5-v2-a` and `phase5-v2-b` remain separate, with the superseded sources needed to identify those methods; all three v2 prediction files have identical bytes. Final replay contains all 32 public-input IR exports in an approximately 84 KB deterministic archive.

```bash
# Verify materialized v2 preparation/predictions and post-inference oracle reporting:
.venv/bin/python -m redesign.pipeline.baseline verify --run-id phase5-v2-c
.venv/bin/python -m redesign.pipeline.baseline audit --run-id phase5-v2-c
# Replay either accepted revision without Ghidra, original binaries or private oracle:
.venv/bin/python -m redesign.pipeline.baseline_snapshot verify
.venv/bin/python -m redesign.pipeline.baseline_history
```

For a fresh preparation, set `GHIDRA_HOME` to the pinned Ghidra 12.1.4 installation, run `baseline lift` with a new ID, then `baseline predict --lift-run <new-id> --run-id <new-prediction-id> --write`. Existing run directories and published outputs remain protected.

Validation: all **219 tests and 80 subtests** pass with Ghidra enabled, including 36 new real stack fixtures and the eleven existing real baseline fixtures. Final-method replay rechecks all 47 real fixtures; v1 and v2 each replay all 32 pilots. Source preservation, sixteen reference builds, Phase 4 repeat/scope/coverage gates and historical provenance still verify. `git diff --check` passes.
