# Phase 5: bounded static baseline v1

Historical v1 report. The October 20 [stack heuristic revision](phase5_stack_revision.md) supersedes this method before lock; its contract is preserved in [baseline_spec_v1.md](baseline_spec_v1.md).

Implemented October 19, 2026, following the [Phase 5 implementation plan](phase5_implementation_plan.md). The [baseline specification](baseline_spec_v1.md) publishes the engine, rules, library contracts, limits, reason codes and support boundary. No LLM or final predictions ran. Experimental sources, build configuration, oracle reviews and public bundles remain unchanged.

## Base-repository review and reuse

The predecessor `pipeline/static_baseline.py` was reviewed with its schema, ABI, path-feasibility and write-bound regressions. Its core is a single-function x86 interpreter, with historical observation IDs, a flat record schema and a saved-frame-overlap stack rule. Porting it would retain the instruction-simulator architecture the redesign explicitly replaces and would not establish the new stack-object endpoint. It remains unchanged and covered by the existing regression suite.

| Component | Decision |
|---|---|
| Strict JSON, hashes, declared matrix and record-inventory checks | Reused from `redesign.pipeline.inventory`; no discovered-file or fixed-count shortcut |
| Public schema, canonicalization, shared budget and cross-function evidence checks | Reused from `bundles.py` |
| Pinned Ghidra launcher/version and environment identity | Reused from `context_worker.engine_home` and `export_context.engine_identity` |
| Decompiler lifecycle and cleanup | Reused the established Ghidra integration pattern, with a new public-image/high-P-code exporter |
| Constant allocation/offset identity and write-time feasibility principles | Adapted the predecessor's useful invariants, with independent regression fixtures and Ghidra SSA rather than register/operand parsing |
| Deterministic gzip/tar provenance | Reused the recipe in `provenance.capture` for the small IR replay archive |
| Historical schema/IDs, x86 simulator, frame-capacity heuristic, root configuration and corpus assumptions | Excluded from the redesigned analyzer |

## Engine decision and verification

Ghidra 12.1.4 recovers the required pointer arguments across independent caller/callee translation units. Real fixtures distinguish a twelve-byte write into an eight-byte allocation from the same write into a sixteen-byte allocation. They also exercise library-copy contracts, multiple distinct allocations, unknown capacities, unsupported calls, eliminated infeasible writes and `%n` rejection. A read-only-write fixture faults with SIGSEGV before reaching the overflowing helper and now abstains with `static_write_not_writable`. A writable-data fixture with matching overlapping windows completes analysis and retains its feasible heap-overflow witness. Original source and ELF paths are removed from these fixtures before baseline lifting, demonstrating that reconstruction uses the public bundle alone. A repeated fresh reconstruction produces identical IR and predictions. Unit fixtures cover concrete/infeasible versus unknown branches, unknown stack bounds, multiple object identities, loops/resource limits, pointer truncation, integer widths, large offset products and erased native writes.

The plan calls for an angr comparison if Ghidra argument propagation proves impractical. It did not: direct argument recovery works on these fixtures without testcase-specific summaries. Ghidra is therefore the selected development engine, and no alternative engine was installed or selected using final accuracy. The implementation remains intentionally small in scope: constant values/offsets and acyclic paths, with abstention for general aliasing, loops or unresolved behavior. It does not attempt a general interprocedural abstract interpreter to force pilot coverage.

The new lifter reconstructs only public instruction/data bytes in a fresh program, uses fixed external signatures/adapters and exports high P-code. It does not receive the original ELF or source/debug/oracle evidence. A native-write inventory checks that high-level decompiler transformations cannot silently erase writes before a classification. Function parameters and machine widths are recovery facts; inferred arrays, frame sizes and data-window extents are not allocation capacities. Both allocation success and failure paths are modeled, and only concrete branch outcomes can support a witness.

## Pilot results

Accepted preparation run: `phase5-lift-b`. Accepted prediction run: `phase5-d`. Every declared pilot cell is preserved. All 32 bundles lifted successfully and all 32 analyzer workers completed; there were no input-unavailable or runtime-failed observations. Results regenerate exactly from the saved public-input IR.

| Outcome | Observations |
|---|---:|
| Definite CWE-122 overflow | 4 |
| No selected overflow after complete supported accounting | 4 |
| Abstention | 24 |
| Unavailable / runtime failed | 0 / 0 |

The eight definite classifications agree with the existing private binary oracle. This is a development feasibility check on two families, not final accuracy or independent effect-size evidence. Definite results cover the heap pilot's two variants at O2/O3, under both symbol treatments. O0/O1 remain abstentions. The compiled no-overflow decisions cover the heap-safe cases whose selected allocation/write was eliminated, following their remaining complete diagnostic path.

Twenty observations abstain because native writes do not have a complete supported high-P-code representation; four abstain on cyclic control flow. The native-write guard applies to both positive and safe decisions. All sixteen stack observations abstain: this implementation has no defensible binary-only stack-object capacity rule and does not guess one from the source-shaped decompiler output or reserved frame space. The coverage denominator remains 32, with eight classified and 24 abstained. No cases were repaired, replaced or excluded because of those outcomes.

The baseline's supported fixtures pass its Phase 5 engineering gate. Its limited stack coverage and cyclic-path support must be reviewed at Phase 7 before choosing the final locked method. If that coverage is inadequate for the substantive comparison, the engine/method or study scope must be amended uniformly before final selection/prediction. This report does not characterize the baseline as a general stack-and-heap detector.

Preparation took approximately 68.91 seconds for 32 public-bundle lifts with two worker processes; prediction worker dispatch/evaluation took approximately 1.27 seconds. These are local development wall times, excluding subsequent verification/archive creation, not a forecast for final inference. All 32 IR files also match the preceding complete development lift byte for byte. An additional guard rejects direct or indirect reads outside exported data before they can support a later finding; independent fixtures check this, and the complete rerun left all 32 prediction bytes unchanged. Static-write permission checks and original-byte overlap validation were then corrected; another complete prediction run retained identical bytes. Earlier attempts and method identities are retained in [development history](../../redesign/provenance/phase5-development-history.json).

## Artifacts and reproduction

- [Published pilot results](../../redesign/results/pilot/baseline/phase5-d.json): all 32 decisions/abstentions and input/IR bindings.
- [Validation evidence](../../redesign/provenance/phase5-v1-d-validation.json): method/policy/engine identities, availability counts, reasons, predictions, private pilot comparison and timings.
- [Replay index](../../redesign/provenance/phase5-v1-d-pcode.json) and `redesign/provenance/phase5-v1-d-pcode.tar.gz`: all 32 public-input IR exports, in a deterministic archive of approximately 14 KB.
- Private preparation/worker logs and complete run manifests: `redesign/build/pilot/baseline-lifts/phase5-lift-b/` and `redesign/build/pilot/baseline/phase5-d/`.

Historical preparation commands under the preserved v1 code (the current CLI runs v2):

```bash
export GHIDRA_HOME=/path/to/ghidra_12.1.4_PUBLIC
.venv/bin/python -m redesign.pipeline.baseline lift --run-id phase5-lift-b
.venv/bin/python -m redesign.pipeline.baseline predict --lift-run phase5-lift-b --run-id phase5-d --write
.venv/bin/python -m redesign.pipeline.baseline verify --run-id phase5-d
.venv/bin/python -m redesign.pipeline.baseline audit --run-id phase5-d --write
```

These commands document historical execution. Use `baseline_history` below to replay v1 under its own code; current `verify`/`audit` bind v2. Additional development runs need distinct IDs. Existing published results cannot be replaced with different bytes. Final-split execution is not enabled by this pilot CLI. No config method-lock or final freeze was created.

Replay without Ghidra, original binaries, sources, private oracle or generated build directories:

```bash
.venv/bin/python -m redesign.pipeline.baseline_history
```

The replay verifier checks current methods/policy, the archive inventory/member hashes, exact public-input hashes and every regenerated prediction. Its regression test removes `GHIDRA_HOME` and rejects private preparation calls. This is reproducibility evidence, not a new predictor or a replacement for independently validating Ghidra's lifting.

Validation: with Ghidra enabled, the complete repository suite passed **168 tests and 80 subtests**, with no skipped checks. All eleven real GCC/Ghidra fixture cases pass, along with constant/feasibility, failure-accounting and artifact-replay regressions. Source import/preservation checks, all 16 reference builds, the Phase 4 repeat/coverage/scope gates, the 29-file predecessor snapshot and both historical archive hashes still verify. All 32 accepted predictions regenerate exactly. `git diff --check` passes. No original testcase, historical baseline, LLM setting or final assignment changed.
