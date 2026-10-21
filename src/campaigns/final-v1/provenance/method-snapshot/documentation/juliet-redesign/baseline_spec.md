# Inferred stack bounds baseline v2

October 20, 2026. Method `ghidra-inferred-stack-bounds-v2` is a development baseline over public schema-2 bundles. Its policy is [baseline_policy.json](../../redesign/baseline_policy.json); its output schema is [baseline-result-v2.json](../../redesign/schemas/baseline-result-v2.json). Phase 7 must lock the implementation and contracts before final prediction. This revision explicitly permits heuristic predictions with inferred stack bounds; a classification is not a proof of source-object safety or overflow. The [v1 contract](baseline_spec_v1.md) and its predictions/method are preserved.

## Evidence and representation

The analyzer receives a public bundle and a generic policy. It never reads a reference/analysis ELF, source, debug file, oracle review, observation table or neighboring prediction. Observation identity is attached outside the worker. `LiftBundle.java` reconstructs a fresh Ghidra memory image using only included instruction/data bytes, with the same addresses and permissions. It removes the raw-loader seed block and does not fill image gaps with imagined code/data. It defines only the declared application functions and fixed opaque external-library adapters. The adapters have synthetic RET bodies for decompilation and declared signatures, not recovered library implementations; they are never exported as application P-code.

Ghidra 12.1.4 performs lifting and parameter recovery using the x86-64/GCC compiler specification. No original ELF, debug search, library autoloading or source declaration is available to this process. Parameters are recovered callee first. Recovered stack symbols, storage offsets, sizes, array kinds and storage lifetimes are exported from the new public-only decompilation. No source-shaped text is parsed for capacities. Native tail-transfer facts come from the shared bundle. Each recovered instruction is checked against its public bytes and length before native-write auditing. SSA varnodes, widths, parameter slots, high P-code and basic-block relationships are exported for exactly the declared functions.

The baseline receives the same selected code/data scope as the future LLM, but uses a different derived representation: reconstructed high P-code plus fixed library contracts. The LLM will receive the original public assembly/decompilation. This representation and modeling difference must be disclosed in comparisons; it is not an LLM-reasoning-only experiment.

## Rules

1. Unavailable public context or a shared-budget failure produces input unavailability, without a prediction. Lifting/runtime failure is also unavailable, separately from ordinary analyzer abstention.
2. Enumerate native memory writes using Ghidra's instruction P-code. Exclude CALL/PUSH ABI stack-protocol writes from the selected C-object write endpoint; do not use them or frame reservation as object capacities. Require each remaining native write's byte extent to have a high-P-code STORE or memory-valued COPY/CAST representation at that instruction, or an exactly matching supported instruction-P-code fallback. Any unmatched write causes abstention before classification. High-level dead-store removal therefore cannot silently prove safety.
3. Evaluate a small set of integer/Boolean/constant/pointer-offset operations over high P-code. Respect varnode widths, modular scalar assignments, sign extension, comparisons and truncation. Pointer truncation or ambiguous arithmetic becomes unknown. Supported pointer offsets are bounded to signed 32-bit displacement values; larger/ambiguous products cannot wrap into a falsely small buffer offset.
4. Track each successful allocation as a separate object with its requested constant byte count. An allocator's extra usable space is not its object bound. Track exact known bytes and pointer slots where available. Writable static initial contents are unknown until assigned by the selected execution; read-only public literal bytes are known. Heap capacities still require allocation requests. Stack capacities use the explicitly qualified recovered-array heuristic below; data windows never establish object capacities.
5. Propagate recovered arguments through direct application calls. Use the same generic interpretation for every function. Memory-SSA INDIRECT markers at explicitly modeled CALL/STORE instructions describe effects of those operations, not additional machine writes; their actual effects are applied by the call/store model. Other unsupported effects and aliases abstain. Application names and decompiled text do not choose rules.
6. Follow only concrete branch outcomes, selecting MULTIEQUAL inputs from the actual incoming edge. Model both allocator failure and fresh-success outcomes. Do not infer favorable input values, branch probabilities, loop iteration counts or infeasible witnesses. Cyclic execution, recursion, unknown control flow or resource limits abstain. Incoming root parameters are unknown unless their values follow from included code.
7. For a direct heap STORE or supported library write, prove destination allocation identity, constant offset, write size, live allocation and path feasibility. A positive-size write outside `[0, requested_size)` establishes the supported CWE-122 finding. Library copies additionally require the supported source/readability evidence; overlap is rejected for memcpy and handled through a temporary byte collection for memmove. No testcase-specific summary is permitted.
8. A feasible overflow encountered before later unsupported behavior remains a witness under the recorded bounds assumptions; an unsupported effect before that write cannot be skipped to obtain a finding. Stop the witnessed execution at its first predicted overflow rather than simulate memory corruption. Evidence contains instruction starts from any included function, allocation/call/branch/write support, and the derived write check. It is not a complete provenance trace for every constant Ghidra folded.
9. A no-selected-overflow decision requires completed interpretation of every modeled admissible path, accounted native writes and no unknown selected writes/effects. Zero selected writes can support that conclusion after complete scope/control-flow accounting. The absence of a dangerous API name is never a safety rule.

This is bounded constant propagation/evaluation, not a general interprocedural abstract interpreter or a sound whole-program verifier. It has no interval domain, alias solver, symbolic feasibility solver, loop induction or testcase-specific repair. Unsupported cases remain in the planned denominator as abstentions or explicit unavailability.

## Heuristic stack rule and store fallback

The lifter reads Ghidra's `HighFunction.getLocalSymbolMap().getSymbols()`, `HighSymbol.getStorage()/getSize()/getDataType()/getPCAddress()` and `VariableStorage.getStackOffset()`. These are binary recovery facts, not source or DWARF object evidence. See the [HighSymbol API](https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighSymbol.html) and [VariableStorage API](https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/VariableStorage.html).

A stack pointer has a live invocation identity, entry-SP-relative offset and, when recoverable, its original recovered variable identity. Constant pointer arithmetic and direct caller-to-helper arguments preserve that identity, including one-past-end offsets. Require one nonoverlapping recovered array with whole-function storage and positive size within 4,096 bytes. Compare the recoverable positive write extent against that inferred extent. Eleven bytes into an inferred ten-byte array predicts `vulnerable_CWE-121`, even if the extra byte lands in padding. Never substitute the reserved frame size or distance to a saved return address.

Every array check records `bound_basis: inferred_stack_object_extent`, the signed frame-relative `object_offset`, object-relative destination offset, capacity, size and instruction evidence. Outcomes are `within_inferred_extent` or `exceeds_inferred_extent`. Results using these checks include `inferred_stack_object_extent`, including no-overflow decisions and later abstentions. A positive stack result additionally includes `stack_write_exceeds_inferred_extent`. A deterministic stack-first tie rule applies if distinct modeled paths expose both heap and stack overflows; all checks remain available.

Nonarray recovered slots may account only for writes wholly inside their recovered scalar storage (`recovered_scalar_slot`); they never support a CWE-121 prediction. Missing array extents, excessive bounds, overlapping variables, reused storage/lifetime ambiguity, unknown offsets, dangling frame pointers and unsupported paths abstain. A raw absolute store into a neighboring slot cannot establish which source array the programmer intended; pointer identity is preserved only when the derivation is recovered.

The fallback in `pipeline/stack.py` projects only constants and entry-SP-plus-constant expressions from Ghidra instruction P-code. It uses the exported high CFG, keeps identical affine facts at joins, resets instruction-local temporaries, invalidates overlapping register writes and discards caller-clobbered facts at calls. It performs no mnemonic decoding, load evaluation, flag evaluation, branch solving or argument recovery. A raw LOAD invalidates affine facts so that an unmodeled read cannot support this or a later fallback store. CALL protocol stores are excluded and PUSH affects SP tracking without becoming a selected buffer write. Ambiguous intra-instruction control, shared instruction ownership, cycles and unresolved destinations cannot support fallback stores.

Restore an erased store only when no high-level write represents that instruction, projected sizes exactly cover its native inventory, and its instruction order can be placed within its high block without crossing reordered earlier effects or terminators. Partial high-level coverage remains guarded. Constants update known bytes; other store values remain unknown. All restored writes still pass the same array/scalar/permission/feasibility checks. Results using them include `instruction_pcode_store_fallback`. Unmatched native writes still abstain before classification. Missing variable extents for O0 parameter spills are deliberately unsupported, rather than converted into guessed arrays.

This heuristic can infer padding as part of an array, split or merge variables incorrectly, and therefore produce false positives or false negatives. Independent O0–O3 fixtures expose both correct stack predictions and missed one-byte overflows when a ten-byte source array becomes an eighteen-byte recovered array. These errors are retained and compared with independent fixture truth; pilot predictions are compared with the unchanged private binary oracle after inference. No claim of definite classifications or sound stack verification is made.

## Fixed library contracts

Contracts apply only to public external edges; an application function with a familiar name is still interpreted through its public body. They assume the ordinary libc behavior stated in every shared bundle, with no interposition.

| API | Model and failure boundary |
|---|---|
| `malloc` | Constant request within the footprint limit; explore NULL and a fresh non-null object with that requested bound; contents unknown |
| `calloc` | Constant count/product within the footprint limit; explore NULL and a fresh zero-filled object |
| `free` | NULL is a no-op; otherwise require a live allocation base and invalidate its lifetime |
| `memcpy`, `memmove` | Constant count, known source bytes and tracked destination; memcpy overlap abstains; memmove snapshots source bytes |
| `memset` | Supported constant count and byte value with a tracked destination |
| `strcpy` | Recover a terminating NUL within known supported source bytes; include it in the write extent |
| `strlen` | Recover a terminating NUL within the string budget; otherwise abstain |
| `puts` | Require a recoverable terminated argument; no selected application-memory writes |
| `putchar` | No selected application-memory writes; return value unknown |
| `printf` | Require a recovered fixed format restricted to integer/character/pointer conversions, escaped `%` and supported constant widths; reject `%n`, `%s`, positional arguments, dynamic widths and unsupported formats; require recovered argument count |
| `exit`, `_exit`, `abort` | Terminate that execution path |

Other APIs, including unmodeled copy variants, formatting extensions, system calls and unknown effects, abstain. A model limit or unknown value is not a no-overflow result. Library internal memory and defects are outside the selected application scope. A static-data write requires exported coverage and established writability for every destination byte. Otherwise the path stops with `static_write_outside_export` or `static_write_not_writable`, and cannot support a later overflow witness. An accepted static write is tracked as static storage rather than a proven stack/heap object write. Zero-byte operations do not require writable storage.

Overlapping data windows are validated against their original exported bytes, separately from runtime memory. Matching writable windows are permitted and start with unknown runtime contents. Conflicting original bytes are rejected. If overlapping permission claims disagree, runtime contents remain unknown and writability is unestablished for those bytes, independent of which window contains them.

## Limits and outputs

| Limit | Value |
|---|---:|
| High-P-code evaluation steps per observation, across paths/calls | 4,096 |
| Allocation-path branching budget | 64 |
| Direct application call depth | 8 |
| Supported allocation/copy footprint | 4,096 bytes |
| String scan | 4,096 bytes |
| Function decompilation / Ghidra process timeout | 60 / 300 seconds |
| Runner worker processes | 2 |

The byte/token/context caps in the Phase 4 shared policy also apply. Exact LLM/chat-template budgeting remains Phase 6 work; a later shared-policy amendment requires uniform pilot revalidation before lock.

Result envelopes distinguish `completed`, `input_unavailable` and `runtime_failed`; lifting checkpoints use `lifted`. Completed results are `classified` or `abstained`, with a decision, reason codes, unique evidence, derived write checks and deterministic step/path counters. No probability/confidence score is fabricated. `unknown_allocation_size` and `unknown_write_extent` also cover extents outside this implementation's footprint support. `ambiguous_stack_layout`, `missing_stack_array_extent`, `unresolved_stack_offset`, `unaccounted_native_write`, `unknown_stack_bound`, `unknown_destination`, `unknown_read_address`, `unknown_string_extent`, `unknown_copy_source`, `nonlive_allocation`, `static_write_outside_export`, `static_write_not_writable`, `unsupported_pcode`, `unsupported_library_call`, `unsupported_output_format`, `argument_recovery`, `overlapping_memcpy`, `unresolved_call`, `unresolved_branch`, `recursive_call`, `entry_inside_function`, `cyclic_control_flow`, `incomplete_control_flow`, `step_limit`, `path_limit` and `call_depth_limit` are explicit abstention reasons. The executable result schema enumerates the complete reason vocabulary.

Prediction envelopes bind the canonical bundle and IR hashes. Run manifests bind the declared inventory, methods, policy, engine identities and per-cell outcomes. Published results are protected against replacement. Regeneration evaluates the saved public-input IR with the same method and checks exact prediction equality. The deterministic replay archive uses the predecessor provenance code's gzip/tar recipe and works without a Ghidra installation or private artifacts. Hashes document identity, not external chronology; this development snapshot is not the Phase 8 freeze.
