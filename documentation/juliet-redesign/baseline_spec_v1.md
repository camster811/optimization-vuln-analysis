# Constant-bounds baseline v1

October 19, 2026. Method `ghidra-constant-bounds-v1` is a development baseline over public schema-2 bundles. Its policy is [baseline_policy.json](../../redesign/baseline_policy.json); its output schema is [baseline-result-v1.json](../../redesign/schemas/baseline-result-v1.json). Phase 7 must lock the implementation and contracts before final prediction.

## Evidence and representation

The analyzer receives a public bundle and a generic policy. It never reads a reference/analysis ELF, source, debug file, oracle review, observation table or neighboring prediction. Observation identity is attached outside the worker. `LiftBundle.java` reconstructs a fresh Ghidra memory image using only included instruction/data bytes, with the same addresses and permissions. It removes the raw-loader seed block and does not fill image gaps with imagined code/data. It defines only the declared application functions and fixed opaque external-library adapters. The adapters have synthetic RET bodies for decompilation and declared signatures, not recovered library implementations; they are never exported as application P-code.

Ghidra 12.1.4 performs lifting and parameter recovery using the x86-64/GCC compiler specification. No original ELF, debug search, library autoloading, source declaration or decompiled array extent is available to this process. Parameters are recovered callee first and committed without adopting inferred object types as capacities. Native tail-transfer facts come from the shared bundle. Each recovered instruction is checked against its public bytes and length before native-write auditing. SSA varnodes, widths, parameter slots, high P-code and basic-block relationships are exported for exactly the declared functions.

The baseline receives the same selected code/data scope as the future LLM, but uses a different derived representation: reconstructed high P-code plus fixed library contracts. The LLM will receive the original public assembly/decompilation. This representation and modeling difference must be disclosed in comparisons; it is not an LLM-reasoning-only experiment.

## Rules

1. Unavailable public context or a shared-budget failure produces input unavailability, without a prediction. Lifting/runtime failure is also unavailable, separately from ordinary analyzer abstention.
2. Enumerate native memory writes using Ghidra's instruction P-code. Exclude CALL/PUSH ABI stack-protocol writes from the selected C-object write endpoint; do not use them or frame reservation as object capacities. Require each remaining native write's byte extent to have a high-P-code STORE or memory-valued COPY/CAST representation at that instruction. Any unmatched write causes abstention before classification. High-level dead-store removal therefore cannot silently prove safety.
3. Evaluate a small set of integer/Boolean/constant/pointer-offset operations over high P-code. Respect varnode widths, modular scalar assignments, sign extension, comparisons and truncation. Pointer truncation or ambiguous arithmetic becomes unknown. Supported pointer offsets are bounded to signed 32-bit displacement values; larger/ambiguous products cannot wrap into a falsely small buffer offset.
4. Track each successful allocation as a separate object with its requested constant byte count. An allocator's extra usable space is not its object bound. Track exact known bytes and pointer slots where available. Writable static initial contents are unknown until assigned by the selected execution; read-only public literal bytes are known. Inferred variable/array types and data windows never establish object capacities.
5. Propagate recovered arguments through direct application calls. Use the same generic interpretation for every function. Memory-SSA INDIRECT markers at explicitly modeled CALL/STORE instructions describe effects of those operations, not additional machine writes; their actual effects are applied by the call/store model. Other unsupported effects and aliases abstain. Application names and decompiled text do not choose rules.
6. Follow only concrete branch outcomes, selecting MULTIEQUAL inputs from the actual incoming edge. Model both allocator failure and fresh-success outcomes. Do not infer favorable input values, branch probabilities, loop iteration counts or infeasible witnesses. Cyclic execution, recursion, unknown control flow or resource limits abstain. Incoming root parameters are unknown unless their values follow from included code.
7. For a direct heap STORE or supported library write, prove destination allocation identity, constant offset, write size, live allocation and path feasibility. A positive-size write outside `[0, requested_size)` establishes the supported CWE-122 finding. Library copies additionally require the supported source/readability evidence; overlap is rejected for memcpy and handled through a temporary byte collection for memmove. No testcase-specific summary is permitted.
8. A feasible overflow encountered before later unsupported behavior remains a definite witness; an unsupported effect before that write cannot be skipped to obtain a finding. Stop the witnessed execution at its first proven overflow rather than simulate memory corruption. Evidence contains instruction starts from any included function, allocation/call/branch/write support, and the derived write check. It is not a complete provenance trace for every constant Ghidra folded.
9. A no-selected-overflow decision requires completed interpretation of every modeled admissible path, accounted native writes and no unknown selected writes/effects. Zero selected writes can support that conclusion after complete scope/control-flow accounting. The absence of a dangerous API name is never a safety rule.

This is bounded constant propagation/evaluation, not a general interprocedural abstract interpreter or a sound whole-program verifier. It has no interval domain, alias solver, symbolic feasibility solver, loop induction or testcase-specific repair. Unsupported cases remain in the planned denominator as abstentions or explicit unavailability.

## Stack support limit

This version cannot establish source-level stack-object capacities from decompiler arrays, neighboring locals, frame padding or saved return-address locations. Stack writes with unknown bounds abstain, as do native writes eliminated from the high-level representation. It deliberately does not port the historical saved-frame-overlap rule. **No positive CWE-121 rule is implemented.** The pilot's stack coverage is zero; later reports must show that coverage explicitly rather than combine it into a claim of broad stack/heap support. Phase 7 must review whether the declared support boundary is adequate for the intended comparison before final selection and freeze.

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

Result envelopes distinguish `completed`, `input_unavailable` and `runtime_failed`; lifting checkpoints use `lifted`. Completed results are `classified` or `abstained`, with a decision, reason codes, unique evidence, derived write checks and deterministic step/path counters. No probability/confidence score is fabricated. `unknown_allocation_size` and `unknown_write_extent` also cover extents outside this implementation's footprint support. `unaccounted_native_write`, `unknown_stack_bound`, `unknown_destination`, `unknown_read_address`, `unknown_string_extent`, `unknown_copy_source`, `nonlive_allocation`, `static_write_outside_export`, `static_write_not_writable`, `unsupported_pcode`, `unsupported_library_call`, `unsupported_output_format`, `argument_recovery`, `overlapping_memcpy`, `unresolved_call`, `unresolved_branch`, `recursive_call`, `entry_inside_function`, `cyclic_control_flow`, `incomplete_control_flow`, `step_limit`, `path_limit` and `call_depth_limit` are explicit abstention reasons. The executable result schema enumerates the complete reason vocabulary.

Prediction envelopes bind the canonical bundle and IR hashes. Run manifests bind the declared inventory, methods, policy, engine identities and per-cell outcomes. Published results are protected against replacement. Regeneration evaluates the saved public-input IR with the same method and checks exact prediction equality. The deterministic replay archive uses the predecessor provenance code's gzip/tar recipe and works without a Ghidra installation or private artifacts. Hashes document identity, not external chronology; this development snapshot is not the Phase 8 freeze.
