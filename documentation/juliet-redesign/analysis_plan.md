# Juliet redesign: experimental contract

Version 1, adopted October 19, 2026. This prospective development contract implements Phase 0 of the root redesign plan. It is not external preregistration, an input freeze, or a completed experiment. Historical results have been inspected. The root analysis plan, configuration, and archives continue to describe their existing campaigns; they do not configure this redesign.

## Question and scope

How do GCC optimization level and symbol stripping affect a transparent static baseline and a local LLM's ability to classify stack and heap buffer overflows in matched Juliet-derived binaries?

Study Juliet 1.3 C testcases for CWE-121 and CWE-122 on x86-64 Linux using the System V ABI. Include direct calls and multiple translation units. Exclude recursion, concurrency, C++, application indirect-call dispatch, Windows-only dependencies, and unspecified interactive environments. These are source-level restrictions, not exclusions based on prediction or extraction success. This is classification conditional on localization, not whole-program vulnerability discovery or a soundness evaluation.

Use ten final pairs, five per CWE, and two separate initial pilot pairs, one per CWE. Within each CWE, select three pairs whose relevant allocation/write reasoning crosses direct application helper calls and two whose relevant reasoning is within one function. This gives six interprocedural and four intraprocedural final pairs before optimization. Cross the original vulnerable and one original safe path with O0/O1/O2/O3 and retained/stripped symbols. The pilot has 16 reference builds, 32 observations, and 96 scheduled LLM slots. The final set has 80 reference builds, 160 observations, and 480 slots. Three repetitions measure one observation. Select at most one final pair per source family; families are the sampling and resampling units. Additional pilots remain development-only. Size or matrix changes require a dated amendment before final predictions.

## Source and build treatment

Preserve allocation sizes, types, expressions, control flow, helper relationships, library operations, and data strings. Permit documented neutral identifier/file/comment sanitization and minimal external harness changes only. Record the chosen original safe path and variant-selection mechanism. Add no volatile, noinline, noclone, used, barriers, or optimization-pass exceptions. Retain and disclose original qualifiers.

Pin GCC 15.2.0 and GNU binutils 2.46. Invoke `gcc-15` with one optimization level and these common flags:

```text
-std=c11 -Wall -Wextra -g -gdwarf-5
-m64 -march=x86-64 -mtune=generic
-fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0
-fcf-protection=none -fno-pie -fno-lto
-fdebug-prefix-map={workspace}=/experiment
-ffile-prefix-map={workspace}=/experiment
```

Link with the same optimization level and `-no-pie -fno-lto -Wl,-z,noexecstack`. Separately compile all testcase, driver, and linked Juliet support translation units at the treatment level with these settings; never reuse support objects across levels. Use ordinary dynamically linked system libc, keeping its identity constant. Record hashes of compiler/linker, headers, support files, libc, effective commands/options, architecture, and OS during preparation. Unavailable pinned tools block builds; substitutions need amendments.

No LTO, sanitizer instrumentation, profiling, or extra hardening enters experimental artifacts. Sanitizer builds are separate validation evidence. Disabled hardening is a controlled simplification, not a production-default claim. Keep ordinary GCC behavior including builtins and undefined-behavior-based transformations: a source overflow need not survive compilation.

Build one private debug executable per variant/level. Derive retained using `objcopy --strip-debug`, then stripped using `strip --strip-all`. Verify executable code and relevant loadable code/data bytes are unchanged. Public inputs have no debug sections or restored private names. Dynamic imports may remain; report actual symbol loss. Failed equivalence checks must be repaired before freeze.

## Observation and evidence

An observation is the selected testcase execution scope under one variant, optimization, and symbol treatment. Its entry and application call closure include necessary callers, helpers, tail calls, and referenced data. It remains an observation when a source function is inlined or eliminated. Invoke only the chosen original variant path; do not bundle unrelated safe/vulnerable paths merely because they share a file.

Private source/debug mapping may locate the entry or containing function; disclose this assistance. Public scope selection thereafter follows binary control flow and fixed traversal rules, not oracle bounds or labels. Both methods receive the same selected code/data scope and completeness facts. Disclose differences in derived representations, such as P-code versus assembly/decompilation. Generic standard-library contracts must be versioned; testcase-specific oracle summaries are prohibited.

Phase 4 will specify traversal limits, library boundaries, serialization, and completeness checks. No silent truncation. Exceeding the locked shared evidence budget yields `context_unavailable` for the primary comparison. Missing essential behavior yields `extraction_unavailable`. Nonessential decompiler failure may retain assembly only if the locked schema and both adapters support it. No selective context repair after predictions.

## Ground truth and assumptions

Keep original Juliet `source_label` separate from reviewed `binary_label`. Binary labels are `vulnerable_CWE-121`, `vulnerable_CWE-122`, `not_vulnerable`, or `unresolved`. Here safe means no selected stack/heap out-of-bounds write under the declared assumptions, not absence of all defects.

Overflow requires a feasible witness with evidence for destination object, capacity, write extent, and path conditions. Safety requires all feasible relevant writes to be within bounds, not just a successful execution or missing alarm. Ambiguous bounds, allocation identity, feasibility, missing behavior, or multiple relevant CWEs preventing one exact label yield unresolved.

Set input domains, entry conditions, allocation-success assumptions, and library semantics from source/environment before final predictors. Provide assumptions needed for interpretation in public context without revealing answers. For variable inputs, overflow is existential over admissible executions; safety is universal. Do not choose favorable concrete inputs after inference.

Review actual optimized instructions privately, recording evidence addresses, hashes, reviewer identity, assumptions, and unresolved reasons. Source labels and sanitizer outcomes alone do not establish binary truth. Share truth across symbol treatments only after code/data equivalence is verified. Adjudicate before final predictions; use independent human review where available and disclose actual review provenance otherwise.

Record transformation independently: surviving, inlined, eliminated, mixed, or unresolved. Eliminated writes support safety only when the complete selected emitted scope establishes no relevant overflow; otherwise truth is unresolved. Neither elimination nor a changed binary label permits replacing a final case.

## Dispositions and scoring

Track truth, transformation, artifact, context, and prediction states separately. Every planned cell remains in the inventory.

| Outcome | Rule |
|---|---|
| Build fails | `build_unavailable`; retain planned cell, no binary truth score |
| Binary truth unresolved | Exclude from binary-label scores; report truth availability and full inventory |
| Resolved truth, missing essential extraction | Unavailable prediction; retain in adjudicated denominator |
| Resolved truth, oversized shared context | Unavailable prediction; retain in adjudicated denominator |
| Valid exact class | Correct/incorrect including CWE |
| Valid uncertain decision | Abstention, never correct |
| Static method cannot prove either answer | Abstention with reason, never implicitly safe |
| Crash, timeout, invalid output, or length-limit termination | Failed attempt, no valid vote |
| Some valid LLM votes, no two identical labels | Aggregation abstention |
| No valid LLM votes | Unavailable aggregate |
| Unresolved truth but usable prediction | Availability and secondary source-label analysis only |

Let A be all selected cells with adjudicated binary truth, including cells with unavailable public inputs or predictions. Partition A into correct C, incorrect E, abstention U, and unavailable M. Report C/A, coverage (C+E)/A, U/A, M/A, and selective accuracy C/(C+E), with raw counts, A/160, and full preparation/truth dispositions. Unresolved truth is neither a model error nor abstention. Zero denominators are NA.

Primary method contrast: LLM minus static C/A on identical adjudicated cells. Coverage and selective accuracy support interpretation. Also report a common-input subset with complete shared context, explicitly conditional; it does not replace the primary denominator. Report optimization, symbol, CWE provenance, and actual binary-class subgroups. Optimization can change binary-class balance.

Secondary alert metrics map either vulnerable prediction to alert and everything else to no alert. Report TP/TN/FP/FN, recall, FPR, precision, F1, and balanced accuracy. Separate no-alert outcomes caused by explicit safe decisions, abstentions, and unavailable results. Wrong-CWE alerts can be alert true positives but exact-label errors. Balanced accuracy needs both actual classes. These metrics do not establish safety from abstention.

Secondary source-label recovery scores against original Juliet labels across all selected cells, retaining unavailable inputs. Call it source-label recovery, not binary-vulnerability accuracy. Report conflicting identical-input groups and sensitivity excluding all their members, without replacing primary scores. An eliminated overflow need not leave a vulnerable/safe binary pair.

## Contrasts and uncertainty

Within each method compare O1/O2/O3 against O0 at matching family, variant, and symbol condition, requiring adjudicated truth at both levels. Retain extraction/prediction failures on those cells. Report matched cells/families, omitted reasons, and binary-label transitions. Compare stripped versus retained within each level similarly. Accuracy contrasts must accompany full transformation and availability tables.

Bootstrap ten families as clusters: 10,000 draws of ten families with replacement using NumPy PCG64 seed 20261019. Share multiplicities across methods, subgroups, and contrast sides. Use 2.5th/97.5th percentiles with linear interpolation. Use only defined replicates for undefined metrics and disclose their count; entirely undefined intervals are NA. Never resample treatment cells or LLM slots independently. Ten clusters support exploratory estimates, not confirmatory population claims. No primary GLMM or hypothesis-testing ladder.

Retain per-family results, leave-one-family-out sensitivity, collisions, symbol-loss audits, paired source-variant discrimination, confidence summaries, and compute/failure accounting. Diagnostics cannot change selection or methods. Self-reported confidence is not calibrated probability.

## Inference, recovery, and locks

Start pilots with existing DeepSeek-R1-Distill-Qwen-14B Q5_K_M, seeds 4101/4102/4103, temperature 0.2, top-p 0.95, and 4096 completion tokens. The current 8192 context is a pilot starting point. Phase 7 locks model/hash, full samplers, chat template, prompt/schema, shared context budget, timeouts, baseline engine/rules/resource limits, and runtime. Phase 8 binds these to final inputs. Pilot-driven changes apply uniformly to final observations.

Order final slots deterministically by SHA-256 of UTF-8 `20261019\n{observation_id}\n{repetition_index}` (indices 1–3), ascending hash then ID/index, independent of labels. Preserve the schedule. Two identical valid labels establish an aggregate, including two uncertain votes. Otherwise some valid votes yield aggregation abstention and zero valid votes yield unavailable. No confidence-weighted voting. Confidence, if collected, is the median of valid runs including nonmajority votes; high confidence means at least 0.8.

Save raw requests/responses, durable dispatch state, usage, timings, finish reasons, validation failures, and runtime identity. Length-limit termination fails even if partial text parses. A dispatched slot with timeout, crash, malformed output, or uncertain completion is terminal failed; never rerun it. Resume only provably never-dispatched slots after checking the same freeze/runtime. Input-blocked slots are unavailable and not actual requests. Never overwrite terminal attempts. Static runtime failures likewise remain unavailable, distinct from ordinary uncertain decisions.

Correctness repairs after final inference begins require an amendment and new campaign identity with a complete corrected run. Preserve affected outputs; never combine method versions. Diagnostic investigations use copies and are labeled. A timestamped deposit is recommended before final predictions; hashes alone do not establish chronology.

## Acceptance and amendments

Phase 0 fixes this question, matrix, selection policy, endpoints, scoring, build treatment, and failure rules. Phase 1 implements isolation/configuration. Phases 2–6 implement source preservation, builds, context, and methods. Phase 7 locks pilot-dependent engineering choices; Phase 8 freezes the final inventory, reviewed truth, inputs, and methods. Only then may final predictors run.

Amendments must state date, changed rule, reason, evidence already inspected, and affected campaign. Additional pilot families remain development-only. Public Juliet may appear in LLM training; family separation prevents local reuse but does not establish pretraining novelty.

Phase 0 acceptance requires a deterministic candidate ordering, performance-independent selection rules, distinct source/binary truth, and explicit dispositions/scoring for every observation outcome. Build, source-authenticity, and inference gates remain pending. No redesigned final predictions are authorized by completion of this phase.

## October 20 baseline amendment before method lock

Revision `ghidra-inferred-stack-bounds-v2` permits heuristic Ghidra-recovered stack-array capacities. Every affected prediction must identify `inferred_stack_object_extent`; classifications may be mistaken and are evaluated against the unchanged private binary oracle. A narrow instruction-P-code store fallback may account for high-level erased stores, with explicit annotations and abstention on unsupported recovery/control flow. The [baseline specification](baseline_spec.md) and [revision report](phase5_stack_revision.md) define the exact rules, independent O0–O3 fixtures, observed errors and pilot coverage. Source/testcase logic, compiler treatments, context bundles, oracle labels, model settings and final selection remain unchanged. V1 predictions and executable method sources are preserved. Phase 7 method lock is still pending.
