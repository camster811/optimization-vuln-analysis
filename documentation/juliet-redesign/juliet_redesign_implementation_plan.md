# Juliet Redesign and Implementation Plan

Prepared October 19 2026

Phase 0 is implemented in [the experimental contract](analysis_plan.md) and [selection specification](selection_spec.md), with a seeded candidate-family inventory in the same directory. The contract specifies six interprocedural and four intraprocedural final pairs, balanced by CWE.

Phase 1 is implemented in the isolated [redesign workspace](../../redesign/README.md): versioned configuration and manifest declarations, deterministic matrix/schedule generation, input inventory checks, and a predecessor code/provenance snapshot. It initially reserved unassigned pilot and final slots. A synthetic two-file fixture validates all four optimization levels and both symbol conditions. The old pipeline is preserved, not silently applied to new inputs.

Phase 2 is implemented: [pilot import and validation report](phase2_report.md). The two pilot slots are assigned to original Juliet paths; final slots remain unassigned. Archive verification, read-only originals, token-preserving sanitization, external drivers, source diffs, O0–O3 compilation comparisons, binary metadata scans, and separate sanitizer checks are complete.

Phase 3 is implemented: [campaign build and private oracle report](phase3_report.md). All 16 pilot reference builds and 32 derived symbol observations pass code/data equivalence, debug-removal, metadata and private-review checks. Selected operations are present in 11 builds, inlined/merged in three, and eliminated in two. Reviews are hash-bound and were performed by Codex without independent human adjudication.

Phase 4 is implemented: [public context report](phase4_report.md), [implementation plan](phase4_implementation_plan.md), and [bundle specification](context_bundle_spec.md). All 32 pilot schema-2 bundles contain address-selected application code/data and pass private instruction-coverage, leakage, symbol-scope and independent-repeat checks. External debug lookup is disabled; stripped inputs are independently recovered. Actual model token budgeting remains Phase 6 work. Phase 4 ran no predictors; no final slots were assigned, and the methods remain unlocked pending Phase 7.

Phase 5 is implemented: [baseline report](phase5_report.md), [implementation plan](phase5_implementation_plan.md), and [rule/contract specification](baseline_spec.md). The public-bundle-only Ghidra P-code baseline accounts for all 32 pilot cells: eight classifications matching the private oracle and 24 explicit abstentions, with no unavailable/failed cells. The October 20 [v2 revision](phase5_stack_revision.md) adds explicitly heuristic recovered-array CWE-121 checks and an instruction-P-code store fallback; stack pilot paths still abstain under the declared support limits. The predecessor was reviewed and compatible validation/provenance patterns reused; its x86/frame heuristic was not ported. Saved IR and predictions replay without Ghidra or private artifacts. No final or LLM predictions ran; coverage review and method lock remain Phase 7 work.

Phase 6 is implemented: [LLM integration report](phase6_report.md). Exact live-template/tokenizer preflight covers all 32 bundles and 96 request slots: 26 bundles fit the retained 8,192-token context with 4,096 tokens reserved; six receive shared `context_unavailable` status. Three scheduled pilot requests pass live response validation. Stateless inference, cross-function evidence validation, frozen runtime/method checks, and durable no-retry recovery are tested. The complete pilot, shared-eligibility evaluation, and method lock remain Phase 7 work. No final inference ran.

Phase 7 is complete: [pilot and method-lock report](phase7_report.md) and [decision log](phase7_decisions.md). All 96 LLM slots are terminal (77 valid, one schema failure, 18 context-blocked), all 32 baseline predictions replay, and an independent rebuild/extraction reproduces the deterministic pilot artifacts. Shared-eligibility scoring and family-level diagnostics are published. The Ghidra-enabled full suite passed 256 tests and 80 subtests without skips; 11 final targeted evaluation/lock tests also pass. The verified method lock fixes the methods and scoring; final assignment, final oracle preparation and the final input freeze remain Phase 8 work. No final inference ran.

Phase 8 is complete: [final preparation and freeze report](phase8_report.md). Ten final families produce 80 references and 160 public observations; all pass extraction and evidence/symbol-scope audits. Exact token preflight records 112 available and 48 shared-unavailable observations (336 eligible and 144 blocked slots). The immutable input release and fresh archive replay verify, 103 regression tests pass without skips, and the Phase 7 method lock remains unchanged. No final predictor ran; Phase 9 is next.

Phase 9 is complete for the user-requested 12,288-token amendment: [final report](phase9_report.md). All 480 LLM slots are terminal (472 valid, six schema failures, two interrupted), all 160 baseline results replay, and analysis/tables/figures regenerate with a separately documented byte-comparison correction. Exact-label C/E/U/M is 125/28/7/0 for the LLM and 18/0/142/0 for the baseline on 160 adjudicated cells. The original locks/releases remain preserved; the final archive and manifest bind results and validation evidence. Phase 10 remains next.

## Purpose and starting design

Rebuild the experiment around original Juliet program logic, ordinary GCC optimization, meaningful neutral symbols, and binary-derived context spanning multiple functions. The objective is to answer:

> How do GCC optimization level and symbol stripping affect a transparent static baseline and a local LLM's ability to recognize stack and heap buffer overflows in matched Juliet-derived binary programs?

This is an implementation plan, not a record of completed work or a preregistration. The existing campaigns remain historical experiments. The redesigned experiment must have its own corpus, schemas, method versions, freeze, inference outputs, and report.

The starting scope is ten final source pairs, five per CWE, with two additional development pairs, one per CWE. Compile vulnerable and safe variants at O0, O1, O2, and O3; derive retained and stripped artifacts from each compiled reference binary. Run three stateless LLM repetitions per final observation.

| Quantity | Pilot | Final |
|---|---:|---:|
| Source pairs | 2 | 10 |
| Variants per pair | 2 | 2 |
| Optimization levels | 4 | 4 |
| Reference builds | 16 | 80 |
| Retained and stripped observations | 32 | 160 |
| Scheduled LLM repetition slots | 96 | 480 |

Counts are planned inventory sizes. Extraction failures or unavailable context must receive explicit statuses; they must not be disguised as completed model requests. Pilot repetitions may be rerun during development, with that history retained. Final retries and interruption handling follow a policy frozen before the final run.

Ten pairs across four levels have the same nominal inference count as the current twenty-pair, two-level design. Multi-function inputs may be larger and slower. More treatment cells do not increase the number of independent source-pair clusters.

## Principles that govern every phase

1. Preserve Juliet allocation sizes, control flow, expressions, data flow, helper relationships, and library operations. Permit documented metadata sanitization and minimal execution-harness changes only.
2. Add no volatile, noinline, noclone, used, or similar preservation controls to the selected samples. Preserve modifiers already present in the original sample and disclose them.
3. Use source and debug information privately for verification and localization. Never supply source-derived capacities, private labels, or restored stripped symbols to either analyzer.
4. Select final cases using documented source-level eligibility and sampling rules, without final analyzer predictions. Freeze methods using separate pilots.
5. Treat inlining, elimination, unresolved calls, extraction failures, and insufficient context as measured outcomes. Do not repair final sources to make them easier to analyze.
6. Keep source labels distinct from conclusions about emitted machine code. Neither a source label nor an absent decompiler statement proves binary behavior.
7. Give both methods access to the same selected code and data scope. Disclose any differences in derived representations or library modeling.
8. Preserve all planned cells in the inventory and disposition tables, even where a classification metric cannot be computed.

## Phase overview

| Phase | Deliverable | Gate to proceed |
|---|---|---|
| 0 | Written experimental contract | Endpoints, scope, eligibility, and failure rules specified |
| 1 | Isolated workspace and configuration-driven inventory | Existing campaigns preserved; O0–O3 matrix validated |
| 2 | Reproducible Juliet import and sanitization | Pilot source logic preserved and metadata leakage checked |
| 3 | Multi-file builds and private oracle | All pilot builds accounted for, including transformations |
| 4 | Multi-function public context bundles | Pilot bundles contain auditable code/data context without private evidence |
| 5 | Small baseline selected and implemented | Generic rules and failures validated on development fixtures |
| 6 | LLM bundle integration | Prompt, context limits, evidence validation, and runtime pass pilot checks |
| 7 | Complete pilot and method lock | End-to-end rehearsal succeeds; all amendments recorded |
| 8 | Final corpus preparation and freeze | Final inventory, oracle, inputs, and methods frozen before predictions |
| 9 | Final inference and analysis | All scheduled slots accounted for; outputs regenerate |
| 10 | Research release and manuscript update | Claims match the measured scope and reproducibility evidence |

Phases 2–4 establish the evidence contract. Baseline and LLM integration can proceed independently after that contract is stable. Final-case predictions begin only after Phase 8.

## Phase 0 Define the experimental contract

### Work

Write a new analysis plan before implementation choices become driven by final results. Set the initial ten-pair scope and O0–O3 matrix. Keep GCC version, architecture, linking choices, hardening flags, and support-library build settings constant across levels. Start without link-time optimization; document that this limits cross-translation-unit inlining.

Choose C samples with supported Linux dependencies and manageable application call graphs. For this first redesign, exclude recursion, threads, C++ virtual dispatch, and function-pointer-heavy cases by an explicit source-level scope rule. Include direct calls across multiple functions and, where feasible, translation units. Record the resulting limits rather than implying arbitrary interprocedural coverage.

Define one observation as the selected testcase execution scope for a source variant and compiler/symbol treatment. The observation must not depend on a particular source function continuing to exist after optimization. Use a documented entry scope and include its application context; if an oracle supplies an entry address, disclose classification conditional on localization.

### Ground truth and endpoints

Use two distinct labels in the private metadata:

- **Source label:** the original Juliet vulnerable/safe designation and CWE. It records benchmark provenance.
- **Compiled-behavior conclusion:** overflow, within bounds/no selected overflow, or unresolved, supported by reviewed emitted-code evidence under documented input and library assumptions.

Recommended primary endpoint: exact classification of the selected compiled behavior where that behavior is adjudicated. A vulnerable source operation proven eliminated is not automatically a binary overflow. Mark it as no selected overflow only when the compiled behavior supports that conclusion; otherwise mark it unresolved.

Report the adjudicated denominator and the complete planned denominator side by side. Unresolved ground truth is not a model abstention or an incorrect prediction. Report extraction availability, context availability, adjudication availability, and analyzer coverage separately.

Retain source-label recognition as a secondary analysis, explicitly identifying it as recovery of source labels from binary evidence. Show how elimination and identical-input conflicts affect that analysis. This prevents a source-flaw recognition score from being presented as binary-vulnerability accuracy.

Predefine method comparisons on identical eligible cells. Optimization contrasts use matched observations with adjudicated truth at both compared levels, with pair counts and omitted-cell reasons reported. Also report the full transformation/disposition table so conditioning on recoverable cases cannot hide optimization's effect on availability.

### Deliverables and acceptance

- New analysis plan defining the observation, labels, eligibility, metrics, pairing, and failure handling.
- Selection specification and seeded ordering of candidate families.
- Explicit treatment of eliminated operations, unknown compiled behavior, and oversized context.
- Gate: every possible observation outcome has a recorded disposition and an unambiguous scoring rule. No rule requires looking at final prediction correctness.

## Phase 1 Isolate the redesign and parameterize the pipeline

### Work

Create a separate development workspace from the latest corrected code. Record the starting revision and any uncommitted changes included. Preserve the existing campaign archives and their hashes.

Replace assumptions about p01–p22, exactly 160 records, and only O0/O2 with a validated experiment configuration and manifests. Generate expected observation IDs, build counts, record inventory, inference slots, and plotting levels from the declared matrix. Do not derive them from whichever files happen to exist.

Retain the working runtime/provenance architecture, strict JSON handling, raw response capture, majority aggregation, explicit failure statuses, pair bootstrap machinery, and byte-for-byte output regeneration where compatible.

### Components to change

| Component | Required redesign |
|---|---|
| Corpus manifest | Upstream case identity, source-file set, variants, entry selection, family, split, sanitization mapping |
| Build configuration | O0–O3, multi-file compilation, support dependencies, original variant-selection mechanism |
| Observation schema | Case-level scope and multiple recovered functions; mapping/disposition states |
| Public record schema | Function collection, calls, referenced data, completeness information |
| Freeze checks | Complete declared inventory, new schemas, sanitization provenance, oracle and context policy |
| Evaluation | Dynamic levels/counts, separate source and binary labels, disposition and denominator reporting |
| Regression tests | New matrix/schema contracts plus the existing ABI, runtime, and correctness regressions |

### Gate

A tiny synthetic development fixture produces a complete declared matrix at all four levels. Missing, duplicate, or unexpected cells fail validation. Old archives still restore with their own historical methods; new code is not required to reinterpret old schemas.

## Phase 2 Import and sanitize Juliet reproducibly

### Work

Pin the exact Juliet archive and digest. Preserve original files read-only and record upstream case identifiers, related translation units, support files, and source hashes.

Select one vulnerable flow and one corresponding safe flow for each pair. Juliet cases can contain multiple good paths; record the chosen pairing explicitly. Prefer original preprocessor controls and a minimal external driver for variant selection. Keep harness changes separate from the testcase bodies.

Implement consistent token-aware renaming across declarations, definitions, calls, and translation units. Sanitize benchmark-specific filenames, comments, identifiers, macros where appropriate, and revealing diagnostic strings. Do not rename standard library APIs or alter strings used as actual test data merely because they resemble metadata.

Use neutral role names such as processing or copying roles, assigned without using the vulnerability label. Use the same naming policy for vulnerable and safe variants. Keep meaningful helper relationships in retained symbols so stripping can remove actual developer information.

Record a transformation manifest and human-readable diff. Every edit must be categorized as identifier sanitization, metadata removal, diagnostic-message replacement, or harness selection. Any other edit fails the preservation check and requires explicit redesign review.

### Verification

- Token or AST comparison checks that executable expressions, constants, statements, types, and control structure are unchanged except permitted transformations.
- Original and sanitized pilot builds are compared through normalized instructions/control flow where practical. Address or symbol relocation alone is not treated as a semantic change.
- Scan both derived binaries and exported records for names, strings, paths, and labels that reveal benchmark truth.
- Separate sanitizer runs help verify expected memory behavior. Passing sanitizer execution does not prove all paths safe or validate production optimized binaries by itself.

### Gate

Both pilot pairs compile with their original helper structure and supported execution paths. Every source change is accounted for. No new preservation modifier, bound change, loop rewrite, or output-call substitution is present.

## Phase 3 Build ordinary optimized binaries and review the oracle

### Work

Compile all translation units using the fixed treatment settings. Compile one private reference binary per variant/optimization and derive retained and stripped analysis artifacts from that same binary. Verify equal executable text between symbol partners and absence of debug information from both public artifacts.

Do not disable individual optimization passes to preserve an example. Record the effective compiler options. Allow ordinary inlining and other transformations within the fixed compilation model.

Replace the single target start/end assumption with a private mapping capable of describing containing functions, inlined regions, multiple instruction ranges, and eliminated or unresolved operations. Debug information may assist mapping, but emitted code must substantiate the adjudication.

For each reference build, review the selected destination, allocation/object bound, write extent, input assumptions, relevant path, and supporting instruction addresses. Capture operation status separately from the classification conclusion: present, inlined/merged, eliminated, or unresolved.

The oracle is not a third predictor. It supplies private provenance, localization where declared, and adjudicated labels for evaluation. Source-derived facts must not be copied into public context as if recovered by the analyzer.

### Gate

All 16 pilot reference builds have a disposition. Retained/stripped partners match in executable text and private conclusions. Missing functions are represented correctly rather than causing a case to disappear. Ambiguous cases are marked unresolved rather than being forced to match Juliet labels.

## Phase 4 Export multi-function context

### Work

Define public bundle schema version 2. A bundle should contain the selected entry address, recovered application functions, per-function assembly and decompilation status, direct call edges, unresolved transfers, referenced constants/global data, and explicit completeness/omission metadata.

Use an entry-rooted application call closure as the starting policy. Include the caller that establishes allocation or arguments when the selected operation is inside a helper. Treat compiler-generated clones and tail calls consistently. Include application support helpers under a documented policy; exclude runtime startup and external library bodies using the same rule for every observation.

Resolve relationships using recovered addresses and control flow rather than retained developer names. Stripped records must not regain original names through oracle joins. Keep actual retained names in retained records and recovered anonymous names in stripped records.

Include referenced literal/global bytes with addresses and recovered interpretation where available. Record uncertainty for unresolved indirect calls or data. A declaration inferred by the decompiler is not automatically a proven object bound.

### Context budget

Use complete small application scopes when they fit. Establish function/byte/token limits on pilots, with deterministic ordering and an explicit oversized status. Never silently crop the allocation, caller, or relevant helper to fit a prompt. If bounded selection is necessary, freeze it and report omissions. Do not manually select a better context for individual final failures.

Some source distinctions cannot be recovered from any binary context. Record equality groups and conflicting source labels rather than promising that a larger prompt can restore information removed by compilation.

### Gate

- Pilot bundles include the independently reviewed allocation-to-write chain when recoverable.
- Inlined cases remain represented through their containing functions.
- Both symbol conditions follow the same address-based selection policy.
- No private source labels, capacities, filenames, or restored stripped names leak.
- Evidence references can be validated across every function in a bundle.
- Two identical extraction runs produce equivalent canonical bundles.

## Phase 5 Select and implement the static baseline

### Initial approach

Evaluate a small set of generic bounds/write checks over Ghidra's intermediate representation. Reuse Ghidra's lifting and basic data-flow facilities rather than extending a custom simulator for every x86 instruction emitted at O3.

Limit the first baseline to recoverable constant sizes, straightforward pointer offsets, direct argument passing, and a documented set of allocation and memory/string operation contracts. Unknown bounds, unsupported aliasing, or unresolved control flow produce abstention. Absence of a dangerous function name does not establish safety; a safe result requires accounting for the relevant selected writes.

Function summaries must be produced from public binary evidence or fixed library contracts. Do not handwrite testcase-specific summaries using source or oracle knowledge. Any path used to support a finding must have the required feasibility support. The October 20 pre-lock amendment permits explicitly heuristic recovered stack-array extents, with their assumptions and errors reported separately from allocation-request bounds.

### Bounded feasibility comparison

Use the pilot stage to compare the Ghidra-based approach with an angr reaching-definitions implementation if Ghidra argument propagation proves impractical. Assess installation, reproducibility, representation recovery, required custom logic, and runtime. Select an engine before final predictions; do not choose whichever wins on final accuracy.

Cppcheck or IKOS may help validate source examples, but they do not directly provide a GCC-binary transformation baseline when run on source/LLVM inputs. BinCAT is a binary analysis toolkit worth considering only if integration remains manageable. None of these options should be described as an already validated drop-in comparator.

### Verification and gate

Use independent small fixtures covering a safe copy, a definite overflow, missing capacity, allocation in a caller, a copy in a callee, multiple allocations, unsupported calls, and infeasible branches. Include direct stores and compiler-inlined copies so the baseline's support boundary is visible.

Pilot mistakes may motivate generic repairs with regression tests. Do not modify testcase logic to suit baseline support. If the baseline requires a general interprocedural abstract interpreter to become usable, record that the simple-baseline scope has failed and choose a revised approach before final selection.

Gate: publish the rule list, library contracts, limits, engine version, and reason codes. Demonstrate useful behavior on its declared supported fixtures, and honest abstention on unsupported ones. Freeze this implementation before final predictions.

## Phase 6 Integrate the LLM with context bundles

### Work

Update the prompt to identify the selected execution scope and explain the bundle structure. Ask for the compiled-behavior decision and instruction-address evidence spanning functions as necessary. Preserve explicit uncertainty and prohibit inference from IDs, presumed class balance, or benchmark conventions.

Extend response validation to accept evidence addresses from any included function and reject addresses outside the bundle. Keep stable opaque observation IDs outside the prompt. Ensure calls and referenced data have enough identity for the model to follow the relationships.

Keep the existing model as the initial choice to avoid introducing another changing factor. Pilot token counts and memory requirements determine whether the current 8,192-token context is sufficient. If a larger context or different model is required, select it before the final freeze and identify the study as a new configuration. Never imply that changing a token limit guarantees the hardware can serve it.

Run stateless repetitions with frozen prompt, schema, seeds, sampling parameters, and scheduling. Retain raw requests/responses, timing, token usage, truncation, and failure statuses. A syntactically valid response stopped by a length limit remains a recorded failure under the declared policy.

### Gate

Every pilot bundle either fits with the full reserved completion budget or receives the declared availability status. Context-size and evidence-address regressions pass. A server identity change or model/prompt mutation is detected. No final inference is used to choose the prompt or model settings.

## Phase 7 Complete the pilot and lock the methods

### Work

Run the complete 32-observation pilot through both methods and evaluation. Perform a clean rebuild/extraction in a separate workspace and verify deterministic artifacts where determinism is claimed. LLM outputs are preserved, not assumed bitwise deterministic across reruns.

Review the following jointly: preservation of source logic, symbol information removed, inlining/elimination dispositions, unresolved context, input collisions, baseline support, LLM token budgets, failures, and adjudication effort. The pilot's purpose is to expose design problems, not to establish the final effect size.

Freeze the source-selection policy, schema, context traversal, baseline, prompt/model, scoring, matched comparisons, and missing-data rules. Record all pilot-driven changes in a decision log.

### Decision gate

Proceed when the system handles ordinary direct multi-function flow and optimization without testcase-specific fixes. If it does not, narrow the declared source-level scope or choose a different baseline before final selection. Additional pilot examples, if needed, become development data permanently.

If the pilot shows that ten final pairs are feasible but too homogeneous, increase diversity before final prediction inspection. Twelve or fourteen pairs permit equal CWE allocation; fifteen requires a declared seven/eight split. Recompute the complete inventory from configuration rather than editing counts by hand.

## Phase 8 Prepare final cases and freeze the campaign

### Work

Apply the frozen selection rules to previously unused source families. Use a recorded seed/order and a reserve list. Avoid treating many near-identical flow variants as independent diversity. Keep both pilot families and all additional development fixtures outside the final set.

For each candidate, record eligibility and any rejection. Permitted technical exclusions must be defined in advance, such as unsupported platform dependencies. Optimization eliminating an operation, low baseline coverage, or an anticipated model mistake is not a replacement reason. Ground-truth uncertainty receives its declared disposition.

Import, sanitize, build, map, and export all final cases without running final predictors. Complete the oracle before predictions. A second human reviewer should adjudicate labels and difficult mappings where available; otherwise disclose who reviewed them and the lack of independent human adjudication.

Audit retained/stripped differences. Report how many matched bundles actually lose meaningful names, how many differ only trivially, and how many are identical. Do not infer symbol loss merely from having invoked strip.

Perform runtime preflight, including token-budget calculation without inspecting final model predictions. Create an immutable campaign freeze covering upstream hashes, sanitized files and transformation manifest, compiler settings, reference/analysis identities, private oracle, public bundles, methods, prompt/schema, model identity, and runtime evidence. Create a versioned release or timestamped deposit for chronology when practical.

### Gate

The complete planned matrix and all exclusions/dispositions are recorded. Every available public bundle passes schema, leakage, identity, and budget checks. The freeze predates both final predictors. No final labels or private bounds enter either predictor's process inputs.

## Phase 9 Run inference and analyze results

### Execution

Run the frozen baseline and scheduled LLM repetitions. Account for every planned observation and repetition slot, including unavailable extraction/context and interrupted or failed requests. Resume only incomplete slots under the frozen recovery policy; do not overwrite completed attempts or retry failures selectively.

A correctness defect discovered during final execution requires an explicit amendment and a new campaign identity for corrected results. Preserve the affected campaign. Do not quietly combine outputs produced by different methods or input versions.

### Reporting

Produce a disposition table by optimization and CWE showing total planned observations, surviving/inlined/eliminated operations, unresolved truth, extraction failures, context failures, and evaluated observations.

Report exact-label correct/incorrect/abstain/unavailable counts, correct rate, coverage, and selective accuracy on clearly stated denominators. Keep source-label analysis separate. Report source-class and adjudicated binary-class balance at each level, because optimization can change the latter.

Use pair-cluster bootstrap intervals and shared resampling weights for paired method comparisons. With ten final pairs, label intervals exploratory. Do not treat treatment cells or LLM repetitions as independent source samples. Mixed-effects regression remains an optional later analysis requiring a separate justification; it is not necessary to restore the original substantive question.

Predefine a small set of contrasts, such as O1/O2/O3 versus O0 and stripped versus retained within each level. Report paired eligibility and counts. Keep broader interaction exploration secondary rather than presenting a large post-hoc testing ladder as confirmatory.

Retain collision audits, paired vulnerable/safe discrimination, per-pair results, leave-one-pair-out sensitivity, confidence/error summaries, and compute/failure accounting. Interpret source-pair discrimination alongside compiled-behavior changes: a pair whose overflow was eliminated no longer has the same binary-class contrast.

### Gate

Every output is traceable to frozen inputs and saved attempts. Static predictions recompute from the frozen baseline. Tables and figures regenerate without modifying inputs. Qualitative examples distinguish observed transformations from unsupported claims that a particular compiler pass caused an error.

## Phase 10 Release the study and update the paper

Release the final selection and exclusion record, source provenance and sanitization changes, build settings, private adjudication evidence where distributable, public bundles, baseline implementation/contracts, prompt/runtime settings, raw predictions, analysis code, and results manifest.

Update the paper around the redesigned question. State the actual number of source families, ordinary optimization settings, localization assistance, context policy, analyzer representation differences, and the information actually removed by stripping. Explain how eliminated operations and unresolved labels were handled.

A fresh final campaign prevents further tuning to its outcomes; it does not establish that a pretrained LLM has never encountered public Juliet examples. Keep claims bounded to the sampled benchmark and tested toolchain. More realistic source structure improves the experiment's alignment with the original proposal without making the corpus representative of all production software.

Gate: the manuscript's sample counts, endpoint definitions, tables, limitations, and version identifiers agree with the released artifacts. Historical 80-observation results appear only as a separate earlier experiment if discussed.

## Effort and scheduling

These are planning ranges for focused engineering work, not guaranteed elapsed times. The pilot determines the credible schedule.

| Work package | Initial allowance |
|---|---:|
| Contract, workspace, and parameterization | 0.5–1 day |
| Juliet import, sanitization, and build support | 1–2 days |
| Mapping, oracle, and multi-function extraction | 2–4 days |
| Baseline feasibility and implementation | 1–3 days |
| LLM integration and end-to-end pilot | 1–2 days |
| Final preparation, adjudication, freeze, and release | 1–3 days plus inference |

The ranges overlap where work is independent. A bounded implementation may fit roughly one to two focused weeks; difficult mapping, baseline integration, or manual adjudication can extend it to two to four weeks. Inference time must be estimated from the measured pilot token counts and throughput. The previous single-function campaign is not a reliable direct forecast for larger bundles.

The critical path is source preservation → transformed-code mapping → public context → pilot validation → method lock → final freeze. Increasing optimization levels alone is a small part of the work.

## Immediate implementation order

1. Finalize Phase 0, especially binary versus source endpoints and unknown/eliminated-case handling.
2. Create the isolated redesign workspace and remove hardcoded matrix assumptions.
3. Import one stack and one heap pilot with direct helper calls, preserving their original logic.
4. Demonstrate all four optimization levels and both symbol conditions, with private mapping and complete public context.
5. Choose the baseline engine from that concrete evidence, then integrate the LLM and complete the pilot.

The first milestone is a reviewed 32-observation pilot with an honest disposition table. The final ten-pair campaign begins only after that milestone settles the design.

## Reference resources

- [NIST Juliet C and C++ 1.3](https://samate.nist.gov/SARD/test-suites/112) — upstream corpus and archive identity.
- [NIST Juliet 1.3 changes and known issues](https://www.nist.gov/publications/juliet-13-test-suite-changes-12) — benchmark limitations to consider during selection and review.
- [GCC 15.2 optimization options](https://gcc.gnu.org/onlinedocs/gcc-15.2.0/gcc/Optimize-Options.html) — treatment settings; preserve the actual compiler's effective option inventory.
- [angr reaching-definitions documentation](https://docs.angr.io/en/stable/api/angr.analyses.reaching_definitions.reaching_definitions.html) — candidate analysis infrastructure, subject to pilot validation and version pinning.
- [BinCAT](https://github.com/airbus-seclab/bincat) — alternative binary-analysis infrastructure if integration is justified.
- [IKOS input and analysis documentation](https://github.com/NASA-SW-VnV/ikos/blob/master/analyzer/README.md) and [Cppcheck](https://github.com/cppcheck-opensource/cppcheck) — possible source-validation tools; not substitutes for the proposed GCC-binary baseline when run on source.
