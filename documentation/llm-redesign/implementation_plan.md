# LLM representation study implementation plan

Current maintenance status: [R6](refactor_r6_report.md) completes the standalone
study cleanup. Freeze/release workflows, environment/source snapshots and automation
are outside the active project. Use the [repository guide](../../README.md) and
[data locations](data_locations.md) for current commands. The scientific phases and
R0–R5 reports below are dated history; they do not require continuing those workflows.

Prepared November 21, 2026; status updated November 23, 2026. Repository cleanup and [Phases 0](phase0_report.md), [1](phase1_report.md), [2](phase2_report.md), [3](phase3_report.md), [4](phase4_report.md), [5](phase5_report.md), [6](phase6_report.md), [7](phase7_report.md), [8](phase8_report.md) and [9](phase9_report.md) are complete. The [analysis contract](analysis_plan.md), [initial representation specification](representation_spec.md) and [policy](../../src/optimization_vuln_analysis/studies/representation/policy.json) fix the study design. All 1,440 final slots are terminal: 1,382 valid responses, six length limits, 16 schema failures and 36 common-blocked slots. All 480 aggregates replay with no retries or uncommitted files. The unchanged frozen scorer and paired analysis retain A=160 for every method; the primary combined-minus-decompilation effect is −6.25 percentage points (exploratory family interval −13.75 to +0.625). Tables, figures and review evidence reproduce byte for byte. [R0](refactor_r0_report.md) completes internal release packaging and the pre-refactor baseline; manuscript and research-documentation work remain Phase 10. Phase numbers below belong to this study and are separate from the completed Juliet redesign phases.

## Purpose and decisions

Investigate how the supplied binary-code representation affects one local LLM's classification of stack and heap buffer overflows, and how those differences vary with compiler optimization and symbol stripping.

The user selected a clean run: assembly, decompilation and combined inputs all receive fresh requests under one new protocol. Historical combined predictions are reference material, not observations in the new three-condition comparison. Use the always-no-overflow control in the main tables. Preserve hash-bound historical evidence in its frozen releases; active code contains only components needed for the representation study.

The main representation contrast is **combined minus decompilation in exact correct/adjudicated rate**: does adding assembly to recovered pseudocode improve classification? Combined minus assembly, decompilation minus assembly, each condition versus the fixed control, and optimization/symbol contrasts are secondary descriptive comparisons. Freeze this ordering before new final inference; do not select a main contrast from the observed winner.

This is an exploratory extension on an already inspected corpus. A fresh run supplies new responses, not fresh unseen families, independent adjudication or external preregistration. The study evaluates classification conditional on supplied localization and context, not whole-program discovery or superiority over established static-analysis tools.

## Inventory and retained inputs

| Item | New study contract |
|---|---|
| Parent | `data/parent-study/` (originally `final-v2-context12288`) and its accepted inputs |
| Families | Same ten final Juliet-derived families, five per source CWE |
| Build matrix | Original vulnerable/safe variants × O0/O1/O2/O3 × retained/stripped symbols |
| Binary observations | 160; each keeps its original opaque observation ID |
| Representation conditions | `assembly`, `decompilation`, `combined` |
| Observation-condition units | 480; these are not 480 independent programs |
| Repetitions | Three per observation-condition, seeds 4101/4102/4103 |
| Scheduled final slots | 1,440, including any input-blocked or failed slots |
| Fixed control | Always `not_vulnerable`; no inference requests |
| Ground truth | Existing hash-bound emitted-binary judgments; source labels remain a separate endpoint |
| Engineering pilots | Existing two pilot families, outside final scores |

Preserve source selections, original build flags, GCC/System V ABI, symbol derivatives, private localization, application closure and referenced-data extraction. Reuse accepted public bundles and private judgments by hash; no new compilation, extraction or P-code lifting is required for this study. Input-integrity problems block preparation and require a documented repair, not substitution of convenient cases.

The historical truth inventory is 28 stack-vulnerable, 32 heap-vulnerable and 100 safe observations. These numbers are verification expectations, never predictor inputs. Source provenance and actual binary classes differ because compilation can remove or change the selected operation.

## Current implementation boundary

The active implementation uses one source namespace and explicit study-data paths:

```text
src/optimization_vuln_analysis/
    common/                         # serialization, artifacts, resources, arithmetic
    inference/                      # transport, attempts, launch and runtime identity
    inputs/                         # bundle validation and historical input adapters
    studies/representation/
        inventory.py                # parent inputs and complete condition matrix
        views.py                    # public projections and visible references
        adapter.py                  # common requests and strict response decoding
        runner.py                   # preparation, preflight and durable dispatch
        replay.py                   # read-only execution/journal inspection
        scoring.py                  # control, paired comparisons and uncertainty
        pilot.py                    # accepted engineering pilot inputs
        reporting.py                # saved-result tables, figures and recounts
        policy.json
        prompt.md
        schemas/{view,response}.json
tests/conftest.py
tests/support/
documentation/llm-redesign/
```

Phases 0–9 are complete. Their dated reports describe the original implementation,
including the freeze/release steps that existed then. [R1](refactor_r1_report.md)
through [R6](refactor_r6_report.md) record the subsequent cleanup. The current
project does not maintain source/environment snapshots, freeze/release workflows,
legacy package aliases or automation. No new model runs or result collection are
planned. The [data guide](data_locations.md) locates the completed inputs, execution
and accepted analysis; the [repository guide](../../README.md) describes current use.

## Representation and response contract

All conditions are deterministic projections of one validated public bundle. Start with explicit field allowlists. Model-facing inputs contain no observation/family IDs, source labels, private source/debug paths, oracle capacities, original reviews, previous predictions or expected answers. Keep the private input-to-observation mapping in the coordinator.

Shared context contains the architecture, entry address, environment assumptions, recovered public function entries/names, direct-call relationships and external target names, and the same referenced-data bytes, permissions, reference locations and recovery limitations. Names remain exactly as publicly recovered under the symbol treatment. Describe data sizes as available windows, not true object capacities. Omit recovered data-type descriptions from all conditions to avoid adding higher-level type hints to the assembly condition. Do not include a complete instruction-address inventory or function-body disassembly in shared metadata.

| Condition | Code fields allowed |
|---|---|
| `assembly` | Per-function public instruction addresses, mnemonics and operands |
| `decompilation` | Per-function Ghidra pseudocode, with deterministic line identifiers |
| `combined` | Exactly the assembly and pseudocode content supplied in the other two conditions |

Instruction machine-code bytes, high/native P-code, recovered stack-object inventories and prior predictions are omitted from every model-facing projection. Referenced **data** bytes remain shared. No extra functions, oracle-guided slices or explanatory summaries are added to an individual condition. Keep line text and ordering stable across a standalone view and its occurrence in combined.

Assign stable public references such as `A:F0001:L00001` and `D:F0001:L00001`, derived from sorted recovered function entries and the original view's line order. The new response retains `decision`, `confidence`, `evidence` and `summary`; `evidence` becomes zero to five unique visible line-reference strings. Assembly-only answers can cite A references, decompilation-only answers D references, and combined answers either. Empty evidence is permitted in all conditions. Validate against the actual supplied view, never against a hidden full-bundle address list. Reference membership verifies visibility, not the correctness of the explanation.

The allowed decisions remain `vulnerable_CWE-121`, `vulnerable_CWE-122`, `not_vulnerable` and `uncertain`, referring to feasible selected stack/heap out-of-bounds writes or their absence under the declared assumptions.

Use one prompt template and one response schema for all three conditions. Explain that a representation may be deliberately omitted and that this does not itself mean an application function is missing. Ask for compiled-behavior classification from the supplied representation, with uncertainty when bounds or feasibility cannot be established. Do not require decompilation-only responses to reconstruct unseen emitted instructions. Original source and capacity annotations remain private.

## Phase 0 — Lock the study design

Write the new `analysis_plan.md` and an initial `representation_spec.md`. Declare the matrix, primary/secondary contrasts, control, projection rules, voting, failure handling, exact-label and alert metrics, family resampling and exploratory status. Record that the corpus, historical results and prediction failures were inspected before this decision.

Use the existing model/quantization and full sampler configuration as the starting settings: DeepSeek-R1-Distill-Qwen-14B Q5_K_M, temperature 0.2, top-p 0.95, three seeds, 12,288 context tokens, 4,096 completion tokens and the existing 600-second request timeout. Bind exact model/server/template identities during preparation. Do not substitute a newer model or runtime without declaring a new configuration.

**Deliverables:** dated contract, decision record, condition/control identifiers, initial policy and dependency map.

**Gate:** the main comparison, denominator, representation boundaries and resource rules are specified before new final answers. No correctness target or requirement that combined win determines acceptance.

## Phase 1 — Isolate the study and bind inputs

Implement `inventory.py` and create the isolated package. Verify the parent input release, public records and oracle bindings without running the old predictors. Build an immutable observation ledger and all 480 observation-condition units, retaining shared family and treatment identities privately. Generate the 1,440 slot keys `(observation_id, representation, repetition)`; include representation in every path and hash identity so conditions cannot overwrite one another.

Stage predictor inputs separately from private evaluation files. Record all imported dependencies and parent hashes. Preserve existing earlier method locks, raw attempts and frozen historical releases. Retired active methods are not dependencies of this study.

**Deliverables:** parent-binding manifest, complete observation/condition/slot ledgers, input staging and dependency inventory.

**Gate:** exactly 160 observations, 480 observation-condition units and 1,440 unique slots; source treatment metadata reproduces the complete matrix; missing/changed inputs fail explicitly. Changing private truth cannot change the generated predictor input or schedule.

## Phase 2 — Implement deterministic code views

Implement the common-field and condition allowlists in `views.py`, a new view schema, stable line references and canonical serialization. Keep the parent bundle immutable. Preserve the original recovered function closure and code order; record parent/view hashes and a private line-to-original mapping for audits.

Test accidental leaks through nested metadata as well as top-level fields. Assert assembly has no pseudocode, decompilation has no instruction listing/bytes/P-code, and combined contains exactly the two standalone code views plus identical shared context. Address-like literals legitimately present in pseudocode are not automatically leaks; provenance and field origin determine eligibility.

**Deliverables:** projection code, schemas, three views per observation and an audit report.

**Gate:** independent repeated projection is byte-identical, shared context matches across conditions, code-view subset relationships hold and all final views validate without oracle input.

## Phase 3 — Implement the common LLM adapter

Write the representation-neutral prompt and line-reference response schema. Implement request construction, strict JSON/schema decoding, visible-reference validation and the existing two-of-three voting rule in `adapter.py`. Retain raw answer, raw reasoning, finish reason, usage, timing, HTTP outcome and typed validation failure.

Each request has one user message, no history, no tool calls, no prior-condition answer and no answer repair. Use the same output grammar and `cache_prompt=false` in all conditions. Preserve the instruction to treat supplied code/data as evidence rather than as directions that can change the task. Confidence does not affect voting. A malformed answer, duplicate/nonvisible reference or length termination is a failed slot, not an automatically corrected answer. A semantically wrong but structurally valid prediction remains an error to score later.

**Deliverables:** adapter, shared template/schema and unit fixtures for each representation and response status.

**Gate:** fabricated transport responses test valid answers, invalid references, empty evidence, malformed envelopes, length limits and all aggregation cases. Task wording is identical across conditions; only the supplied view changes.

## Phase 4 — Implement scheduling and durable execution

Adapt runtime helpers and implement `runner.py` for the new slot identity. Use schedule seed 20261121: sort observation/repetition blocks by SHA-256 of UTF-8 `20261121\n{observation_id}\n{repetition}`, then order the three conditions inside each block by the hash of that string plus `\n{representation}`. Resolve ties lexicographically. Thus each block's views run close together with deterministic shuffled condition order. Repetition r uses the same declared seed across conditions; seed matching does not make repetitions independent samples.

Write and sync a dispatch record before transport. Preserve every dispatched slot as terminal after success, failure or interruption; resume only demonstrably never-dispatched slots. A dispatch marker without a completed response becomes a terminal interrupted slot. Keep raw failures. Input-blocked slots have explicit records and make no request. Runtime restarts require captured identities matching the frozen computational settings and append-only restart evidence before remaining slots proceed; earlier slots are never repeated.

**Deliverables:** immutable manifests, deterministic schedule, slot state machine, offline verifier and runtime adapter.

**Gate:** fake-transport tests cover interruption before/after dispatch, restart, corrupt files, changed view/prompt/runtime, duplicate execution and concurrent runner ownership. Offline verification never sends a request or rewrites a result.

## Phase 5 — Implement controls and scoring before inference

Implement the always-no-overflow function without inspecting input content or labels. It emits an explicit safe decision for every observation; it has no artificial LLM repetitions or confidence. Because it needs no code input, it remains an available control even when LLM inputs are blocked. This new rule is explicit and differs from earlier shared-eligibility overlays. Its expected full-corpus correctness is 100/160 if the parent truth is unchanged.

Implement a four-method evaluator: three representations plus the control. Here A is the adjudicated denominator, C correct, E incorrect, U abstained and M unavailable. Preserve `A = C + E + U + M` on all adjudicated observations, including preparation and prediction failures. Each condition is evaluated over the same A, expected 160. Unresolved truth stays in the planned inventory and outside binary-label scores. No valid LLM votes yields unavailable; at least one valid vote without two matching labels yields abstention; two valid uncertain votes also yield abstention.

Report exact correct/A, coverage, selective accuracy, abstention and unavailability, plus alert TP/TN/FP/FN, recall, FPR, precision, F1 and balanced accuracy. Wrong-CWE alerts can be alert true positives and exact-label errors. Separate no-alert outcomes due to explicit safe decisions, abstention and unavailable results. Zero denominators are NA.

Use 10,000 PCG64 family-cluster draws with seed 20261019 and linear 2.5/97.5 percentiles, sharing the same family multiplicities across conditions, control, subsets and contrast sides. Never resample slots or treatment cells as independent programs. Include defined-replicate counts. Add binary-class, source-CWE, optimization, symbols and family tables, matched optimization/symbol contrasts, binary-label transitions, collision diagnostics and leave-one-family-out sensitivity. Source-label recovery remains separately named.

**Deliverables:** pure control, scorer, deterministic paired-bootstrap implementation and independently specified toy fixtures.

**Gate:** hand-countable cases verify abstentions/failures, wrong CWE versus alert scoring, three-condition alignment, shared resampling, treatment matching and empty denominators. Tests pass before final inference; prediction order or private-label mutation cannot change predictor inputs.

## Phase 6 — Validate on engineering pilots

Run all offline regression tests and project the existing two-family pilot inputs. Predeclare two live smoke cells: the vulnerable-source O0 retained observation from each pilot family. Run all three views and all three seeds for these two cells: **18 additional engineering slots**, excluded from final scoring. Select by metadata, not by a favorable historical answer.

Use the pilot to validate rendering, reference visibility, transport, parsing, timing, durable recovery and runtime feasibility. It is an integration check, not a useful accuracy estimate. Any method change creates a new identified pilot configuration; retain failed/dispatched attempts and never retry them as though they were the same slots.

**Deliverables:** pilot identities, raw smoke attempts, test evidence and a report of engineering fixes.

**Gate:** all 18 smoke slots are accounted for, each condition has at least one valid live response, and infrastructure/schema defects are resolved under a declared method version. Saved attempts regenerate their decoded and aggregate states. Correct classifications are not required for acceptance.

## Phase 7 — Preflight and freeze the complete final campaign

Render and tokenize every final request using the actual pinned tokenizer/chat template, without final generation. Freeze exact wire payloads and hashes; record prompt token IDs/counts, chat-template overhead, completion reservation, runtime/model identity, all 480 view files, private truth binding, schedule, code/dependency snapshots, prompt/schema/policy and scorer.

Use the same maximum context and completion settings for all conditions. Do not pad shorter prompts or truncate combined input. Establish one input-eligibility flag per binary observation: all three views must be valid and fit to dispatch any final view for that observation. Otherwise all nine LLM slots are input-blocked, the observation remains in A, and the unconditional control still emits safe. Publish per-view fit statistics and a common-eligible secondary analysis; never replace the full-denominator analysis with it.

Start at 12,288/4,096 tokens. If any new projection does not fit, report that before inference. Either accept the locked blocked-input policy or make a dated uniform context amendment, repeat feasibility/pilot/preflight and freeze the replacement configuration. Do not fix individual prompts or drop observations. Record actual token differences as part of the practical representation treatment, not proof of a pure syntax effect.

**Deliverables:** final method/input/evaluation freeze, eligibility ledger and detached manifest/archive.

**Gate:** no new final answer has been generated; exact inventory and eligibility reproduce; all source/runtime/input hashes match; 1,440 slots have known request-or-blocked dispositions. Do not claim a third-party timestamp from local hashes alone.

## Phase 8 — Execute all three conditions afresh

Run the frozen deterministic schedule with the new runner. Recheck identities before each dispatch and record permitted server restarts. Maintain progress counts by condition/status without changing prompts or limits in response to final correctness. Never seed a new slot from a saved historical response, copy the old combined answers or retry a terminal interruption/failure.

Preserve all 1,440 final slot dispositions even if fewer requests are actually sent because of shared input blocking. Scoring may run after terminal completion; inspection of final labels cannot trigger tuning within this campaign. A correctness repair after dispatch requires a new versioned campaign and preservation of the affected run.

**Deliverables:** raw requests/responses/reasoning, dispatch records, runtime events, usage/timing and 480 condition aggregates.

**Gate:** exactly 1,440 terminal slot dispositions and 480 aggregates verify; zero ambiguous pending slots; fresh combined results have their own new run identity and no historical response imports.

## Phase 9 — Analyze paired representation effects

Join predictions to private truth only in the evaluator. Generate the frozen primary contrast and all secondary tables, including full C/E/U/M counts, the no-overflow control, matched compiler/symbol effects, stack/heap distinctions and operation-survival transitions. Independently recount integer outcomes and agreement cases.

Record actual prompt/completion tokens, recorded runtime, failed/interrupted usage gaps and per-observation disagreements. Report combined-only successes and failures relative to each standalone view. Use a declared, non-cherry-picked selection rule for qualitative examples: order disagreement groups by frozen observation ID and select the first cases in each specified outcome category. Suggested error codes are frame-versus-object bounds, source/destination region confusion, element/byte units, infeasible paths, eliminated writes and unsupported reasoning. These codes explain reviewed examples, not mechanically verified model reasoning.

**Deliverables:** evaluation JSON, observation-condition CSV, metrics/contrasts/stability/compute tables, figures and exploratory error analysis.

**Gate:** A partitions correctly for every method, paired comparisons use identical observations and family weights, failures stay in the denominator and each published number traces to saved artifacts. New scores are not required to reproduce 78.125%; that belongs to the historical combined run.

## Phase 10 — Document the completed study

R0's technical packaging and independent restore/replay are historical completed
work. R6 removes ongoing reproduction, freezing and release-maintenance obligations
at the user's request. No new preservation framework or automation is needed.

The remaining manuscript/documentation work should describe representation
sensitivity under compiler treatments, the no-overflow control, and the corpus,
localization and adjudication limitations. Do not claim whole-program discovery
or tool superiority, call these inspected families a new held-out set, or treat
self-reported confidence as calibrated probability.

**Deliverables:** updated manuscript and research/Obsidian documentation using the
accepted analysis. A positive combined-condition advantage is not a completion criterion.

## Implementation order and completion boundary

The completed experiment implemented input, representation, response, recovery and
scoring contracts before its pilot, final execution and paired analysis. The dated
phases above record that sequence. Current maintenance is complete when the
standalone code is readable, its research data are clearly located and every
retained test passes. It requires no fresh execution or historical reproduction.

## Evidence informing this plan

- [Original experimental contract](../juliet-redesign/analysis_plan.md): localization, binary truth, dispositions and family-cluster inference.
- [Public context specification](../juliet-redesign/context_bundle_spec.md): public/private boundary and extraction scope.
- [Phase 6 integration](../juliet-redesign/phase6_report.md): token budgeting, strict validation and durable failure handling.
- [Phase 9 report](../juliet-redesign/phase9_report.md): completed results, context amendment, failures and CSV-byte verification.
- Current shared interfaces: [transport](../../src/optimization_vuln_analysis/inference/transport.py), [runtime](../../src/optimization_vuln_analysis/inference/runtime.py), [attempts/voting](../../src/optimization_vuln_analysis/inference/attempts.py) and [arithmetic](../../src/optimization_vuln_analysis/common/metrics.py). The earlier bundle runner/decoder and freeze/release interfaces have been retired.
