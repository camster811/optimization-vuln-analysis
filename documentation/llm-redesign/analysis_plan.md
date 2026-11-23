# LLM representation study: analysis contract

Dated November 21, 2026. Design version `representation-study-v1`;
study ID `llm-representation-v1`; initial configuration
`representation-v1-context12288`. Phase 0 fixes the design before any new final
answers. Input binding, executable adapters, pilots and final freezing remain
later gates. The machine-readable contract is
[`policy.json`](../../src/optimization_vuln_analysis/studies/representation/policy.json).

## Question, scope and prior inspection

On the same reviewed binary observations, how does supplying assembly,
decompilation or both affect one local LLM's classification of feasible selected
stack/heap out-of-bounds writes? How do these differences vary with optimization
and symbol stripping? Classification is conditional on supplied localization,
recovered application closure, referenced data and environment assumptions.

This is exploratory work on ten already inspected Juliet-derived families.
The corpus, source/binary judgments, historical combined predictions, prediction
failures, method-development failures and earlier input sizes were inspected before
this decision. Fresh requests do not make the families unseen. The earlier oracle
was reviewed by Codex without independent human adjudication. Family separation
does not establish absence from model training. Neither whole-program discovery,
general tool superiority nor independently preregistered inference is claimed.

All three representations receive fresh responses. Historical responses are
reference evidence and cannot fill any new slot. Positive effects, a particular
correctness rate or a combined-condition win are not acceptance criteria.

## Inventory and identities

| Item | Fixed design |
|---|---|
| Parent | `redesign/campaigns/final-v2-context12288`, verified input release |
| Families | Ten final families, five per source CWE; existing two pilots excluded |
| Treatments | Vulnerable/safe source variants × O0/O1/O2/O3 × retained/stripped symbols |
| Reference builds / observations | 80 / 160; preserve original opaque observation IDs |
| LLM condition IDs | `assembly`, `decompilation`, `combined` |
| Control ID | `always_not_vulnerable` |
| LLM method ID | `public-representation-llm-v1`, qualified by condition |
| Observation-condition units | 480; not independent programs |
| Repetitions | Three; repetition indices 1/2/3 use seeds 4101/4102/4103 |
| Final slots | 1,440, including blocked, failed and interrupted slots |
| Engineering smoke run | Two predefined pilot cells × three conditions × three seeds = 18 slots |

The smoke cells are the vulnerable-source O0 retained observation from each of
the two existing pilot families, selected from metadata before viewing new
responses. They have separate identities and never enter final scores. Initial
planned work totals 1,458 slots; any amended pilot configuration adds separately
identified slots.

Reuse accepted public bundles and private emitted-binary judgments by hash.
Preserve source selections, GCC/System V ABI, build flags, symbol derivatives,
private localization, function closure and data extraction. No rebuilding,
extraction or lifting is needed. Missing or changed input blocks preparation
until a documented repair; never replace an inconvenient observation. The parent
freeze, input archive and policy identities are recorded in the initial policy;
complete per-observation/oracle binding belongs to Phase 1.

Model inputs contain no observation/family/treatment identifiers, source labels,
private paths, capacities, reviews or expected/prior answers. Private mappings and
truth are coordinator/evaluator inputs. Changing private truth must not change
predictor inputs or the schedule. Exact code-view and shared-field boundaries are
fixed in the [representation specification](representation_spec.md).

## Ordered contrasts

The sole primary contrast is **combined minus decompilation in exact correct /
adjudicated rate**, paired on the same observations. This asks whether assembly
adds classification value to recovered pseudocode. Differences are calculated as
fractions and displayed in percentage points.

Secondary descriptive contrasts are combined minus assembly, decompilation minus
assembly, each LLM condition minus the fixed control, and matched optimization
and symbol effects within each of the four methods. This ordering is fixed before
new final responses and cannot be changed to follow an observed winner. Report
estimates and exploratory intervals; no hypothesis-testing ladder, multiplicity
claim or confirmatory significance threshold is introduced.

## Decisions, control and voting

Allowed response decisions are `vulnerable_CWE-121`, `vulnerable_CWE-122`,
`not_vulnerable` and `uncertain`, interpreted against compiled behavior under the
declared assumptions. The first two identify the destination object's stack/heap
region. Source provenance is not the binary label.

`always_not_vulnerable` returns `not_vulnerable` for every observation without
inspecting its content, labels or eligibility. It is always available, including
when LLM inputs are blocked, and has neither fabricated repetitions nor confidence.
The parent truth expectations are 28 stack-vulnerable, 32 heap-vulnerable and 100
safe observations: the control is therefore expected to score 100/160 = 62.5%.
These counts are integrity checks, never predictor inputs or acceptance targets.

Each LLM aggregate accounts for exactly three terminal slots. Two matching valid
labels establish the decision regardless of confidence. Two valid `uncertain`
votes produce abstention. Any valid votes without two matching labels also produce
abstention; zero valid votes produce unavailable. Confidence is the median of
all valid votes, including nonmajority votes, solely for descriptive reporting.
Self-reported confidence is not a calibrated probability.

## Denominators and metrics

Keep every planned observation in the inventory. Primary truth is the reviewed
emitted-binary label. Unresolved truth stays in the inventory and truth-availability
tables, outside binary-label metrics. For every method and every adjudicated
subset, enforce `A = C + E + U + M`: adjudicated, exactly correct, exactly incorrect,
abstained and unavailable. Expected full-corpus A is 160 for each method. Input
blocking, preparation failures and prediction failures never reduce A.

Exact correct rate is C/A; coverage is (C+E)/A; selective accuracy is C/(C+E);
abstention and unavailability are U/A and M/A. Always show integer C/E/U/M counts
and the denominator alongside rates. An unavailable control due to LLM eligibility
would violate this contract.

For alert metrics either vulnerable decision is an alert. Explicit safe,
abstained and unavailable outcomes are no alerts, reported separately. A wrong-CWE
alert can be an alert true positive and an exact-label error. Compute TP/TN/FP/FN,
recall TP/(TP+FN), FPR FP/(FP+TN), precision TP/(TP+FP),
F1 2TP/(2TP+FP+FN), and balanced accuracy (recall + 1 − FPR)/2.
Zero denominators yield NA, including balanced accuracy when either binary class
is absent. Abstention or unavailability does not establish safety.

Report full-denominator results first and common-input-eligible results second.
Also report binary class, source CWE, optimization, symbols and family tables;
truth/operation-survival transitions; input collisions; and leave-one-family-out
sensitivity. Source-label recovery uses original source labels as a separately
named endpoint and retains failures. It is not binary vulnerability accuracy.

For optimization contrasts match O1/O2/O3 against O0 by family, source variant and
symbols. For stripped-minus-retained match by family, variant and optimization.
Require adjudicated binary truth on both sides, score each against its own binary
truth, retain prediction/input failures, and report matched cells/families,
omissions and label/availability/operation transitions. Missing partners do not
silently disappear.

Within each representation, diagnose exact predictor-input equality groups and
conflicting binary/source labels. Sensitivity excluding all members of conflicting
groups accompanies, and never replaces, the primary analysis. Preserve parent
scope/collision diagnostics separately. For each standalone condition, define two
qualitative groups: combined correct with standalone not correct, and standalone
correct with combined not correct. Not correct includes errors, abstention and
unavailability on adjudicated observations. Select exactly the first frozen
observation ID in each group (up to four examples), and report empty groups as
empty. Duplicate selections may be discussed once with both group memberships.
Examples explain saved answers without proving their reasoning mechanically correct.

## Family resampling

Use NumPy PCG64 seed 20261019 for 10,000 replicates. Each replicate samples ten
families with replacement from the lexicographically sorted final family IDs.
Every observation in a sampled family receives that family's multiplicity. Share
the same draws across all four methods, subsets and contrast sides. Never resample
slots, source variants or treatment cells as independent programs.

Compute the observed estimate with unit family multiplicities. Percentile bounds
are the 2.5th and 97.5th percentiles of finite replicate estimates with linear
interpolation, excluding the observed estimate. Disclose defined-replicate counts;
all-undefined intervals are NA. Ten homogeneous family clusters support exploratory
stability assessment, not confirmatory population claims.

## Requests, resources and durable execution

Start with DeepSeek-R1-Distill-Qwen-14B Q5_K_M and the parent's expected GGUF
SHA-256, full sampler settings, llama.cpp configuration and reasoning format.
Temperature is 0.2, top-p 0.95, context 12,288, completion reservation 4,096 and
request timeout 600 seconds. The initial policy copies all 24 sampler fields and
their exact numeric values and order from the parent. Bind the actual model,
server, libraries, source, tokenizer and chat template during preparation; no
newer model/runtime substitution is implicit.

Use the same task wording, output grammar and resource limits in all conditions;
one user message per request, no history/tools/prior answers, `cache_prompt=false`,
and no answer repair. Treat supplied code/data as evidence, never task instructions.
Save raw answer/reasoning, response body, HTTP status, finish reason, usage, timing
and typed validation failures. Malformed JSON/envelopes, duplicate/nonvisible
references, schema failures, empty answers, length termination, transport failures
and timeouts fail the slot. A structurally valid wrong answer remains a scored error.

Schedule seed is 20261121. Sort observation/repetition blocks by SHA-256 of UTF-8
`20261121\n{observation_id}\n{repetition}`; sort conditions within each block by
SHA-256 of that string plus `\n{representation}`. Resolve ties lexicographically
by observation ID/repetition and condition ID respectively. Matching seeds across
conditions do not make repetitions independent samples. Include condition in
every slot identity, path and request binding.

Render and tokenize all final requests before final generation with the actual
pinned template/tokenizer. All three views must be valid and fit for an observation
to dispatch any of its nine slots. Otherwise record all nine as input-blocked,
retain the observation in A and still emit the control. Do not truncate, pad,
substitute or selectively drop inputs. Report per-view fit/token statistics and
actual prompt/completion tokens as part of the practical treatment; the comparison
does not isolate syntax from token volume. Report any nonfitting projections before
inference. Accept the declared blocking rule or issue a dated uniform context
amendment, then repeat feasibility, pilot, preflight and freeze.

Sync a dispatch record before transport. Every dispatched slot is terminal after
success, failure or interruption, with no retry. A dispatch record lacking a
completed response becomes terminal interrupted. Resume only provably never-dispatched
slots. Runtime restarts require matching frozen computational identities and
append-only restart evidence before remaining dispatches. Preserve all 1,440
dispositions, 480 aggregates and compute/usage gaps; offline verification sends
no requests and rewrites no saved result.

## Decision record, dependencies and amendments

All decisions below are dated November 21, 2026 and precede new study responses.

| ID | Decision and reason |
|---|---|
| D01 | Fresh three-condition run; historical combined answers cannot enter the comparison |
| D02 | Combined-minus-decompilation is primary; secondary ordering cannot follow results |
| D03 | Full adjudicated denominator and unconditional safe control expose failure/coverage costs |
| D04 | Shared closure/data and allowlisted code views constrain the representation treatment |
| D05 | Preserve parent model/samplers, use uniform 12,288/4,096 limits and matched seeds |
| D06 | Ten-family paired resampling respects the corpus's dependence structure |
| D07 | Durable terminal dispatch and separate smoke slots preserve failures and chronology |
| D08 | Reuse tested primitives with local adapters; create only modules that a required contract needs |

| Dependency boundary | Reuse and required local adaptation |
|---|---|
| `redesign.pipeline.inventory` | `read_json`, `strict_json`, `digest`, `local_path`, `require`; bind parent inventory rather than regenerate final IDs from the development manifest |
| `redesign.pipeline.bundles`, `sanitize`, bundle schema | Validate immutable parent bundles; `canonical` serializes views; projections use their own schema and recursive allowlists |
| Root `pipeline.run_llm` | Reuse `send_request`, `usage_counts`, `canonical_json`; explicit policy, no root-config discovery |
| Root `pipeline.serve_llm`, `pipeline.runtime` | Reuse launch/model/process/listener/source/property identity with explicit arguments and captured new-run evidence |
| `redesign.pipeline.llm` | Reuse `aggregate`; adapt settings, request construction and decoding locally for new method IDs and visible line references |
| `redesign.pipeline.llm_runtime` | Reuse `write_new`, explicit-policy `budget`, `capture`, `verify_live`; new orchestration binds the new policy and supports verified restarts |
| `redesign.pipeline.run_llm` | Reuse `wire`; its pilot dispatch/recovery pattern is tested but needs condition identity, the new schedule and offline-only verification |
| `redesign.pipeline.metrics` | Reuse `divide`, `statistics`, `interval`; create condition-neutral event construction, shared family draws and four-method reporting locally |
| Environment | Pin `requirements.txt`, Python, model and llama.cpp binary/libraries/source/template/tokenizer at preparation/freeze; no new compiler or Ghidra execution |

This is a dependency map, not an already frozen dependency inventory. Record actual
transitive imports and source/environment hashes when implemented. Existing reuse
checks are listed in the [cleanup record](cleanup_report.md); do not weaken old
validators or alter frozen methods to fit the extension.

Amendments record date, reason, changed rule, evidence already inspected, affected
configuration and consequences for existing attempts. After dispatch, correctness
repairs require a new versioned campaign and preserved affected outputs; never mix
method versions. Phase 0 completion authorizes no claim that later gates have
passed. Final release must reproduce saved decoding, votes, evaluation, tables and
figures byte for byte in a fresh directory without inference or workspace fallback.
Local hashes/timestamps bind content but supply no third-party timestamp authority.
