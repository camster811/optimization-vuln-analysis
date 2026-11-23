# LLM representation study

Data location update: current inputs/sources are now in `data/`, completed runs and
accepted analysis in `results/`, and older material in `artifacts/history/`.
The [migration record](data_migration.md) accounts for every former `redesign/` file.

Current maintenance status: [R6](refactor_r6_report.md) completes the standalone
study cleanup. Freeze/release workflows, environment/source snapshots and automation
are outside the active project. Use the [repository guide](../../README.md) and
[data locations](data_locations.md) for current commands. The scientific phases and
R0–R5 reports below are dated history; they do not require continuing those workflows.

Prepared November 21, 2026; status updated November 23, 2026. Repository cleanup and [Phases 0](phase0_report.md), [1](phase1_report.md), [2](phase2_report.md), [3](phase3_report.md), [4](phase4_report.md), [5](phase5_report.md), [6](phase6_report.md), [7](phase7_report.md), [8](phase8_report.md) and [9](phase9_report.md) are complete. All 1,440 final dispositions and 480 aggregates verify. The final input freeze and paired analysis reproduce offline. [R0](refactor_r0_report.md) completes internal release packaging and the pre-refactor preservation gate. Manuscript and research-documentation work remain Phase 10.

The study compares assembly, Ghidra decompilation and their combination on the same reviewed binary observations, with an always-no-overflow control. All three LLM conditions ran afresh. Exact correctness is 45.00% assembly, 77.50% decompilation, 71.25% combined and 62.50% control. The primary combined-minus-decompilation effect is −6.25 percentage points, with an exploratory family interval of −13.75 to +0.625 points. The earlier experiment remains historical evidence in its frozen release.

Start with the [phase-by-phase implementation plan](implementation_plan.md). It defines the proposed package, representation rules, common prompt and evidence format, execution and scoring contracts, acceptance gates and release requirements.

The [repository refactor plan](refactor_plan.md) is separate from the scientific phases. [R1](refactor_r1_report.md) completes shared serialization/artifact interfaces with 500 passing tests and byte-exact saved outputs. Historical verification uses the [R0](refactor_r0_report.md) saved method; refactored source identities are recorded independently.

[R2](refactor_r2_report.md) separates inference helpers from protocol settings and retains both response decoders. Its 58 critical checks passed; the full suite and campaign replay were not rerun under the requested limited test scope.

[R3](refactor_r3_report.md) separates saved replay from execution, removes private helper coupling and passes 25 critical checks. The remaining cleanup emphasizes a smaller, readable active repository with its intended behavior retained; further model runs and result collection are outside the work.

[R4](refactor_r4_report.md) separates parent interpretation and shared source/resource capture. Copied accepted pilot packets and relocated parent releases no longer require original build paths; 23 critical checks passed.

[R5](refactor_r5_report.md) consolidates active code under `src/optimization_vuln_analysis/`,
packages protocol resources, retires the unused original runner/decoder and moves shared
fixtures to `tests/support/` and `conftest.py`. See the [repository guide](../../README.md)
for installed commands and separate offline/evidence checks.

The [analysis contract](analysis_plan.md) records the dated design decisions and dependency map. The [representation specification](representation_spec.md) defines the initial field and evidence boundaries. The [initial policy](../../src/optimization_vuln_analysis/studies/representation/policy.json) preserves the parent model and full sampler settings at 12,288 context / 4,096 completion tokens; it is explicitly unbound and cannot establish execution readiness.

The [Phase 1 report](phase1_report.md) documents the thin inventory adapter, accepted input preparation, 160/480/1,440 inventory gate and offline verification commands. The initial policy stays unchanged; the preparation manifest records the completed input binding. Final execution readiness remains a later gate.

The [Phase 2 report](phase2_report.md) records the projection/schema, stable line references, private lineage maps and two independent byte-identical final view exports. It includes offline verification commands. These are untokenized views; token fit and common eligibility remain pending preflight.

The [Phase 3 report](phase3_report.md) records the common prompt/response schema, strict decoding, visible-reference validation and reused transport/voting helpers. All 1,440 requests were constructed offline and fabricated responses cover all 480 views; these are engineering checks, with no live inference or final payload freeze.

The [Phase 4 report](phase4_report.md) records durable no-retry dispatch, common input blocking, verified restart events, exclusive ownership and offline replay. Its engineering request packet had 1,440 pending slots at that gate. Its separate completed synthetic execution is engineering evidence, not study predictions.

The [Phase 5 report](phase5_report.md) records the unconditional safe control, full-denominator four-method scoring, shared family bootstrap, matched-treatment contrasts and sensitivity analyses. The expected control score is verified at 100/160; synthetic evaluation reproduces byte for byte from copied source dependencies. All 397 offline tests pass.

The [Phase 6 report](phase6_report.md) records accepted pilot binding, 96 projected pilot views, metadata-based selection of two smoke cells and all 18 fresh engineering responses. All 408 offline tests passed before pilot generation. Saved decoding, voting and integration checks reproduce from copied source dependencies with the server stopped. Pilot outcomes are excluded from final scores.

The [Phase 7 report](phase7_report.md) records actual final tokenization, template overhead, private truth/scorer/dependency binding and byte-exact archive restoration. Four combined views exceed the unchanged 12,288/4,096-token limits, yielding 36 common-blocked slots and 1,404 requests while retaining all 160 observations. All 434 offline tests passed before sealing; no final slot had been dispatched at that gate.

The [Phase 8 report](phase8_report.md) checks the user's completed execution: 1,382 valid, six length-limited, 16 schema-invalid and 36 blocked terminal slots, with no retries or uncommitted files. The [Phase 9 report](phase9_report.md) records unchanged frozen scoring, independent recounts, all tables/figures, compute costs and predeclared qualitative examples. All 28 analysis/evidence outputs regenerate byte for byte from saved source and data with runtime access disabled. The full suite passed 443 tests; the final figure-export adjustment also passes all nine reporting tests.

The final matrix is 160 binary observations × three representations × three repetitions = **1,440 scheduled final slots**. Reusing the existing inputs does not make this an untouched evaluation corpus: its earlier predictions and judgments have already been inspected.

The source campaign is [`final-v2-context12288`](../../data/parent-study). The [original experimental contract](../juliet-redesign/analysis_plan.md) and [Phase 9 report](../juliet-redesign/phase9_report.md) explain the previous design and its limitations. The [cleanup record](cleanup_report.md) identifies the shared components retained for the smallest necessary extension and their regression checks.
