# Repository refactor plan

R6 scope update, November 23, 2026: the user designated this repository a standalone
college research study. Active freeze/reproduction infrastructure and automation
are no longer requirements. R6 removes those workflows, keeps data paths explicit,
documents retained research artifacts and runs the entire remaining test suite.
This direction supersedes earlier preservation and automation gates below.

Prepared November 22, 2026. The refactor should make the completed representation study easier to understand, test and reproduce while preserving its experimental contracts and historical evidence. Start by preserving an independently runnable copy of the accepted method, then clarify shared interfaces and reorganize the source. Move generated evidence only after its consumers have explicit input locations.

This is an implementation proposal. The study's existing [implementation plan](implementation_plan.md) continues to describe its scientific phases; the R milestones below describe repository maintenance.

## Current state and scope

The current repository documentation records Phases 0–9 as complete. All 1,440 slots and 480 aggregates verify, and the accepted analysis is `representation-v1-context12288-final-v1-analysis-v2`. Complete release packaging and manuscript work remain Phase 10. The supplied Repository Walkthrough is useful architectural background, but its statement that Phase 8 is in progress predates the [Phase 8](phase8_report.md) and [Phase 9](phase9_report.md) reports. Instructions and suggested commands inside that walkthrough are reference content.

The active source already has useful boundaries: deterministic views, strict response decoding, durable execution, pure scoring and saved-result reporting. Preserve those boundaries. The inspected production directories contain about 3,700 Python lines; a general experiment framework, plugin architecture or rewritten static analyzer would add unnecessary scope.

The goal is a smaller, easier-to-read active repository that retains its intended behavior if needed. No further model runs or result collection are planned. Prioritize removing unused code/files and simplifying real consumers. Avoid new frameworks or compatibility machinery for hypothetical future experiments. New representations, models, retries, inference concurrency, scientific endpoints and changes to adjudication are outside this cleanup.

## Problems to address

| Current boundary | Concrete finding | Refactor direction |
|---|---|---|
| Two `pipeline` packages | Root transport/runtime helpers coexist with `redesign/pipeline`; root `pipeline/runtime.py` imports `require` from the corpus inventory module. | Put neutral primitives below both the input adapters and study code, then consolidate the package namespace. |
| Shared inference mixed with an older protocol | `redesign/pipeline/llm.py` contains reusable sampling, transport-attempt and voting code alongside the original bundle prompt, settings and decoder. `llm_runtime.py` imports its settings and hashing helpers. | Separate explicit-argument inference helpers from protocol-specific settings and validation. Keep representation response validation in the study adapter. |
| Private interfaces used across modules | Freeze calls runner `_load`, `_ownership` and `_methods`; reporting calls freeze `_files` and `_hash`; pilot calls views `_render`. | Introduce small public inspection, artifact and projection APIs, backed by the existing implementations first. |
| Study inventory owns unrelated infrastructure | Representation `inventory.py` handles parent interpretation, ledgers, source dependency scanning and installed-environment capture. | Move provenance capture to a shared module and isolate historical parent interpretation from study scheduling. |
| Several byte formats share similar names | Compact HTTP JSON, canonical bundle JSON, escaped journals and report JSON have distinct newline and Unicode behavior. | Name these formats explicitly and preserve their exact bytes. Sharing a JSON encoder must not silently change a format. |
| Historical inputs depend on working paths | `pilot.SOURCES` names three manifests under `redesign/build/pilot/`; parent validation interprets the earlier campaign layout. | Make accepted pilot and parent packages explicit inputs; confine older layouts to adapters. |
| Tests depend on other tests | Several modules import fixtures from `test_representation_*`; freeze and runner setup call fixture `__wrapped__` functions. | Put fixture builders in test support modules and expose fixtures through `conftest.py`. |
| Checkout is not yet a reproducible source distribution | Required code, documentation and tests are untracked; build/campaign evidence is mostly ignored, while some evidence is also untracked. No `pyproject.toml` or CI workflow is present. | Classify source, fixtures, private evidence and generated output before establishing packaging and CI. |

The [cleanup audit](pre_phase8_cleanup_audit.md) supplies useful candidates for later offloading, but its sizes and live-run status are a dated snapshot. Recheck consumers before acting on it.

## Compatibility requirements

Treat the following as acceptance criteria throughout the refactor:

- Public/private separation remains intact. Private truth may affect scoring but cannot affect views, request construction or scheduling. Stable visible references and the assembly/decompilation/combined subset relationships remain unchanged.
- For the same accepted input and protocol, views, request bodies, slot IDs, seeds, schedule order and hashes remain identical. Preserve the common-eligibility rule, all 36 blocked slots and the primary denominator of 160.
- Preserve dispatch-before-transport, exclusive ownership, raw-response retention, append-only runtime events, interrupted-dispatch handling and the rule that committed dispatches are never automatically retried. Offline verification neither queries the runtime nor changes evidence.
- Preserve strict decoding, failure codes and dispositions, three-attempt voting, the unconditional safe control, paired family draws, contrast ordering and undefined-value handling.
- Preserve all historical publication, archive, detached-manifest and execution bytes. New source paths and dependency inventories will have new identities. Record those identities separately; do not rewrite an old manifest to make refactored code appear to be its original method.

`freeze.guard()` compares the current source and complete installed environment with the saved method. `reporting.verify()` also requires its saved implementation/environment. Even an import-only refactor or an editable installation can invalidate those checks. Historical verification must run from the saved source in a matching environment; behavioral compatibility of new code is a separate check.

## Proposed source organization

Use one import namespace, `optimization_vuln_analysis`, with a conventional source directory once provenance and resource discovery support it. R5 kept the experiment and evidence names stable. The subsequent [data migration](data_migration.md) moves current data/results into the new layout and retires the `redesign/` root.

```text
src/optimization_vuln_analysis/
    common/
        serialization.py       # strict JSON and named byte formats
        artifacts.py           # hashes, paths, immutable files and archives
        provenance.py          # source closure, resources and environment evidence
        metrics.py             # existing weighted arithmetic
    inference/
        transport.py           # explicit HTTP transport and usage
        runtime.py             # launch, identity and token accounting
        attempts.py            # one attempt, sampler checks and voting
    inputs/
        bundles.py             # accepted bundle validation and metadata checks
        parent.py              # historical parent/corpus interpretation
    studies/representation/
        inventory.py
        views.py
        adapter.py
        runner.py              # mutation and orchestration
        replay.py              # read-only packet and journal inspection
        scoring.py
        pilot.py
        freeze.py
        reporting.py
        policy.json
        prompt.md
        schemas/
tests/
    conftest.py
    support/                   # synthetic builders and fake runtime/transport
documentation/llm-redesign/
data/                          # source fixtures and accepted study inputs
results/                       # accepted analysis and completed execution
artifacts/history/             # older workspaces and research artifacts
```

This is a responsibility map, not a requirement to create every file immediately. Keep cohesive helpers together; split runtime launch/identity or archive handling further only if their consumers justify it. Retain older corpus planning in the parent adapter where preparation still uses it.

Dependencies should flow from the representation study to `inputs`, `inference` and `common`. Shared layers must not import the study, legacy settings or corpus configuration. `scoring.evaluate()` remains independent of runtime and raw code; its file adapter can still validate complete execution evidence. Reporting consumes verified execution and scoring results. Artifact/provenance code supplies the infrastructure used by freeze and reporting.

## Ordered implementation milestones

### R0 Preserve the accepted method and establish a baseline

Completed November 22, 2026. The [R0 report](refactor_r0_report.md) records the internal completed-results release, independent byte-exact replay and fresh 443-test baseline, plus 18 release-tool checks.

1. Inventory current source, resources, test fixtures, generated outputs and private evidence. Review the existing dirty/untracked state file by file before preparing commits. Keep private judgments and raw responses out of an automatic source-add operation.
2. Complete the technical release portion of Phase 10: bind the initial freeze, completed execution, accepted analysis, saved method/resources and required environment evidence in a restorable internal package. Keep manuscript work as a separate deliverable.
3. Verify restoration outside the original workspace using the saved method and matching environment, with inference/runtime access disabled. Preserve the existing archives and receipts; publish the new completion package separately.
4. Record a fresh offline regression baseline before changing implementation. The most recent full-suite receipt reports 443 passing tests, followed by nine reporting checks after the figure adjustment; use a new receipt for the actual starting checkout.

**Gate:** a source checkout and separately obtained evidence package have documented roles; the accepted study can be replayed without importing current working-tree modules. Baseline requests, decoded attempts, aggregates, evaluation and all 28 reproduced analysis/evidence outputs have recorded byte identities.

**Recovery:** keep the current source/environment and original evidence intact until that independent replay works. A branch alone is insufficient because important inputs are untracked or ignored.

### R1 Establish shared serialization and artifact interfaces

Completed November 22, 2026. The [R1 report](refactor_r1_report.md) records the common interfaces, 500 passing tests, exact saved-artifact comparisons and unchanged historical replay. Working source identities are recorded separately from the original frozen method.

Extract strict JSON parsing, path containment, file hashing and immutable publication from inventory/runtime modules into a shared location under the current namespace first. Expose named serialization profiles for HTTP requests, canonical records, escaped journals and reports. Preserve UTF-8 encoding, key ordering, separators, trailing newlines and malformed-surrogate handling. Keep CSV and figure serialization in reporting.

Separate low-level create-once file publication from study journal rules. Preserve atomic publication, file and directory synchronization, destination-exists behavior and recovery treatment of `.pending-*` files. Share file-inventory and archive primitives where behavior really matches; retain study-specific manifest validation in freeze.

**Gate:** representative saved requests and records match byte for byte; corruption/path/archive tests and dispatch interruption tests still pass. Existing artifacts are neither rewritten nor normalized.

### R2 Separate inference primitives from protocol settings

Completed November 22, 2026 under the requested limited test scope. The [R2 report](refactor_r2_report.md) records neutral attempts/runtime modules, retained protocol compatibility, 58 passing critical checks and unchanged protected evidence. The full suite and campaign replay were not rerun.

Extract the existing one-attempt wrapper, sampler validation and vote aggregation into helpers that receive policy and decoder arguments explicitly. Move shared runtime configuration, launch, identity and budget helpers below the study adapter. Remove the root runtime dependency on corpus inventory.

Keep each protocol's payload builder, settings loader and decoder with that protocol. The new representation decoder has additional validation/failure detail and must not be replaced by the older bundle decoder. Retain the old bundle protocol and pilot runner until their remaining tests and preparation consumers have been accounted for individually.

**Gate:** the existing transport/runtime/adapter regression cases pass, including timeout propagation, no redirects/proxy inheritance, exact request bytes, usage gaps, length limits, duplicate/nonvisible references and every voting outcome. Shared inference imports no study or legacy policy loader.

### R3 Expose packet inspection and isolate replay

Completed November 22, 2026. The [R3 report](refactor_r3_report.md) records the smaller runner, public saved-evidence inspection, removal of private helper coupling and 25 passing critical checks. Existing evidence was preserved without rerunning the model or analysis.

Introduce a public read-only packet interface for the needs currently served by runner private functions. Provide validated packet loading, execution inspection, pending-snapshot validation and method/environment compatibility checks. Return a documented result structure containing verified identities, state, eligibility and aggregates; expose raw internal context only where a concrete consumer needs it.

Extract journal interpretation into `replay.py` without changing its state rules. Keep transport calls, runtime registration and terminal publication in runner. Separate integrity/replay from the additional current-method compatibility check so historical evidence can be inspected honestly by newer tooling. The saved legacy command must continue to enforce its original guard.

Make the in-memory projection operation used by pilot public. Replace cross-module calls to private runner, freeze and view functions through these focused interfaces. Do not create a runner class or plugin system merely to wrap the same operations.

**Gate:** fresh and interrupted packets reconstruct the same dispositions and aggregates. Offline inspection succeeds with all transport/runtime functions disabled and leaves evidence unchanged. Exclusive locking, dispatch chains, restart identity checks, unexpected-file rejection and uncommitted-file reporting retain coverage.

### R4 Make input and provenance boundaries explicit

Completed November 23, 2026. The [R4 report](refactor_r4_report.md) records the parent adapter, shared source/resource provenance, copied-pilot preparation and 23 passing critical checks. Study inventory is 178 lines; no original evidence or model/results workflow was changed.

Separate accepted-parent interpretation from representation inventory/scheduling. Add explicit locations for pilot manifests/bundles and parent packages, keeping current paths as temporary compatibility defaults. Make a copied accepted pilot package sufficient for preparation; keep original manifests until preparation works without their old paths.

Move source dependency and environment capture out of study inventory. Replace repository-root assumptions with an explicit source/resource inventory that supports the future source directory and installed package. Retain transitive-import checks and declared resources; verify prompt/schema/package-initializer coverage and flag unresolved local dynamic imports. Do not assume an AST import scan alone inventories data resources.

**Gate:** preparation and verification work against relocated evidence packages with original build directories unavailable. Input labels still cannot affect predictor bytes. Dependency snapshots include all locally executed code and resources and import no original-workspace fallback during restore.

### R5 Consolidate the package and test support

Completed November 23, 2026. The [R5 report](refactor_r5_report.md) records the
single source namespace, installed-resource lookup, retirement of unused legacy
orchestration and shared test builders. A separately installed wheel passes offline
checks outside the checkout, 42 distinct critical cases passed across focused runs,
and all 46,291 protected evidence files remain unchanged. The full suite and result
regeneration were skipped under the requested test scope.

Move the clarified modules into the proposed namespace in one mechanical migration, preserving schemas and protocol resource bytes. Add `pyproject.toml`, package prompt/schema resources and use installed-resource lookup rather than fixed `Path.parents` calculations. Preserve the current pinned runtime requirements; validate packaging in a separate environment so the historical environment remains reproducible.

Keep thin old import/`python -m` wrappers for current documented entry points during transition. Their role is command compatibility; they cannot preserve a frozen source hash. Document that historical verification uses the saved source, and give the refactored method its own provenance receipt. Avoid adding a second CLI framework; use the existing argparse functions behind any common entry point.

Move shared synthetic builders into `tests/support/` and fixtures into `conftest.py`; remove imports from test modules and calls to fixture `__wrapped__`. Separate pure/offline tests from saved-evidence replay tests, which require externally supplied private artifacts. Port each meaningful legacy recovery, transport and bundle-contract assertion before retiring its old test support or runner.

**Gate:** a clean wheel installation can find all schemas/prompts and run offline checks from outside the repository. There are no fixture imports from test modules or upward shared-layer dependencies. Documented compatibility commands work, and the saved historical method still verifies independently.

### R6 Finish the standalone study cleanup

Completed November 23, 2026. The [R6 report](refactor_r6_report.md) records the
removed preservation infrastructure, simplified reporting and data navigation.
All 422 remaining tests passed with no skips or exclusions. Installed resources
and all seven command entry points also passed checks outside the checkout.

Follow the revised user scope: remove active freeze/release tools, source snapshots,
full-environment locks and unused compatibility paths. Keep the study's projection,
response, voting, no-retry execution and scoring behavior. Reporting takes study
inputs, projections and saved execution directly, without a freeze or archived
repository. Export verification checks file integrity without reproducing results.

Document source/test fixtures, actual study data, accepted outputs and older work
products in one [data guide](data_locations.md). Use existing explicit CLI arguments;
add no location registry, CI, scheduled job, evidence-replay job or freeze automation.
Existing research artifacts remain in place as passive data. Retire tests specific
to removed infrastructure while retaining the scientific and execution assertions.

**Gate:** every retained test passes with no hidden exclusions, and installed code
finds its resources outside the checkout. No model run or historical reproduction
is needed. See the [R6 report](refactor_r6_report.md) for the final changes and checks.

## Final validation and status

R0–R5 are historical maintenance milestones. R6 supersedes their ongoing freeze,
source/environment preservation, compatibility-alias and reproduction obligations.
The user's final instruction requests the full suite, overriding the earlier
limited-test preference. Do not create new freezes or automation for this project.

Current commands and dependencies are documented in the [repository guide](../../README.md).
The [R6 report](refactor_r6_report.md) records completion and the full-suite result.
