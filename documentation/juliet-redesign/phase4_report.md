# Phase 4: public multi-function context

Implemented October 19, 2026, following the [Phase 4 implementation plan](phase4_implementation_plan.md) and [public bundle specification](context_bundle_spec.md). No final assignments or predictor runs occurred. Phase 3 sources, compiler configuration, artifacts and oracle reviews are unchanged and still verify.

## Implementation

The new `redesign.pipeline.export_context` coordinator accounts for the declared observation inventory and stages each analysis ELF under a neutral filename. Its localization tickets contain only an opaque observation ID, analysis-artifact hash and reviewed entry address. A separate worker process imports that artifact into a fresh Ghidra 12.1.4 project with the x86-64/GCC compiler specification. No source label, capacity, private function name/list, debug reference or oracle instruction range is passed to the worker.

`ConfigurePublicAnalysis.java` disables external debug recovery before analysis; `ExtractBundle.java` checks the disabled state and exports an entry-rooted address-based closure. External library autoloading is explicitly disabled. Ghidra's public type/function-identification databases remain enabled and are hashed with its libraries, x86 language definitions, decompiler and Java identity. Fresh per-job settings prevent a prior project from donating restored names. Both retained and stripped inputs are analyzed independently.

The closure includes application/support functions, compiler clones, native tail transfers, all recovered body ranges, inlined behavior through containing functions, assembly/instruction bytes, separate decompilation statuses, direct call edges, unresolved transfers and direct referenced data. External/PLT bodies are excluded; application wrappers in `.text` remain included even if identified as thunks. Data includes exact initialized/zero-filled bytes, recovered or explicitly unknown extents, referring sites and independently checked string-prefix decoding. Public interpretation notes explicitly distinguish recovered types/windows from proven object bounds.

The strict schema is [bundle-v2.json](../../redesign/schemas/bundle-v2.json). `bundles.py` checks canonical structure/order, ranges and instruction membership, public ELF code/data bytes, relationship closure, decoded literal consistency, known private metadata and cross-function evidence references. Availability and omission fields are explicit. Budgets apply uniformly; no available context is silently cropped. Unknown code transfers, unreadable required static data, engine failures and decompilation failures remain unavailable under the conservative development policy.

## Pilot results

The accepted runs are `phase4-c` and `phase4-d`. Each contains all 32 declared observations; every canonical public record is byte-identical across these two independent fresh-project extractions. The first run's records are published under `redesign/data/pilot/records/`. Existing public records and run directories are protected against overwrite.

| Acceptance item | Result |
|---|---:|
| Planned / available bundles | 32 / 32 |
| Unresolved code transfers / unavailable bundles | 0 / 0 |
| Exported function instances / successful decompilations | 108 / 108 |
| Functions per bundle | 2–5 |
| Instructions per bundle | 11–103 |
| Referenced data bytes per bundle | 0–83 |
| Canonical bundle UTF-8 bytes | 3,257–15,231 |
| Symbol pairs with identical binary code/data scope | 16 / 16 |
| Symbol pairs losing imported developer names | 16 / 16 |
| Imported developer function-name instances removed | 54 |
| Identical retained/stripped bundles | 0 |
| Canonical records identical across accepted runs | 32 / 32 |

The private audit independently checked every reviewed destination, object-bound setup, selected write and path instruction address against each exported bundle. All are present. Inlined cases are covered by their actual containing functions, including the optimized driver `main`; eliminated heap writes remain observations with their remaining diagnostic path. The audit did not select or restore context using those evidence addresses.

Twenty direct-data windows across the 32 observations have explicitly unknown object extents. They are marked uncertain rather than promoted to source-derived capacities. This is compatible with available code context under the direct-static-reference policy; future analyzers must handle any resulting uncertainty honestly. No unresolved code transfer or cropped data was accepted.

The equality audit finds four exact-bundle groups and fourteen groups with identical binary code/data scope when ignoring names and decompiler rendering. None contains conflicting source labels. These are groups with at least two members, rather than counts of independent source pairs. Symbol removal changes every retained/stripped public bundle; all sixteen pairs preserve the selected binary code/data scope. The two pilot families remain development-only.

The canonical validation evidence is [phase4-validation.json](../../redesign/provenance/phase4-validation.json). It records method hashes, engine/data identities, the policy, per-observation oracle coverage and decompilation states, actual symbol changes, equality groups and the comparison-run identity. Raw extraction logs, localization tickets, staged ELFs and run manifests are retained separately under `redesign/build/pilot/context/`.

## Development decisions and limits

The shared caps are 32 functions, 4,096 instructions, 16,384 referenced data bytes, 256 bytes per reference, 131,072 canonical UTF-8 bytes and a conservative 65,536-token upper bound counted using UTF-8 bytes. Undefined static data uses explicitly uncertain 16-byte windows. These caps exceed the observed pilot maxima; all policies remain subject to Phase 7 lock.

This does not establish compatibility with the current 8,192-token model runtime plus its reserved 4,096-token completion. Phase 6 must tokenize the actual prompt/chat template, measure hardware feasibility and impose the shared inference availability gate before either method is compared. The Phase 4 data policy covers direct static references, not transitive pointer closure or arbitrary runtime memory; Ghidra decompilation is not a sound bounds proof. Localization is private-oracle assisted, and the existing oracle has no independent human adjudicator.

Independent fixtures exposed and now check Ghidra's call-return override of native tail jumps, application thunk wrappers that must remain inside the scope, separate-translation-unit allocation/write flow, ordinary entry inlining, literal references, indirect-call unavailability, budget omission reporting and missing entries. Unit fixtures also cover discontiguous body ranges, malformed relationships, data/address validation, failed preparation and strict public/private field rejection.

Prototype runs are preserved in [development history](../../redesign/provenance/phase4-development-history.json). Early parallel attempts exposed HotSpot perf-data filename collisions when separate process namespaces reused PIDs in a shared `/tmp`. Workers now disable JVM perf-data files; this changes launcher behavior, not sample compilation. Two development attempts also span policy/method edits and correctly failed publication verification. They were superseded by complete fresh runs of every observation, rather than selective retries. No previous published record was overwritten.

## Reproduction

After reproducing or verifying the Phase 3 builds in a fresh workspace:

```bash
export GHIDRA_HOME=/path/to/ghidra_12.1.4_PUBLIC
.venv/bin/python -m redesign.pipeline.export_context extract --run-id phase4-c --write
.venv/bin/python -m redesign.pipeline.export_context extract --run-id phase4-d
.venv/bin/python -m redesign.pipeline.export_context verify --run-id phase4-c
.venv/bin/python -m redesign.pipeline.export_context audit --run-id phase4-c --compare phase4-d --write
.venv/bin/python -m pytest -q
```

For materialized runs, use `verify`/`audit` directly. Additional development extractions need distinct run IDs. The public record bytes must agree with any existing publication; changed inputs or methods require an explicit preserved development revision and fresh complete validation. Byte equality is claimed for canonical public bundles, not timestamps, filesystem paths or engine logs.

The Phase 4 pilot evidence gate passes. Phase 5 can implement the baseline against this public scope; Phase 6 must integrate and budget LLM inputs. Neither predictor is implemented or validated by Phase 4 completion, and final predictions remain unauthorized until the Phase 8 freeze.

Validation: the complete repository suite passed **126 tests and 83 subtests**, with Ghidra enabled and no skipped checks. Imported-source preservation, all 16 Phase 3 reference builds and both accepted Phase 4 extraction runs verify. `git diff --check` passes. The published pilot snapshot also has a regression test that checks all declared records, current method identities, schemas, budgets and private instruction coverage without requiring a materialized Ghidra project or build directory.
