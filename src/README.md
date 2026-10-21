# Juliet redesign workspace

The active user-requested context amendment uses `campaigns/final-v2-context12288` with a 12,288-token context and the same 4,096-token completion reservation. Follow the [amended execution runbook](../documentation/juliet-redesign/context12288_runbook.md). The original `final-v1` release and Phase 7 lock remain preserved.

Phase 9 is complete for the amended campaign; see the [final report](../documentation/juliet-redesign/phase9_report.md). All 480 LLM slots are terminal (472 valid, six schema failures, two interrupted), and all 160 baseline predictions replay. LLM C/E/U/M = 125/28/7/0; baseline = 18/0/142/0. Results, tables, figures and a byte-preserving regeneration check are saved; the results release includes raw attempts and baseline IR. Phase 10 manuscript/research-release work remains separate. The earlier 8,192-token campaign and original methods remain preserved.

Phase 8 is complete. The isolated final campaign in [`campaigns/final-v1`](campaigns/final-v1/README.md) freezes ten families, 80 reference builds, 160 public observations, and 480 scheduled LLM slots. Exact preflight makes 112 observations available and 48 shared-unavailable. The Phase 7 methods remain locked, and no final predictor ran. See the [Phase 8 report](../documentation/juliet-redesign/phase8_report.md). Earlier phase notes below are historical.

From the repository root, using the existing Python environment:

```bash
.venv/bin/python -m redesign.pipeline.inventory --split pilot --write
.venv/bin/python -m redesign.pipeline.inventory --split final --write
.venv/bin/python -m redesign.pipeline.inventory --split final --check-plan redesign/build/final/planned_inventory.json
.venv/bin/python -m redesign.pipeline.import_juliet verify
.venv/bin/python -m redesign.pipeline.validate_sources
.venv/bin/python -m redesign.pipeline.build build
.venv/bin/python -m redesign.pipeline.build verify
.venv/bin/python -m redesign.pipeline.oracle --write
.venv/bin/python -m pytest tests/test_redesign.py tests/test_juliet_import.py tests/test_redesign_phase3.py
```

`config.json` declares the treatment matrix, split quotas, compiler settings, and repetition seeds. `corpus/manifest.json` contains assigned pilots and explicitly unassigned final slots. Inventories derive from those declarations, never from discovered build files. Generated plans go under this workspace's `build/`, with separate pilot/final paths; they are not frozen inputs or completed attempts.

`--require-assigned` rejects unassigned slots in the requested split. Future build/freeze/inference entry points must use that gate, verify actual record inventory and hashes, and implement their phase-specific checks. Assigning pilot sources does not require assigning final sources. The generic inventory supports smaller synthetic matrices; the shipped configuration implements the Phase 0 contract.

Assigned manifest entries retain `pair_id`, `split`, `cwe`, `structure`, and `status`, and add `family_id`, `upstream_case_id`, `sources`, `support_sources`, `entries` keyed by variant, `variant_selection` keyed by variant (`defines` and `driver_sources`), `sanitization_manifest`, `selection_record`, and `file_sha256` covering every listed source/provenance file. Paths are relative to this workspace. Multi-file sources and original variant-selection macros are supported as declarations; the two pilot recipes have passed Phase 2 review and validation.

Pilot entries also declare `headers`, `include_dirs`, and `translation_units`. Each driver includes its sanitized original unit so it can call the selected static safe entry without changing its linkage. Compile only the declared translation units and support sources, not every listed source file; `unit.c` is already included by its driver. Both variants use the neutral `process_case` entry, with renamed original omit macros selecting the path. Other original safe paths remain in the source but are not invoked by the driver.

To reproduce the import, supply the pinned ZIP and its extracted `C` directory:

```bash
.venv/bin/python -m redesign.pipeline.import_juliet import --archive /path/to/juliet.zip --extracted-root /path/to/C
```

The importer verifies all 9,562 candidate C files against the ZIP and original inventory, then recreates or confirms the exact reviewed outputs. It refuses changed existing files. Rerunning import restores read-only permissions on originals after a fresh Git checkout, since Git does not preserve those permission bits. Do not edit upstream copies or sanitized testcase bodies manually; preservation checks will reject unreviewed changes.

`validate_sources` builds original and sanitized pilots at every declared optimization, scans both public symbol treatments, checks text/relocation equivalence, and runs separate O0 AddressSanitizer builds. Outputs and logs are under `build/phase2-validation/`; the versioned summary is `provenance/phase2-validation.json`. These are validation artifacts, not the Phase 3 campaign or oracle.

`build build` compiles each declared driver/testcase/support translation unit separately at its treatment level. Original variant macros and external drivers choose the execution path. It records header dependencies, effective optimizer/target options, exact commands and diagnostics, pinned tool and libc identities, private debug mappings and disassembly. The reference executable stays in `build/pilot/oracle/`; retained and stripped derivatives occupy their declared inventory paths. All allocated sections (including executable sections, constants, writable data and zero-filled objects) must match in bytes, addresses, sizes and flags. Both derivatives must pass debug-removal and metadata checks. A failed build keeps its cell with `build_unavailable` and a reason. Unassigned final slots and unavailable pinned tools block preparation.

`build-manifest.json` and private evidence live under `build/pilot/`. Existing manifests are protected against accidental replacement: use `build verify` for an existing build, or copy the workspace inputs to a fresh directory and call `build(root)` through Python for an independent rebuild. Verification checks the declared inventory, input/method/tool hashes, artifacts, dependencies and evidence. It does not execute the testcase binaries.

`corpus/private/pilot-oracle.json` contains the reviewed Phase 3 conclusions, separate source labels, instruction ranges across containing functions, assumptions, destination/bound/write/path evidence, and assembly excerpts. Reviews bind exact reference and evidence hashes; rebuilding never generates labels. `oracle --write` verifies these reviews and emits `build/pilot/dispositions.json` plus the versioned `provenance/phase3-validation.json` summary, giving both equivalent symbol partners the same conclusion. Unknown behavior stays `unresolved`, independently of operation status. This private material must never be joined into analyzer inputs. All pilot execution scopes start at privately localized `main`, including cases where the source entry has been inlined or has no standalone symbol. This localization assistance must be disclosed in Phase 4.

See `../documentation/juliet-redesign/phase3_report.md` and `provenance/phase3-validation.json` for the reviewed dispositions and validation evidence. Review was performed by Codex, without independent human adjudication. Phase 4 uses this evidence only for localization and post-export audits.

Phase 4 exports public schema 2 records under `data/pilot/records/`. See the [context specification](../documentation/juliet-redesign/context_bundle_spec.md), [implementation plan](../documentation/juliet-redesign/phase4_implementation_plan.md), and [Phase 4 report](../documentation/juliet-redesign/phase4_report.md). With the pinned Ghidra installation available, a fresh workspace can reproduce both accepted runs:

```bash
export GHIDRA_HOME=/path/to/ghidra_12.1.4_PUBLIC
.venv/bin/python -m redesign.pipeline.export_context extract --run-id phase4-c --write
.venv/bin/python -m redesign.pipeline.export_context extract --run-id phase4-d
.venv/bin/python -m redesign.pipeline.export_context verify --run-id phase4-c
.venv/bin/python -m redesign.pipeline.export_context audit --run-id phase4-c --compare phase4-d --write
.venv/bin/python -m pytest -q
```

Extraction run directories cannot be reused. For materialized runs, use `verify`/`audit`; for additional development runs, choose distinct run IDs. `--write` publishes only if every existing record already matches, preserving prior attempts. Private logs, localization tickets, staged analysis ELFs and run manifests stay under `build/pilot/context/`. The audit command regenerates `provenance/phase4-validation.json` from those manifests and records; prototype runs are recorded separately in `provenance/phase4-development-history.json`.

`context_policy.json` controls shared limits without changing the Phase 3 build configuration. The worker receives only the public ELF, entry address and generic policy; Ghidra follows recovered address relationships and extracts code/data without oracle bounds or labels. DWARF/PDB lookup and external-library autoloading are disabled. Ghidra's own public recovery/type archives remain enabled and recorded. Afterward, a private audit checks reviewed instruction coverage, actual name removal, symbol-partner scope parity and input equality groups. Phase 4 did not run either predictor.

All 32 accepted pilot bundles are available and repeat byte for byte across two fresh-project runs. Each has two to five functions and 11–103 instructions; canonical sizes are 3,257–15,231 UTF-8 bytes. All 108 exported function instances have successful decompilation. Every reviewed instruction is covered, all 16 symbol pairs have identical binary code/data scope, and every pair loses at least one imported developer name. The Phase 4 byte/token-upper-bound policy is a development evidence limit; actual model/chat-template budgeting remains Phase 6 work.

Phase 5's baseline reconstructs a new Ghidra image solely from the public bundle's code/data bytes, exports high P-code, and evaluates constant allocation sizes, pointer offsets, recovered direct-call arguments and concrete acyclic paths. Fixed external contracts and both allocator outcomes are explicit. It checks native-write coverage before trusting the high-level representation. It reads no private oracle, source or original ELF while predicting. The predecessor's x86 simulator and frame-overlap stack rule were reviewed and excluded; compatible validation, provenance and feasibility patterns are reused. The v2 revision adds explicitly heuristic recovered stack-array bounds and a narrow instruction-P-code store fallback. See the [baseline specification](../documentation/juliet-redesign/baseline_spec.md), [v2 evaluation](../documentation/juliet-redesign/phase5_stack_revision.md), and [historical v1 report](../documentation/juliet-redesign/phase5_report.md).

```bash
.venv/bin/python -m redesign.pipeline.baseline lift --run-id phase5-v2-lift-a
.venv/bin/python -m redesign.pipeline.baseline predict --lift-run phase5-v2-lift-a --run-id phase5-v2-c --write
.venv/bin/python -m redesign.pipeline.baseline verify --run-id phase5-v2-c
.venv/bin/python -m redesign.pipeline.baseline audit --run-id phase5-v2-c --write
# Replay published pilot predictions without Ghidra or generated build artifacts:
.venv/bin/python -m redesign.pipeline.baseline_snapshot verify
# Replay preserved v1 with its own method/policy/schema:
.venv/bin/python -m redesign.pipeline.baseline_history
```

Lifting needs the same `GHIDRA_HOME` as Phase 4. Existing run directories are protected; use `verify` or choose distinct IDs for new development attempts. The accepted pilot has eight classifications and 24 abstentions across all 32 cells; all eight classifications match the private oracle. No runtime/input failures occurred. Inferred nonoverlapping arrays can now support CWE-121 predictions, explicitly annotated `inferred_stack_object_extent`; ambiguous recovery and unsupported paths abstain. All stack pilot observations still abstain. Independent O0–O3 fixtures include correct stack predictions and nine measured false negatives caused by enlarged inferred bounds. Final execution remains disabled, and Phase 7 must assess this declared coverage before method lock. No LLM predictions ran.

`provenance/starting-code.tar.gz` preserves the latest predecessor code, prompts, tests, settings, and design documents for porting. It is reference material, not the new pipeline: its schema, counts, single-function extraction, and old endpoints must not run on redesigned inputs. `provenance/start.json` records revision, dirty state, file hashes, and historical archive hashes. `provenance/working-tree.patch` preserves tracked starting changes; untracked method/tests/docs included in the snapshot are listed by hash.

The predecessor's runtime identity checks, raw attempt persistence, voting, bootstrap, and regeneration remain available in that snapshot. They will be integrated with the new schemas and recovery rules in later phases, rather than importing code that implicitly reads the old root configuration. The existing root regression suite continues to test those implementations.

The experimental contract and selection rules live in `../documentation/juliet-redesign/`. Do not run the root legacy build or inference commands expecting them to use this workspace.

Phase 1 validation: the complete root suite passed 72 tests and 83 subtests; six optional Ghidra checks were skipped because `GHIDRA_HOME` was unset. The 17 new checks include a real two-file GCC fixture built at O0–O3 for both variants, with retained/stripped executable-text equivalence. No research samples or model predictions were generated.

Phase 2 validation: the complete root suite passed 86 tests and 83 subtests, with six optional Ghidra checks skipped because `GHIDRA_HOME` was unset. Sixteen original/sanitized build comparisons and eight ASan executions passed. One diagnostic-string layout change was verified through the referenced literal bytes. The import adds 14 regression checks. Imported-source checks, the predecessor snapshot, and both historical archive hashes verify. No final cases or model predictions were generated. See `../documentation/juliet-redesign/phase2_report.md` for selection decisions and limits.

Phase 3 validation: all 16 references and 32 derivatives pass build/private-review checks. A clean workspace reproduced every binary and private evidence file byte for byte and accepted the unchanged oracle. The full suite passed 91 tests and 83 subtests, with six optional Ghidra checks skipped. Selected operations are present in 11 reference builds, inlined/merged in three and eliminated in two. No source changes, final assignments or predictor runs were needed.

Phase 4 validation: all 32 public bundles pass schema, byte identity, leakage, private coverage and symbol-scope checks, and reproduce byte for byte across two fresh-project runs. With Ghidra enabled, the complete suite passed 126 tests and 83 subtests, with no skips. Source-preservation and Phase 3 build checks still pass. No model requests or final-case selections occurred.

Phase 5 v1 validation passed 168 tests and 80 subtests. The v2 stack revision passes 219 tests and 80 subtests with Ghidra enabled and no skips, including 36 O0–O3 stack fixtures. All 32 pilot cells complete, with eight classifications and 24 abstentions; the 84 KB v2 IR archive replays every prediction without Ghidra or private artifacts. V1 also replays with its preserved method. Prior source/build/context/provenance checks still pass. See the v2 evaluation for measured heuristic errors and support limits.

Phase 6 implements the stateless public-bundle LLM adapter, strict cross-function evidence validation, exact live-template token budgeting, runtime identity checks, and durable no-retry dispatch recovery. At the retained 8,192-token context with 4,096 tokens reserved for completion, 26 of 32 pilot bundles fit and six have shared `context_unavailable` status. Phase 7 must apply that availability overlay to both methods. See the [Phase 6 report](../documentation/juliet-redesign/phase6_report.md) for commands, validation, partial pilot requests, and the method-lock boundary.

Phase 7 is complete: all 96 pilot LLM slots are terminal, the 32 baseline predictions replay, and an independent workspace reproduces all 16 references, 32 derivatives and 32 public bundles. Shared-eligibility scoring yields baseline C/E/U/M = 8/0/18/6 and LLM = 15/11/0/6 on 32 adjudicated cells. The [Phase 7 report](../documentation/juliet-redesign/phase7_report.md), [decision log](../documentation/juliet-redesign/phase7_decisions.md), and [method lock](provenance/method-lock.json) record results, limitations and frozen choices. Run `.venv/bin/python -m redesign.pipeline.method_lock verify` from the repository root. The verified lock supersedes historical pending markers; final family assignment and the final input freeze remain Phase 8 work.

Phase 8 verification: `.venv/bin/python -m redesign.pipeline.final_freeze verify`. The [freeze](campaigns/final-v1/release/freeze.json) and private input archive bind 3,144 files; fresh archive replay passes. The regression suite passed 103 tests with Ghidra enabled and no skips. Phase 9 must use this isolated campaign and shared eligibility, verify the freeze, and preserve all planned cells. The original pilot manifest remains unchanged under the method lock.
