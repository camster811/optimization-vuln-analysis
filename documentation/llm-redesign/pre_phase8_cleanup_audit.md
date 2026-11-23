# Repository cleanup audit before Phase 8

November 22, 2026. Identification only: no repository data, code, environment or historical evidence was deleted or moved, and no tests were run for this audit. File counts and sizes are a snapshot of the current workspace. Sizes are logical file bytes, not a promise of physical disk space recovered.

## Conclusion

The active implementation is already small. Most clutter is expanded historical builds, extraction caches, superseded campaigns and duplicate engineering packets. The repository contains about **4.48 GiB outside `.git/` and `.venv/`**. About **4.02 GiB** belongs to legacy build work plus the superseded `final-v1` campaign, after retaining the three old pilot manifests still used by the current pilot-preparation interface.

The current Phase 7 freeze binds 21 production Python files. All are still relevant. The only active Python file outside that source closure is `redesign/pipeline/run_llm.py`, which current regression tests still import. There is no additional production-code directory that can simply be removed without considering a dependency.

Keep the immutable publication, its archive/detached manifest and the separate writable Phase 8 execution. Cleanup should preserve their bytes and paths, and preserve the pinned environment. Refactoring imports, renaming packages or uninstalling dependencies at this point would require renewed freeze checks and possibly a new method freeze.

## Immediately disposable material

| Candidate | Finding |
|---|---|
| Root `.pytest_cache/` | Disposable test cache, about 0.08 MiB. |
| `__pycache__/` and `.pyc` files in active source/test directories | Recreated by Python. Together with pytest cache, 42 cache files occupy about 1.00 MiB. None intersects the current publication or the inspected parent release file inventories. |
| Empty temporary Ghidra directories in historical builds | No code/input value, but remove them with their enclosing retired workspace rather than individually traversing sealed evidence. |

Do not apply a blanket cache-removal command to immutable archives or publications. The safe cache list refers to identified unbound working files, not files merely named like caches inside a release.

## Historical workspaces to remove from the active checkout

These are unused by the latest execution. They may still be useful as historical evidence; archive/offload them if that evidence is to be retained. Their size is not evidence that their contents are backed up.

| Path | Approximate size | Classification and reason |
|---|---:|---|
| `redesign/build/extensions/baseline-study/` | 1,586.53 MiB | Retired static-baseline/contract-study work, compiled fixtures and extraction/lifting caches. No active import or runtime dependency. No `.tar.gz`, ZIP or 7z backup was found inside the remaining directory, and its old publication directory is absent; treat it as potentially unique historical evidence. |
| `redesign/build/pilot/`, excluding the three manifests below | About 1,121.6 MiB | Earlier compilation, oracle, baseline and extraction work. The context subtree alone is 1,081.78 MiB. The latest run uses accepted public bundles and packaged inputs, not these compiler/Ghidra working projects. |
| `redesign/build/phase7-clean-a/` | 228.59 MiB | Earlier full validation/rebuild checkout with old source, binaries and working projects. Not the new representation study's Phase 7 freeze. |
| `redesign/build/phase2-validation/` | 5.25 MiB | Earlier source/build validation outputs, not current model inputs. |
| `redesign/build/final-runtime/` | 2.69 MiB | Previous study runtime evidence. Current runtime evidence is under the representation-study Phase 6/7 paths. |
| `redesign/build/final/` | 0.17 MiB | Old planned-inventory output. Current inventories come from the accepted Phase 1/frozen publication. |
| `redesign/campaigns/final-v1/` | 1,170.05 MiB | Superseded 8,192-token campaign and large materialized extraction workspace. The declared current parent is `final-v2-context12288`. Preserve its own archive/manifest if retaining this historical configuration, rather than editing its expanded contents in place. |
| `redesign/provenance/` | 3.33 MiB | Prior redesign development receipts, old baseline snapshots and old archives. No active code/test path reads this root directory; provenance copied inside current packages is a different, required set of files. |
| `redesign/results/pilot/` | 0.39 MiB | Original study's pilot results. Not the new Phase 6 execution or final predictions. |
| `optimization-vuln-analysis_old.7z` | 3.15 MiB | Predecessor backup, not imported or referenced by current execution manifests. Keep outside the active checkout if wanted. |

### Retain these three original pilot manifests

`pilot.prepare()` still reads these exact paths. Do not delete the whole old pilot build directory while retaining that interface without retaining these files:

```text
redesign/build/pilot/build-manifest.json
redesign/build/pilot/context/phase4-d/extraction-manifest.json
redesign/build/pilot/llm/phase6-a/manifest.json
```

They total about 3.06 MiB and bind the accepted pilot inputs. The current frozen publication already embeds the accepted new pilot preparation/execution, so Phase 8 itself does not need these original paths; keeping them preserves pilot re-preparation and the current repository interface.

## Redundant or completed representation-study work

All paths below are relative to `redesign/build/extensions/representation-study/`.

| Path | Approximate size | Finding |
|---|---:|---|
| `phase1-inputs-v1/` | 18.95 MiB | Superseded by the accepted v2 preparation. Historical development copy. |
| `phase2-views-v1-b/` | 8.14 MiB | Independent repeatability copy; matches the accepted A projection bytes. Useful acceptance evidence, not a Phase 8 input. |
| `phase3-offline-v1/` | 0.26 MiB | Superseded offline adapter receipt/identity ledger. |
| `phase3-offline-v2/` | 0.26 MiB | Accepted construction checks already superseded operationally by exact frozen request files. Optional audit history, not a dispatch dependency. |
| `phase4-offline-v1/` | 22.24 MiB | Earlier pending engineering request packet, not the final working execution. |
| `phase4-synthetic-v1/` | 2.52 MiB | Completed fabricated execution for the runner gate, not real model data. |
| `phase5-offline-v1/` | 1.25 MiB | Fabricated evaluation fixtures/output and an older source snapshot, not final study results. |

These can leave the active checkout. Retain compact acceptance receipts or an external engineering archive if preserving every phase's detailed audit trail.

### Accepted build copies already embedded in the Phase 7 publication

The following source-to-publication file-byte matches were checked for every file, not inferred from similar names. Publication paths are relative to:

```text
redesign/experiments/llm-representation-v1/representation-v1-context12288-final-v1/
```

| Build workspace | Publication copy | Files checked | Approximate build size |
|---|---|---:|---:|
| `phase1-inputs-v2/` | `inputs/` | 191 | 18.95 MiB |
| `phase2-views-v1-a/` | `projection/` | 824 | 8.14 MiB |
| `phase6-pilot-v1/` | `pilot/preparation/` | 269 | 5.22 MiB |
| `phase6-execution-v1/` | `pilot/execution/` | 108 | 1.23 MiB |

The build copies are redundant once later commands use the publication's `inputs/`, `projection/` and `pilot/` paths. Do not delete a copy while leaving a command or receipt checker expecting that original location. Frozen publication permissions may differ from working-copy permissions; the verified equality is file content.

`phase7-accounting-v1.json` is byte-identical to publication `accounting.json`; `phase7-regression-v1.json` is byte-identical to publication `method/regression.json`. Their loose build copies are also redundant. The other small Phase 6/7 receipts and runtime logs are worth retaining: some are referenced by hash but not copied verbatim into the publication.

**Do not treat `phase7-final-v1/` as another disposable duplicate.** It is the writable execution packet that Phase 8 will extend with restart/dispatch/response/result journals. The publication's `execution/` is the immutable pre-generation snapshot.

## Documentation cleanup

`documentation/llm-redesign/` is the active documentation set; keep its contract, specification, phase reports and working instructions.

`documentation/juliet-redesign/` contains 24 historical files, about 0.28 MiB. It can be removed from the active documentation navigation or offloaded as historical material. Four files are still linked from the current README/implementation plan:

```text
analysis_plan.md
context_bundle_spec.md
phase6_report.md
phase9_report.md
```

Keep those references accessible, or update the current links to an archived location before moving them. The other twenty files concern the previous selection/build/static-baseline workflow and are not needed to execute the latest study. Existing frozen copies must remain unchanged.

The Obsidian `static_baseline.md` already records the baseline's implementation/results, but it is a narrative record, not a replacement for raw historical evidence.

## Keep for the latest iteration

| Path or group | Why it remains relevant |
|---|---|
| `.git/`, `.gitignore`, root README and `pytest.ini` | Repository state, source discovery and project entry points. |
| `.venv/` and `requirements.txt` | Current pinned execution/replay environment. The freeze checks installed distributions as well as declared requirements; do not prune packages before Phase 8. |
| Root `pipeline/` Python sources | Explicit transport, model/server launch and runtime identity helpers; part of the frozen 21-file import closure. |
| `redesign/extensions/representation_study/` sources, policy, prompt and schemas | Active implementation. Pilot/inventory/freeze code is needed by verification even after its preparation phase has finished. |
| `redesign/pipeline/` sources and package initializers | Bundle validation, serialization, identity, persistence, metric arithmetic and current test support. |
| `redesign/config.json`, `context_policy.json`, `llm_policy.json`, `redesign/llm/` and `redesign/schemas/` | Retained validators, tests and pilot-preparation contracts. Their older names/settings do not make them unused. |
| `redesign/corpus/` and `redesign/data/pilot/` | Small source/provenance inventory and accepted pilot fixtures; read by preparation and regression checks. |
| Current `tests/test_*.py` files | Regression coverage and the hash-bound Phase 7 test snapshot. Do not remove tests merely because their original workflow was historical. |
| `redesign/experiments/llm-representation-v1/` | Canonical immutable Phase 7 publication plus internal archive/detached manifest; about 109.49 MiB. |
| `redesign/build/extensions/representation-study/phase7-final-v1/` | Current writable final execution, about 57.66 MiB. |
| Representation-study Phase 6/7 runtime folders and small receipts | Current live-pilot and final-preflight provenance. |
| `redesign/campaigns/final-v2-context12288/` | Declared parent and default input-preparation source, about 201.74 MiB. Keep through the run; later it can be offloaded with its archives and detached manifests. |
| The three original pilot manifests listed above | Preserve the current pilot preparation entry point. |

### A legacy file that should stay for now

`redesign/pipeline/run_llm.py` is outside the generation/freeze source closure, but `tests/test_redesign_llm.py` imports it for retained transport/recovery boundary checks. The old prompt/schema and root pilot policies are also exercised by tests. Removing these together is a possible later reduction, requiring test/dependency updates; it is not a cache cleanup.

Do not merge or rename the two `pipeline` packages before Phase 8. Their imports and source paths are part of the frozen method identity.

## Source-control finding

Several required current files are untracked, including `redesign/extensions/representation_study/freeze.py`, the current study documentation and several current regression files. The current publication is also untracked. Untracked does not mean irrelevant in this checkout. A broad `git clean` would mix essential work with disposable files and is unsuitable for this cleanup.

## Recommended boundary for the next cleanup action

1. Remove identified unbound caches.
2. Offload retired build work and `final-v1`, preserving historical evidence where desired and the three required pilot manifests in their existing paths.
3. Make the Phase 7 publication the canonical accepted-input/pilot location, then retire redundant build copies and completed synthetic workspaces with command-path updates.
4. Keep the current final working execution, source/resources, test support and pinned environment unchanged.
5. Run read-only freeze/archive/working-execution guards afterward. No new model requests or test-suite run are needed to establish file identity.

This audit authorizes no deletion by itself. It provides the concrete candidates and dependencies for the requested cleanup decision.
