# R3 execution and saved replay separation

Completed November 22, 2026, America/New_York. R3 separates code that writes or dispatches execution from code that reads saved evidence. The runner shrank from 470 to 212 lines. The refactor uses existing functions and plain dictionaries, with no packet class, plugin system or new compatibility layer.

## Structure

| Module | Responsibility |
|---|---|
| [`runner.py`](../../src/optimization_vuln_analysis/studies/representation/runner.py) | Preparation, runtime registration, dispatch, response/result publication and the existing CLI |
| [`replay.py`](../../src/optimization_vuln_analysis/studies/representation/replay.py) | Packet/request validation, runtime-event and journal reconstruction, eligibility, aggregates, readiness and source checks |
| [`views.py`](../../src/optimization_vuln_analysis/studies/representation/views.py) | Projection and its public in-memory `render` operation, reused by pilot preparation |

`replay.inspect(directory)` is the read-only entry point. It returns:

- `state`: the unchanged summary previously returned by `runner.verify`, including verified manifest identity, dispositions and aggregates;
- `projection_manifest_sha256`: the bound projection identity;
- `eligibility`: observation eligibility, or `None` before preflight.

`runner.verify` retains its existing return format and CLI behavior by returning the inspection's `state`. Replay imports independently of runner and has no dispatch/server entry point. Inspection makes no requests, does not create a missing lock file and does not require the working source to match the saved method.

Writers and freeze accounting use the public `load_packet`, `ownership`, `reconstruct`, `require_pending` and `check_method` operations. `check_method` retains source/requirements enforcement before mutation; `freeze.guard` retains the complete publication/environment guard. Integrity inspection and permission to continue an execution remain separate checks.

## Removed coupling

Freeze no longer calls runner's private loader, state, locking or method helpers. Pilot and scoring use the inspection metadata directly instead of reading manifests/preflight again. Reporting's terminal-record reader moved to public `replay.records`. Pilot uses public `views.render`.

The old `freeze._hash`, `freeze._files`, `freeze._pending` and `reporting._records` entry points were removed. Hashing and inventories use the shared R1 helpers directly; readiness and journal records have one implementation in replay. Freeze shrank from 351 to 331 lines and reporting from 438 to 426. No forwarding aliases were added for removed private functions. Existing tests were updated to their actual public owners.

The new file gives saved-data validation a clear home; this step does not claim a reduction in total repository file count. Removal of unused legacy modules and generated duplicates remains dependency-guided cleanup work. Historical archives and unique evidence were retained.

## Verification

Only important focused checks were run, following the requested limited test scope:

- **23 replay/lifecycle cases passed:** pending inspection, all three dispatch-interruption points, orphan temporary files, common blocking, restart identity, changed/corrupt inputs, source drift and concurrent ownership.
- **One scoring boundary case passed:** incomplete execution is rejected before evaluation.
- **One freeze reader case passed:** verification works without runtime access or the original working source and leaves evidence unchanged.

Static comparison confirms the moved record reader and projector bodies are unchanged. Study sources compile, production consumers no longer call the removed private interfaces, and all **46,291 protected evidence files** retain their hashes. No model requests, final-result generation, bootstrap analysis, figure regeneration or full-suite run occurred. The new working source closures contain 26 freeze and 27 reporting files; original frozen source identities remain unchanged.

The [completion receipt](../../artifacts/history/redesign/build/refactor/r3-v1/completion.json) records the source changes, three test receipts and preservation check. The pre-change source snapshot and JUnit outputs are under `redesign/build/refactor/r3-v1/`.

The remaining refactor should prioritize a smaller, easier-to-read active repository. Remove unused paths once their real consumers are accounted for, and retain the intended behavior for occasional use. New experiments and model/result reruns are outside the planned work.
