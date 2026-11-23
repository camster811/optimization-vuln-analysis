# R4 input adapters and source provenance

Completed November 23, 2026, America/New_York. R4 separates historical input interpretation, study scheduling and source/resource capture. Study inventory shrank from 357 to 178 lines. Preparation can use relocated parent releases and copied accepted pilot packets without the original build paths. No model or result workflow was rerun.

## Structure and removed coupling

| Owner | Responsibility |
|---|---|
| [`inputs/parent.py`](../../src/optimization_vuln_analysis/inputs/parent.py) | Verify the older parent release/archive, read accepted bundles and bind reviewed observations/evaluation metadata |
| [`representation_study/inventory.py`](../../src/optimization_vuln_analysis/studies/representation/inventory.py) | Study policy, condition/slot scheduling and staged input publication |
| [`common/provenance.py`](../../artifacts/history/redesign/build/refactor/r5-v1/source-before/redesign/common/provenance.py) | Resolve declared source/resources, capture imports/environment, create snapshots and verify saved bytes |
| [`representation_study/pilot.py`](../../src/optimization_vuln_analysis/studies/representation/pilot.py) | Select/project engineering inputs from either an accepted packet or the retained legacy workspace interface |

The study-owned `dependencies` scanner, `REPO` global and historical `PARENT_FILES`/`verify_parent` entry points were removed. Consumers use the shared provenance functions and the parent adapter directly. Repeated dependency-copy and verification loops were replaced with `snapshot` and `verify_snapshot`. Protocol resources are declared once as `representation_study.RESOURCES`; the separate freeze resource list was removed.

Provenance binds Python sources, package initializers, requirements, the common prompt, policy and three schemas. It follows static imports and literal dynamic imports and rejects unresolved dynamic import calls rather than silently omitting them. Resource files are declared explicitly because an import scan cannot discover them. Conflicting resource/requirements bindings are rejected.

Logical snapshot names stay stable. `capture`/`snapshot` accept explicit package roots and resource-path overrides for source-directory or extracted installation layouts; defaults retain the current checkout locations. Saved snapshot verification reads only the supplied snapshot directory. It does not resolve original source paths. Wheel installation remains outside this milestone.

## Accepted pilot input

`pilot.prepare(..., accepted=path, accepted_manifest_sha256=...)` uses the existing self-contained preparation format: source bindings, provenance manifests and accepted bundles. It verifies the packet before use and never falls back to the old workspace in this mode. The destination cannot overlap accepted input.

An optional preparation command, with no model access, is:

```sh
.venv/bin/python -B -m redesign.extensions.representation_study.pilot prepare \
  --accepted redesign/experiments/llm-representation-v1/representation-v1-context12288-final-v1-completed-r0-v2/frozen/pilot/preparation \
  --directory /tmp/representation-pilot-preparation
```

Use `--accepted-manifest-sha256` to pin a specific accepted packet. Existing `root`/`--root` behavior and the parent's explicit `--parent` option remain available. The three original pilot manifests remain for legacy-root preparation; their removal must follow retirement of that consumer. No new input-package format was introduced.

## Verification

**23 focused critical cases passed**, with zero failures or errors:

- Six provenance cases cover explicit source/resource locations, initializers, literal and unresolved dynamic imports, conflicting bindings, changed/missing assets and re-capture from a saved snapshot with original-checkout reads blocked.
- Twelve parent rejection cases preserve archive/hash and semantic binding checks.
- Three input-boundary cases prove copied-pilot preparation without the old workspace, relocated-parent preparation/verification and private-truth changes leaving predictor inputs/scheduling unchanged.
- Two consumer cases preserve the full source/environment guard and read-only inspection when working sources are unavailable.

Copied pilot selection and projected-view bytes match the accepted packet. All **46,291 protected evidence files** retain their hashes. Full-suite execution, campaign replay, inference, bootstrap analysis and figure regeneration were skipped under the requested limited test scope.

New snapshots include `resource_files` alongside source and environment identities; readers still accept older snapshots whose resource bindings live in their surrounding publication manifests. New freeze regression receipts must bind the declared resources too. Current source closures contain 29 freeze and 30 reporting files, with five declared protocol resources. Requirements, protocol content, archived methods and saved outcomes remain unchanged.

The [completion receipt](../../artifacts/history/redesign/build/refactor/r4-v1/completion.json) binds the focused checks, source changes and preservation result. R4 keeps current defaults for compatibility while making their actual consumers explicit. Continue cleanup by consolidating active packages/test support and removing obsolete paths once their meaningful assertions and consumers have been accounted for.
