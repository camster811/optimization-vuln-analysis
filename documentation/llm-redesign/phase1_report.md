# Phase 1 — isolated inputs and complete ledgers

November 21, 2026. Phase 1 is complete for `llm-representation-v1` and
`representation-v1-context12288`. The accepted preparation is
[`phase1-inputs-v2`](../../artifacts/history/redesign/build/extensions/representation-study/phase1-inputs-v2).
Its status is `inputs_bound_execution_pending`; Phases 2–10 remain pending.

## Implementation and reuse

The extension adds a package initializer and one
[`inventory.py`](../../src/optimization_vuln_analysis/studies/representation/inventory.py)
adapter. It reuses the retained strict JSON, path containment, hashing, inventory
generation, record inventory checks, bundle validation/canonicalization, evidence
membership and immutable publication helpers. No existing helper was replaced,
weakened or modified. No other proposed study module was needed for this phase.

Parent verification checks the pinned freeze and archive hashes, all 4,111 released
files, and the archive's exact regular-file membership and content without extracting
or executing it. Extra, duplicate, missing or linked archive members fail. The
retained generator reproduces the frozen build plan from the parent's configuration
and source manifest; it does not generate replacement IDs from the development
workspace. Accepted public bundles are checked against their actual public ELF load
bytes with the retained validator.

The adapter joins existing reviews to reference-binary and evidence-file hashes,
saved dispositions and public extraction/localization records. Private fact
instruction addresses must be covered by the accepted bundle. It binds existing
judgments; it does not re-adjudicate truth or run an earlier predictor.

The source snapshot contains the actual 14-file local import closure, including
root transport/identity helpers and package initializers. Dependency metadata records
the requirements hash, Python version, declared package versions and all 26 installed
distribution versions. The import closure is discovered from source, not a hand-written
assumption that the extension is standalone. These are Phase 1 dependencies; later
phases must extend the inventory as they introduce imports.

## Staged artifacts

| Path within preparation | Contents and boundary |
|---|---|
| `public/bundles/` | 160 accepted parent bundles, copied byte for byte; projection source inputs, not new model-facing views |
| `coordinator/observations.json` | Observation/build IDs, family/CWE/structure/treatment mapping and binary/public-input hashes; no truth labels |
| `coordinator/conditions.json` | 480 units, condition identities and reserved view/aggregate paths |
| `coordinator/slots.json` | 1,440 unique slot identities, seeds, condition-qualified paths and deterministic order |
| `private/evaluation.json` | Private observation-to-review labels and operation states, separately bound to bundle identities |
| `private/parent/` | Original frozen config, source manifest, build report, oracle, dispositions, bundle schema, extraction report and freeze |
| `coordinator/parent-binding.json` | Parent hashes, complete released-file hash inventory and verification receipt |
| `coordinator/dependencies.json`, `dependency-snapshot/` | Import/environment inventory and exact source/requirements snapshots |
| `coordinator/policy.json` | Unchanged Phase 0 policy snapshot, kept outside predictor inputs |
| `coordinator/manifest.json` | Completion marker binding all 190 staged files |

Files are published exclusively, made read-only and hash-bound. Existing preparation
directories are never overwritten or resumed. An interrupted preparation lacking its
completion marker cannot verify. The earlier `phase1-inputs-v1` preparation remains
preserved as development history; v2 captures the final import/environment inventory
and verification implementation.

Condition and slot hashes include the representation and public bundle identity,
never the private label or parent-oracle hash. Every reserved view, aggregate and
slot path includes the condition. Shared parent bundles intentionally have one copy
per observation. The schedule follows seed 20261121 and the declared block/condition
SHA-256 ordering. It reserves execution identities; no requests or dispatch files
are created.

These preparations are immutable input workspaces. Later phases consume them and
write identified outputs separately. Reserved paths do not imply that views,
aggregates or slot directories exist yet. The initial Phase 0 policy is unchanged;
the preparation manifest is the Phase 1 binding receipt, not a final execution freeze.

## Gate results

| Check | Verified result |
|---|---:|
| Families / source-CWE quotas | 10 / five per CWE |
| Reference builds | 80 |
| Original opaque observations | 160 |
| Complete distinct family × variant × optimization × symbols cells | 160 |
| Observations per family | 16 |
| Observation-condition units / per condition | 480 / 160 |
| Unique slots / per condition | 1,440 / 480 |
| Binary truth: stack / heap / safe | 28 / 32 / 100 |
| Verified parent release files | 4,111 |
| Staged files, excluding completion manifest | 190 |

Preparation manifest SHA-256:
`b35cdb079c1d8be2b95bb3c2a7b782fbcca2650de573a7a462e90a25df7daf77`.

The parent freeze remains
`740a291e1c7b413406b7ec797d33523fb47885b364168de96e29ff714046bbed`;
its input archive remains
`842f80e9ba40b15068b3548b64252fc1a01d004c6750a639e84fbb6a9fa4d041`.
No original source, policy, oracle, locked method, raw attempt or historical release
was changed. Local hashes identify content, not an independent timestamp.

## Validation and commands

The complete suite passes **130 tests**, including 30 new Phase 1 checks. The
fixtures exercise real ELF load-byte validation without invoking a compiler.
They cover deterministic repeated preparation, shared-input separation, preserved
IDs, condition-specific identities/paths, independent schedule recounting,
missing/changed/extra/symlink inputs, archive membership/content, stale reference
or evidence bindings, inconsistent judgments/extraction records, nested private
fields, changed instruction bytes, corrupt or rehashed ledgers, missing count
fields and interrupted publication. The original 100 reuse checks still pass.

A coherent private-label swap, explicitly rebound as a new fixture parent,
changes only private evaluation/binding evidence: the public bundle bytes and
observation, condition and slot ledgers remain byte-identical. An unbound private
edit is rejected before a destination is created.

The verifier reads only the staged preparation, checks its file inventory/hashes
and regenerates the ledgers; it has no parent or server fallback and never rewrites
an artifact. A fresh copy of the real preparation also verified using its saved
source snapshot with `PYTHONPATH` cleared and bytecode writing disabled. Every
copied file remained byte-identical. Unit tests separately verify with the parent
directory unavailable. `git diff --check` passes.

From the repository root:

```sh
# Choose a new destination for another preparation; existing names are protected.
.venv/bin/python -m redesign.extensions.representation_study.inventory prepare \
  --directory redesign/build/extensions/representation-study/my-new-inputs

# Verify the accepted preparation without accessing the parent or a model server.
.venv/bin/python -m redesign.extensions.representation_study.inventory verify \
  --directory redesign/build/extensions/representation-study/phase1-inputs-v2 \
  --manifest-sha256 b35cdb079c1d8be2b95bb3c2a7b782fbcca2650de573a7a462e90a25df7daf77

.venv/bin/python -m pytest -q
```

`prepare` defaults to the parent declared by the policy; `--parent` permits a
relocated copy only when the same pinned content verifies. `--policy` selects an
explicit versioned configuration. `verify` needs neither option because it uses
the staged policy and parent documents. Generated preparations remain under the
ignored build directory; this is not the final publication package.

Phase 2 can now project deterministic code views from the staged public bundles.
No new compilation, extraction, lifting, tokenization or inference ran in Phase 1.
