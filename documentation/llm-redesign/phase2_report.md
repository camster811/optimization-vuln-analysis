# Phase 2 — deterministic code views

November 21, 2026. Phase 2 is complete for `llm-representation-v1` and
`representation-v1-context12288`. The accepted projection is
[`phase2-views-v1-a`](../../artifacts/history/redesign/build/extensions/representation-study/phase2-views-v1-a),
with an independent byte-identical run at
[`phase2-views-v1-b`](../../artifacts/history/redesign/build/extensions/representation-study/phase2-views-v1-b).
Status is `views_projected_not_tokenized`; Phases 3–10 remain pending.

## Implementation and reuse

The phase adds [`views.py`](../../src/optimization_vuln_analysis/studies/representation/views.py)
and [`schemas/view.json`](../../src/optimization_vuln_analysis/studies/representation/schemas/view.json).
`project(bundle, representation)` constructs each nested object from explicit
allowlists. It accepts public evidence and schema definitions, with no oracle,
source-label, private-localization or previous-answer interface. It validates the
parent with the retained bundle validator, then requires available, complete input.
It does not modify, crop or repair the parent.

The new schema reuses applicable parent field definitions through a local-only
`referencing.Registry`, already supplied by the JSON Schema dependencies. Both
schemas are packaged. Unknown schema resources fail rather than being fetched.
Additional properties are rejected at every object boundary. Schema validation
is supplemented by function/line ordering, closure, reference uniqueness,
instruction-address ordering and data-window byte-count checks.

Canonical JSON, strict parsing, hashing, safe paths, Phase 1 verification and
immutable publication are reused. The existing dependency-discovery helper now
accepts an entry module, retaining its previous default; this two-line change
lets it discover the new view module's complete import closure. No parallel
dependency scanner or general workflow framework was added.

## Implemented representation boundary

All conditions preserve the same architecture, entry, assumptions, public function
entries/names, call relationships, external targets, referenced-data bytes/windows,
permissions and recovery limitations. Call-site and data-reference addresses remain
shared. An address-like pseudocode literal is preserved according to its field
origin; it is not treated as an instruction-list leak.

Assembly lines contain only reference, address, mnemonic and operands.
Decompilation lines contain only reference and exact Ghidra text. Combined contains
exactly the two standalone code arrays. Instruction bytes/sizes, body ranges,
name-origin metadata, recovered data-type descriptions, derived string-prefix
descriptions, P-code and stack-object inventories are omitted. Parent data sizes
are explicitly available window sizes, not proven object capacities.

Function and line references follow the unchanged
[initial specification](representation_spec.md): ascending recovered function
entries, one-based `F0001`, `A:F0001:L00001` and `D:F0001:L00001` identifiers,
and original code order. LF splitting preserves leading, internal and trailing
empty segments, indentation, CR characters and Unicode. Joining decompilation
line texts with LF recovers the exact original text. All views serialize using
the retained canonical UTF-8 JSON format with one final LF.

`visible_references(view)` exposes only the code references actually present in a
validated view for the later response adapter. It neither reads a hidden full
instruction inventory nor validates explanation correctness. Response decoding,
prompt construction and voting integration remain Phase 3.

## Artifacts and binding

| Path within projection | Contents |
|---|---|
| `public/views/{representation}/{observation_id}.json` | 480 model-facing views; observation IDs occur in filenames, not inserted into payloads |
| `private/line-maps/{observation_id}.json` | Parent hash and one-based original function/instruction/text-line positions for all A/D references |
| `coordinator/views.json` | Condition IDs, parent/view/map hashes, view byte sizes and visible-reference counts |
| `coordinator/audit.json` | Per-observation repeatability, shared-context equality and standalone/combined subset checks |
| `source/bundles/` | Accepted public parent bytes for offline regeneration, separate from model-facing views |
| `schemas/` | New view schema and exact bound parent public-bundle schema |
| `coordinator/input-manifest.json`, `conditions.json` | Phase 1 identity and exact bound condition ledger |
| `coordinator/dependencies.json`, `dependency-snapshot/` | 15-file local import closure, environment metadata and exact source/requirements snapshots |
| `coordinator/manifest.json` | Completion marker binding all 823 other files |

Preparation first verifies the Phase 1 receipt, then projects public inputs only.
No private evaluation/oracle content is copied into this output. The Phase 2
verifier regenerates views, mappings and audits using only the packaged public
sources, schemas and condition ledger; it needs neither the Phase 1 directory nor
private judgments. Existing destinations cannot be overwritten, files are made
read-only, and missing/extra/changed files or altered audit results fail verification.

The input manifest remains
`b35cdb079c1d8be2b95bb3c2a7b782fbcca2650de573a7a462e90a25df7daf77`.
Both independent projection runs have manifest SHA-256
`3c0ea0bb5950696d55f0063efab1c53246706b46386795bd6af3946bec1aa2d4`.
The new view schema SHA-256 is
`947f4dc03246480f6621aac8b4b356906d52d46631ae230a71e1dd0c20ba40f4`.
These are local content identities, not independent timestamps.

## Gate results

| Check | Verified result |
|---|---:|
| Original observations | 160 |
| Valid views | 480; 160 per representation |
| Shared recovered function instances | 488 across the 160 source bundles |
| Assembly instruction lines | 7,182 |
| Decompilation lines, including empty segments | 9,846 |
| Private lineage maps | 160 |
| Independent repeated projection | All output bytes identical, including manifests and maps |
| Shared-context equality and exact combined subsets | Passed for every observation |
| Parent mutation | None; all 190 Phase 1 files retain their hashes |

View UTF-8 byte ranges are 2,301–13,633 for assembly, 2,283–9,953 for decompilation
and 3,271–20,283 for combined. Byte sizes do not establish tokenizer fit. The audit
explicitly records token fit as pending preflight; no eligibility or context
amendment decision is inferred from these sizes.

## Validation and commands

The complete suite passes **180 tests**, including 50 new Phase 2 checks. They
cover independently specified expected views, exact shared/data fields, absence
of cross-representation fields, nested private metadata, omitted type descriptions,
preserved pseudocode types/address literals, stable references, LF/CR/Unicode
preservation, detached mutable objects, unavailable/noncanonical parents,
all 32 accepted pilot bundles, deterministic batch projection, lineage mapping,
and corruption of schemas/views/maps or rehashed view content. The previous 130
tests continue to pass.

All 480 real final views validate without oracle arguments. Two separate processes
produced byte-identical preparations. A fresh copy also verified using only its
saved source snapshot, with `PYTHONPATH` cleared and bytecode writing disabled;
every copied file remained byte-identical. Unit verification additionally removes
the Phase 1 and original parent locations and blocks the private-input verifier.
Phase 0 artifact hashes and the Phase 1 input preparation remain unchanged.
`git diff --check` passes.

From the repository root:

```sh
# Choose an unused destination for another projection.
.venv/bin/python -m redesign.extensions.representation_study.views prepare \
  --inputs redesign/build/extensions/representation-study/phase1-inputs-v2 \
  --input-manifest-sha256 b35cdb079c1d8be2b95bb3c2a7b782fbcca2650de573a7a462e90a25df7daf77 \
  --directory redesign/build/extensions/representation-study/my-new-views

# Offline: uses the packaged schemas/public sources, with no oracle or server.
.venv/bin/python -m redesign.extensions.representation_study.views verify \
  --directory redesign/build/extensions/representation-study/phase2-views-v1-a \
  --manifest-sha256 3c0ea0bb5950696d55f0063efab1c53246706b46386795bd6af3946bec1aa2d4

.venv/bin/python -m pytest -q
```

Phase 3 can consume the bound views through one common prompt/response adapter.
No compilation, extraction, lifting, tokenization or inference ran in Phase 2.
