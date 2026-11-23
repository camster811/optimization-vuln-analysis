# Phase 7 — Final preflight and method freeze

Completed November 22, 2026. The final campaign is frozen before generation:
**160 observations, 480 views and 1,440 scheduled slots**. All exact requests
were rendered and tokenized with the pinned local runtime. Four combined views
do not fit, so the locked common-eligibility rule schedules **1,404 requests and
36 input-blocked slots**. All 160 observations remain in the adjudicated
denominator, and the unconditional safe control remains available for every one.
**No final slot has been dispatched and no final answer has been generated.**

## Implementation and regression evidence

One new production module,
[`freeze.py`](../../artifacts/history/redesign/build/refactor/r5-v1/source-before/redesign/extensions/representation_study/freeze.py), adds
template-overhead accounting, immutable publication, offline verification,
working-execution checks and deterministic archive/restore adapters. It reuses
the inventory and view verifiers, exact request reconstruction, preflight/state
validation, computational identity, pilot check, dependency discovery, synced
publication and scorer's family draws. No existing production module changed.
The existing parent-archive verifier is specific to the historical parent
contract; the new archive adapter binds this study's detached manifest instead.

The freeze includes **21 imported local source files**, including the scorer,
shared metric arithmetic and imported root inference/runtime helpers. It also
includes requirements, exact Python/package versions, installed-distribution
inventory, protocol/schema resources, all regression test files and the initial
analysis/representation contracts. The evaluation contract binds method IDs,
ordered contrasts, unconditional control and the 10,000-draw PCG64 family
resampling configuration. Its shared multiplicity matrix retains SHA-256
`4e9ea9fd8b596009e8f805711064431999efc91080b5428520dccd09054843ff`.

[`test_representation_freeze.py`](../../artifacts/history/redesign/build/refactor/r5-v1/source-before/tests/test_representation_freeze.py)
adds 26 checks covering common blocking, explicit request/block dispositions,
control availability, raw-content/template accounting, method/environment drift,
stale test evidence, wrong-purpose or already-started executions, corruption,
missing/extra files, symlinks, deterministic archives, traversal/duplicate-member
rejection and byte-exact restore. Scorer-contract mutations are rejected.
Offline verification is tested with runtime access disabled and no original
repository location available.

**434 offline tests passed in 411.05 seconds before sealing.** The regression
receipt binds the exact source/test/requirements hashes and the preflight,
accounting, pilot completion and standalone runtime evidence hashes.
`git diff --check` passes.

## Actual final token accounting

The new working packet is
`redesign/build/extensions/representation-study/phase7-final-v1`, with purpose
`final`. The earlier Phase 4 engineering packet remains intact. The final
policy, common [prompt](../../src/optimization_vuln_analysis/studies/representation/prompt.md),
response schema, full sampler configuration, seeds and timeout are unchanged.
Context stays **12,288 tokens**, completion reservation **4,096 tokens**, leaving
8,192 prompt tokens. No padding, truncation or context amendment was applied.

The captured final model, server binary, libraries, source, chat template,
properties, 49-layer GPU offload and flash attention match the accepted pilot.
The initial runtime event retains complete process/model/template identities;
the GGUF and external runtime binaries are pinned by hash rather than bundled.

All **1,440 wire payloads** received actual template rendering and prompt
tokenization. Raw user content was separately tokenized for **396 distinct
messages**, reusing identical content across repetitions/equality groups. The
net overhead is rendered-prompt tokens minus user-content tokens with
`add_special=false, parse_special=true`; rendered requests use the shared
preflight's `add_special=true, parse_special=true`. The measured overhead is
**three tokens for every request**. Prompt token IDs, rendered strings, counts,
reservations, request hashes and raw-content IDs/counts are saved.

| Representation | Views | Prompt-token range | Nonfitting views | Planned requests | Planned blocked slots |
|---|---:|---:|---:|---:|---:|
| assembly | 160 | 1,283–6,238 | 0 | 468 | 12 |
| decompilation | 160 | 1,260–4,947 | 0 | 468 | 12 |
| combined | 160 | 1,688–9,291 | 4 | 468 | 12 |
| Total | 480 | | 4 | 1,404 | 36 |

The nonfitting observations are:

| Observation ID | Source variant / optimization / symbols | Combined prompt tokens | Prompt + completion reservation |
|---|---|---:|---:|
| `r056bfd421a55d16c53a40be0` | safe / O0 / stripped | 9,244 | 13,340 |
| `r106011d15c96fd16f846b638` | safe / O0 / retained | 9,104 | 13,200 |
| `r652b0bd129403ad05df9a8bc` | safe / O0 / retained | 9,151 | 13,247 |
| `rd235b8027ffdfea941d8f5c4` | safe / O0 / stripped | 9,291 | 13,387 |

The first pair belongs to
`CWE121_Stack_Based_Buffer_Overflow__CWE806_wchar_t_declare_memmove`; the second
to `CWE121_Stack_Based_Buffer_Overflow__src_wchar_t_declare_cpy`. All standalone
views fit, but all nine LLM slots for each observation are blocked under the
predeclared rule. This retains 156 common-eligible observations as a secondary
analysis and all 160 in the primary denominator. The blocking decision was
reported before any final generation. Input-size differences are part of the
practical representation treatment, not evidence of a pure syntax effect.

`fit.json` freezes the 160 eligibility flags, all 480 per-view measurements and
all 1,440 request-or-block dispositions. The runner packet itself still has
1,440 pending slots and no outcome journals: Phase 8 will write the explicit
blocked terminal records without transport and dispatch only eligible slots.

## Immutable publication and detached archive

The publication directory is:

```text
redesign/experiments/llm-representation-v1/representation-v1-context12288-final-v1/
```

It contains verified Phase 1 inputs/private truth, Phase 2 projections, the
pre-generation final execution, accepted pilot preparation/raw execution,
accounting and fit ledgers, evaluation contract, source/resources/test snapshots,
regression evidence and `freeze.json`. There are **3,388 bound files plus the
freeze manifest**. The private evaluation ledger is separately bound in the
manifest; it is never used to construct predictor payloads.

The adjacent archive contains all 3,389 files and is 11,213,715 bytes. File
ordering, tar metadata and gzip timestamp are deterministic. Regular-file-only
membership and every member hash are verified before restoration. Publication
completion markers and the detached manifest are written after their inputs.

| Artifact | SHA-256 |
|---|---|
| Publication `freeze.json` | `fbd6d84c4222ac147c9ea6be730ed6efa2a658b1ac53dfd9b516a9d757c25249` |
| `representation-v1-context12288-final-v1-inputs.tar.gz` | `f711f9bd61c9aea0f82812ec1103c3841f08bc5af3ac00bcf66d1f64fd9bb7d5` |
| `representation-v1-context12288-final-v1-inputs.json` — detached manifest | `f8baf6b52d0c93a5c40d95046950c78aa72c4b3e5a41b942b34dc09ea87d0448` |
| Build `phase7-accounting-v1.json` | `e7f24f775beb05d6e6e02f1f60cfb880e5e5c9df45f8627988730fb44cc215db` |
| Build `phase7-regression-v1.json` | `0f78648cd7396afed88682c9291c2409509c8151a51704e1611bee484be33436` |
| Build `phase7-checks-v1.json` — restore/acceptance receipt | `63882a64eb0319d9e7b0733244212ca0d50491d86efbc580dbf2d28bee0768ec` |

The build receipts are under
`redesign/build/extensions/representation-study/`. Standalone server launch,
startup log and capture remain in `phase7-runtime-v1/`, with their hashes in the
packaged regression receipt. The server was stopped after accounting. The
archive is marked **internal**: it includes private oracle material and raw
engineering-pilot outcomes. Local content hashes/timestamps do not establish
third-party timestamping or independent preregistration.

## Offline reproduction and Phase 8 boundary

The archive was restored into a fresh directory. Every restored file matches
the publication bytes. Using only its saved source/input snapshot with the
existing pinned Python/packages, no original project-source/data fallback and
HTTP/runtime calls disabled, verification reproduced the saved receipt bytes
exactly. The working final execution also passes the full source/environment
and frozen-request/preflight guard. The accepted pilot and earlier bound input
artifacts retain their original identities.

These commands are read-only and work with the server stopped:

```sh
.venv/bin/python -m redesign.extensions.representation_study.freeze verify \
  --directory redesign/experiments/llm-representation-v1/representation-v1-context12288-final-v1 \
  --manifest-sha256 fbd6d84c4222ac147c9ea6be730ed6efa2a658b1ac53dfd9b516a9d757c25249

.venv/bin/python -m redesign.extensions.representation_study.freeze verify-archive \
  --archive redesign/experiments/llm-representation-v1/representation-v1-context12288-final-v1-inputs.tar.gz \
  --detached redesign/experiments/llm-representation-v1/representation-v1-context12288-final-v1-inputs.json \
  --manifest-sha256 f8baf6b52d0c93a5c40d95046950c78aa72c4b3e5a41b942b34dc09ea87d0448

.venv/bin/python -m redesign.extensions.representation_study.freeze guard \
  --directory redesign/experiments/llm-representation-v1/representation-v1-context12288-final-v1 \
  --execution redesign/build/extensions/representation-study/phase7-final-v1
```

`freeze restore` accepts the archive, detached manifest and a destination that
does not already exist. It validates the archive before creating that destination and
checks restored contents offline. The immutable publication stays separate
from the working execution. Phase 8 must start/capture a matching owned server
and append restart evidence before dispatching remaining requests; no terminal
slot may be retried. Final execution, saved-result analysis and release remain
Phases 8–10.
