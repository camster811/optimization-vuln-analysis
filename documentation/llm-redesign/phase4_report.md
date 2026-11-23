# Phase 4 — durable execution and verified restarts

November 21, 2026. Phase 4 is complete for the representation-study executor.
The implementation passes its fake-transport gate. Phases 5–10, live pilot,
actual tokenizer preflight and the complete final method/input freeze remain pending.

## Implementation and reuse

The phase adds one [`runner.py`](../../src/optimization_vuln_analysis/studies/representation/runner.py).
It consumes the existing condition ledger and reuses
`inventory.conditions_and_slots` for the declared seed-20261121 block/condition
order. Request construction, wire serialization, response decoding, transport,
voting, hashing, safe paths and durable immutable publication reuse existing helpers.
Each condition's request template is constructed once; only the declared seed
changes across its repetitions. Every slot still has its own exact wire file/hash.

Runtime adaptation lives in the same module. Computational identity is a pure
comparison of the captured policy/model hashes, server binary, libraries, source,
properties/chat template, context/slot settings and GPU/flash-attention evidence.
Process PID/start ticks and model-file stat metadata may change on a verified
restart; computational settings may not. Capture, live process/listener/model
verification and actual-template token accounting reuse `llm_runtime` functions.
The existing server-launch branch was extracted into `serve(directory, policy)`;
both its original CLI and the new runner delegate to it with explicit policy.
No separate runtime framework or replacement scheduler was needed.

## Prepared requests and state transitions

The accepted real-input engineering packet is
[`phase4-offline-v1`](../../artifacts/history/redesign/build/extensions/representation-study/phase4-offline-v1).
It binds 160 observations, 480 conditions and 1,440 requests in 1,946 immutable
files, plus its completion manifest. Its 17-file source import closure and
requirements/environment metadata are snapshotted. All 1,440 request hashes
exactly match the Phase 3 offline request identities.

Preparation is offline. It verifies the Phase 2 source, snapshots the common
policy/prompt/schemas and views, and publishes the manifest last. Existing
destinations cannot be overwritten. Runtime and token accounting are bound
separately; the real packet currently has **1,440 pending slots, zero runtime
events and no bound preflight**. It is not a final study freeze.

| Artifact | Meaning |
|---|---|
| `coordinator/manifest.json`, `schedule.json` | Immutable run identity/purpose, source bindings, ordered slot/request identities |
| `protocol/`, `public/views/` | Frozen policy, prompt, schemas and actual supplied views |
| `coordinator/dependency-snapshot/` | Exact local imported sources and requirements |
| `coordinator/preflight.json` | Immutable request-bound template/token accounting, computational identity and common observation eligibility |
| `runtime/000001.json`, subsequent sequence files | Append-only captured sessions with previous-event hash and matching computational settings |
| `slots/{representation}/{observation_id}/{repetition}/dispatch.json` | Durable dispatch intent with schedule index, request/preflight/runtime bindings and previous-dispatch hash |
| `response.json` in that slot | Raw/decoded adapter result, bound to the dispatch, saved before post-request checks |
| `result.json` in that slot | Terminal disposition and response hash; does not overwrite the response |

An exclusive OS file lock covers execution, preflight and runtime registration.
Before dispatch, the runner verifies the frozen common inputs, selected view/wire
bytes, executing local source hashes and current live runtime identity. It syncs
the dispatch record before calling transport. After receipt, it durably saves
the response, checks identities again and publishes the terminal marker. A
post-request runtime/input mismatch preserves the response and produces
`runtime_changed`, with no valid vote from that slot.

Only provably never-dispatched slots can execute on resume. Any dispatch lacking
a terminal completion marker is conservatively `interrupted`, even if raw response
receipt was saved before completion publication failed: the post-request checks
were not durably acknowledged. Recovery writes the interruption marker without
repeating transport. Timeouts, HTTP/schema/length failures and completed slots
are likewise never retried.

Recognized `.pending-*` files left by interruption of atomic publication remain
preserved and are reported as uncommitted evidence. They are never substituted
for committed records. Raw response journals use lossless JSON escaping so unusual
strings remain serializable while the exact response-body text is retained.

## Runtime, eligibility and offline verification

Preflight uses the retained apply-template/tokenizer helper for every frozen
request and verifies the captured runtime before and after accounting. Offline
checks verify token IDs/counts, completion reservation, request hashes and fit
status. If any representation/repetition does not fit for an observation, all
nine slots get explicit `input_blocked` terminal records and make no request.
The unconditional control remains separate and unchanged for Phase 5.

Initial session evidence is bound with preflight. A later process must be freshly
captured, pass live ownership checks and match that frozen computational identity
before an append-only runtime event permits further dispatch. The event and
dispatch hash chains expose missing/reordered or altered records. Earlier slots
are preserved. A changed context, template, model/server/library/source identity
cannot silently continue the run.

`verify` acquires a read-only shared lock for a consistent offline snapshot; it
does not create a lock file, query runtime/tokenizer endpoints, send requests,
write completion markers or rewrite results. It verifies immutable membership
and hashes, regenerates requests/schedule, checks runtime/preflight/dispatch chains,
re-decodes saved HTTP responses and reconstructs terminal counts and condition
aggregates. It reports incomplete dispatches as interrupted without modifying them.
Verification during an active writer fails with lock contention rather than
interpreting an in-flight request as a completed outcome.

## Gate evidence

The complete suite passes **369 tests**, including 30 new runner checks and the
previous 339 checks. Coverage includes independent request/schedule reconstruction,
interruption before dispatch, after dispatch and after response receipt; orphaned
atomic-write files; all-nine-slot input blocking; no retries; matching restarts;
incompatible model/binary/library/template/context/source changes; post-response
identity failure; corrupt view/prompt/request/schema/schedule/result/runtime/preflight
files; changed executing source; real OS lock contention; transport/HTTP/schema
failures and unusual Unicode response storage. The new runtime CLI is tested to
delegate the explicit representation policy to the shared launcher.

The separate [synthetic execution](../../artifacts/history/redesign/build/extensions/representation-study/phase4-synthetic-v1)
and [check receipt](../../artifacts/history/redesign/build/extensions/representation-study/phase4-checks-v1.json)
exercise a complete 32-observation engineering fixture with fake budget/runtime/HTTP
functions. They contain no model observations and are excluded from study results:

| Synthetic check | Result |
|---|---:|
| Planned / terminal slots | 288 / 288 |
| Valid synthetic responses | 277 |
| Input-blocked slots | 9 |
| Timeout / interrupted slots | 1 / 1 |
| Unique dispatches / repeated dispatches | 279 / 0 |
| Captured synthetic runtime sessions | 2 |
| Reconstructed condition aggregates | 96 |
| Live generation requests / real tokenizer queries | 0 / 0 |

A fresh copy of that completed execution verified using its saved source snapshot
with `PYTHONPATH` cleared and bytecode writing disabled. All copied file bytes
remained unchanged, including raw failures, event chains and terminal records.
An offline second execution pass made zero additional transport calls. The real
1,440-slot packet remains entirely pending. `git diff --check` passes.

| Artifact | SHA-256 |
|---|---|
| Real-input pending packet manifest | `0f8d360a20c78fc8a80bd04d98878005b007d2a75a0cc07e1ced3f82bfc25888` |
| Completed synthetic packet manifest | `fe2397ef53c97209da24c3f90fda4e33f7d102743d2fb853d9b35302ffae9220` |
| Engineering check receipt | `686fb9a72d6bff81b6290bf01d095b7856f158ee88aed5e198fd9319447d8200` |

These hashes identify local evidence, not independent timestamps. Prior input/view
releases and the Phase 0 policy remain unchanged.

## Commands and remaining boundary

From the repository root:

```sh
# Choose an unused destination; this only prepares engineering requests offline.
.venv/bin/python -m redesign.extensions.representation_study.runner prepare \
  --projection redesign/build/extensions/representation-study/phase2-views-v1-a \
  --projection-manifest-sha256 3c0ea0bb5950696d55f0063efab1c53246706b46386795bd6af3946bec1aa2d4 \
  --directory redesign/build/extensions/representation-study/my-new-request-packet \
  --purpose engineering

.venv/bin/python -m redesign.extensions.representation_study.runner verify \
  --directory redesign/build/extensions/representation-study/phase4-offline-v1 \
  --manifest-sha256 0f8d360a20c78fc8a80bd04d98878005b007d2a75a0cc07e1ced3f82bfc25888

.venv/bin/python -m pytest -q
```

The same CLI exposes `serve` and `capture` for owned server sessions, `preflight`
for actual token accounting, `register-runtime` for a captured restart and `run`
for execution. Runtime binding takes `--server` pointing to captured evidence;
server operations take `--protocol-root` for explicit settings. `run --max-slots 0`
performs recovery and writes known blocked dispositions without dispatching eligible
slots. A run without bound preflight cannot dispatch.

These are executor interfaces for later engineering/final workflows. They do not
replace the Phase 5 scoring gate, Phase 6 live pilot or Phase 7 complete final
method/input/evaluation freeze. No live model, actual tokenizer or new study
inference ran in Phase 4.
