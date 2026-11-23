# Phase 3 — common LLM adapter

November 21, 2026. Phase 3 is complete for `public-representation-llm-v1` and
`representation-v1-context12288`. Request construction, strict decoding, visible
evidence validation and vote aggregation pass the offline gate. Phases 4–10,
runtime binding, token preflight, pilot and final inference remain pending.

## Deliverables and reuse

| Component | Implementation |
|---|---|
| Common task template | [prompt.md](../../src/optimization_vuln_analysis/studies/representation/prompt.md) |
| Common strict response grammar | [schemas/response.json](../../src/optimization_vuln_analysis/studies/representation/schemas/response.json) |
| Offline settings, payloads, decoding and attempt adapter | [adapter.py](../../src/optimization_vuln_analysis/studies/representation/adapter.py) |
| Fabricated response/transport fixtures | [test_representation_adapter.py](../../tests/test_representation_adapter.py) |

The adapter reuses the existing request-attempt helper for transport, timeout
classification, elapsed time and response-body/HTTP recording. That helper now
accepts an optional decoder for each call; its default remains the original
instruction-address decoder. The unchanged sampler checks were extracted into a
shared helper, used by both settings loaders. The original settings' model-ID,
schedule and runtime-path checks remain in place. Existing response validators
and locked historical methods were not weakened or changed.

Wire serialization and usage parsing use the root explicit-argument helpers.
`aggregate` is a direct alias of the existing two-of-three voting function, with
no replacement voting implementation. View structure and reference membership
reuse Phase 2 validation and `visible_references`.

Request construction and decoding are local adapters because the original
interfaces embed bundle placeholders, instruction-address evidence and the old
method's settings. The new decoder also validates envelope roles, choice shape,
tool/function-call absence and reasoning/content types, and records typed failure
stages. No new scheduler, transport backend or persistence framework was added.

## Common request and response contract

Every generated request has one user message, the same task wording and schema,
one completion, `stream=false` and `cache_prompt=false`. Only the canonical supplied
view changes across representations; repetition selects seeds 4101/4102/4103.
All 24 sampler fields retain their declared values and order. Unknown sampler
fields cannot inject tools or other request settings.

The prompt describes feasible compiled stack/heap writes, uncertain recovered
bounds, referenced-data windows and deliberate representation omission. It does
not require decompilation-only answers to reconstruct unseen emitted instructions.
Code, names, strings and data are evidence, never instructions that change the
task. The full study policy, private labels, observation IDs and previous answers
are not inserted into the prompt.

Responses contain exactly `decision`, `confidence`, `evidence` and `summary`.
Confidence must be finite and between zero and one, excluding booleans. Summary
must be nonblank. Evidence permits zero to five unique visible line references;
empty evidence is valid for every decision and condition. Assembly can cite A
references, decompilation D references and combined either. Raw addresses and
shared metadata do not supply evidence-reference identifiers.

Strict parsing rejects duplicate JSON keys and nonstandard nonfinite literals.
There is no substring extraction, fence removal, reasoning removal or answer repair.
Length termination fails even when answer text is otherwise valid JSON. Duplicate
or invisible references fail the slot. A structurally valid but semantically wrong
label remains valid output for later scoring; visibility does not prove reasoning
correctness.

The attempt record returns raw answer/reasoning, full response-body text, HTTP
status, finish reason, usage, elapsed seconds, parsed output, status and error.
`validation_failure` is null on success; failures carry a stage, code and schema
path where applicable. Stages distinguish transport, envelope JSON, envelope
shape, completion termination, answer JSON, answer schema and answer validation.
Missing or invalid token counts remain unknown. Transport exceptions produce one
terminal attempt with no retry. Durable dispatch/publication remains the runner's
responsibility in Phase 4.

Malformed nontext reasoning/finish values remain in the exact response body;
their normalized text fields are null. This keeps failed-attempt records
serializable even for legal JSON numeric exponents that overflow Python floats,
without repairing or accepting the malformed answer.

Offline settings validate the protocol without checking for a model installation
or contacting a server. This does not bind a live runtime or establish execution
readiness. The initial policy and all previous input/view artifacts remain unchanged.

## Gate evidence

The complete regression suite passes **339 tests**, including 159 new adapter
cases and the previous 180 checks. New checks cover all three representations,
four labels with empty evidence, mixed five-reference combined evidence,
duplicates/nonvisible references, invalid confidence/summary/schema fields,
malformed envelopes and JSON, role/tool/function-call violations, finish reasons,
empty answers, HTTP failures, unknown usage, timeout/connection failures and
serialization of malformed numeric metadata.
Raw material is preserved and transport executes once in fabricated tests.

One independent arithmetic fixture exhaustively checks all 125 combinations of
four possible valid decisions plus a failed vote over three slots. It verifies
majority, uncertain-majority abstention, disagreement, unavailable results and
confidence medians without confidence weighting. Tests also demonstrate that the
original validator still rejects new line references as instruction addresses.

The [offline check receipt](../../artifacts/history/redesign/build/extensions/representation-study/phase3-offline-v2/checks.json)
and [request identity ledger](../../artifacts/history/redesign/build/extensions/representation-study/phase3-offline-v2/request-identities.json)
record a separate full-matrix check:

| Check | Result |
|---|---:|
| Bound views checked | 480 |
| Requests constructed offline | 1,440; 480 per condition |
| Unique observation/representation/repetition keys | 1,440 |
| Common task, grammar and request settings | Identical across conditions |
| Fabricated envelopes decoded as valid | 480; one structural fixture per view |
| Live requests / tokenization calls | 0 / 0 |

These fabricated answers are engineering fixtures, not model observations or
accuracy results. Request hashes are construction evidence, not a final wire
payload freeze. The receipt records the 16-file local import closure and installed
environment. All 823 Phase 2 artifact hashes remained unchanged. No private oracle
or historical response was used to construct or validate the fixtures.

| Artifact | SHA-256 |
|---|---|
| Common prompt | `c4b2709fbbec3d34132086957196353c4ee8147cdb2774e41ee36f9602fe19db` |
| Common response schema | `c33e4e8ece06f0b98d035da0d46ffff1ea5b182c0b73822faffdcfb60e103617` |
| Offline check receipt | `cfe0efa43206731aaac2388226a76c5d5bc4ca6ac768d07288710e2486b4044c` |

The Phase 2 input manifest remains
`3c0ea0bb5950696d55f0063efab1c53246706b46386795bd6af3946bec1aa2d4`.
Local hashes bind content, not an independent timestamp. `git diff --check` passes.

From the repository root:

```sh
.venv/bin/python -m pytest tests/test_representation_adapter.py -q
.venv/bin/python -m pytest -q
```

`settings()` returns the explicit policy, common prompt and response schema.
`payload(...)` builds the stateless request, `decode(...)` validates a saved or
fabricated envelope, `attempt(...)` performs one caller-dispatched transport
attempt, and `aggregate(...)` applies the retained voting rule. The runner must
save durable dispatch before transport and never retry terminal slots. This
phase introduces no live inference command; Phase 4 implements scheduling and
durable execution before the later pilot/preflight/freeze gates.
