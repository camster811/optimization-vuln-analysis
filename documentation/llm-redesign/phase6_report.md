# Phase 6 — Engineering pilot integration

Completed November 22, 2026. **All 18 predeclared live engineering slots returned
valid responses**, six per representation. There were no blocked inputs,
transport/schema failures, length terminations, interruptions or retries. Saved
responses regenerate all six condition aggregates. The pilot is excluded from
final scoring; the final 1,440 slots remain entirely pending.

## Implementation and acceptance tests

One new production module,
[`pilot.py`](../../src/optimization_vuln_analysis/studies/representation/pilot.py), binds the
accepted pilot inputs, selects smoke cells and checks integration evidence. The
final inventory adapter assumes a frozen final release and private truth; the
pilot needs a local accepted-input binding without truth or historical answers.
The pilot adapter preserves those existing final checks and supplies the
projection manifest format needed by the retained verifier.

The adapter reuses inventory generation, source/record hashes, condition/slot
identities, `views._render`, `views.verify` and the complete Phase 4 runner/runtime.
It projects all 32 pilot observations into 96 views, then selects two observations
and their six views for the smoke execution. The derived engineering policy
changes private configuration/matrix metadata and records exclusion from final
scores. Its prompt, response schema, model, samplers, seeds, timeout and resource
limits retain the common study settings. Initial policy bytes remain unchanged.

[`test_representation_pilot.py`](../../tests/test_representation_pilot.py) adds
11 checks covering deterministic staging, metadata-only selection, truth
independence, accepted/extracted input hashes, missing/unavailable inputs,
unchanged model settings, exact projector reuse, tampering, offline verification
and complete fake execution. Uncertain answers can pass the integration gate;
schema failures require review, and length-limited slots remain failed slots.
No correctness target determines acceptance.

**408 offline tests passed in 309.78 seconds before the first live dispatch.**
The pre-generation receipt binds the test files and pilot source. No shared
production helper needed modification. The live pilot required no prompt,
schema, sampler or budget repair and introduced only configuration
`representation-v1-context12288-pilot-v1`.

## Inputs and predeclared smoke cells

All 32 current public bundles match the hashes in the accepted original pilot
input manifest and accepted extraction manifest. Source configuration, corpus,
build plan, extraction and schema bindings are retained with the preparation.
Preparation does not read the private oracle or saved historical predictions.
Both selected families are disjoint from the ten bound final families.

The fixed rule is vulnerable source variant, O0, retained symbols, one cell per
existing pilot family. Selection was saved before generation:

| Pair / family | Observation ID |
|---|---|
| `pilot-01`: `CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_loop` | `ra5f6072d3eed46cfbcd279df` |
| `pilot-02`: `CWE122_Heap_Based_Buffer_Overflow__c_CWE129_large` | `rc24d885eb5101822727fe6bf` |

Each observation receives assembly, decompilation and combined inputs, with
repetitions/seeds 1/4101, 2/4102 and 3/4103. The existing deterministic shuffled
schedule governs all 18 fresh requests. They have their own engineering
configuration, condition/slot identities, requests and dispatch journals.

## Runtime feasibility and live results

The captured model, server binary, libraries, source tree, properties/chat
template, full GPU offload and flash attention match the frozen parent runtime.
The study policy identity differs because it identifies the new pilot protocol.
The model is DeepSeek-R1-Distill-Qwen-14B Q5_K_M, model SHA-256
`3eea644370914aebfff274dd8f5a790aaee42ba69a1ce09051eeaad0f05afd32`.
The server confirms 49 GPU layers, flash attention enabled and one slot at
12,288 context tokens. Its binary SHA-256 is
`7ea2c663925ee73d03d41e0a84ff687c17a57e6c40f42e65fdade36e2cd27a9a`.

All 18 exact requests were rendered/tokenized before generation. Each view's
three repetitions have the same prompt count. Every request reserves 4,096
completion tokens, with no padding, truncation or budget amendment:

| Observation | Representation | Prompt tokens | Prompt + reservation |
|---|---|---:|---:|
| `ra5f6072d3eed46cfbcd279df` | assembly | 3,717 | 7,813 |
| `ra5f6072d3eed46cfbcd279df` | decompilation | 2,218 | 6,314 |
| `ra5f6072d3eed46cfbcd279df` | combined | 4,960 | 9,056 |
| `rc24d885eb5101822727fe6bf` | assembly | 5,715 | 9,811 |
| `rc24d885eb5101822727fe6bf` | decompilation | 3,207 | 7,303 |
| `rc24d885eb5101822727fe6bf` | combined | 7,381 | 11,477 |

Both observations were eligible for all nine of their slots. All actual
response usage prompt counts match the saved preflight counts.

| Representation | Valid / scheduled | Prompt tokens | Completion tokens | Recorded response seconds |
|---|---:|---:|---:|---:|
| assembly | 6 / 6 | 28,296 | 6,568 | 122.90 |
| decompilation | 6 / 6 | 16,275 | 5,554 | 100.52 |
| combined | 6 / 6 | 37,023 | 5,468 | 107.97 |
| Total | 18 / 18 | 81,594 | 17,590 | 331.39 |

All responses include saved raw reasoning; all finish with `stop`. Completion
usage ranges from 564 to 3,130 tokens. The response schema, confidence checks and
membership of every cited reference in the supplied view validate. Empty evidence
remains permitted. These counts establish engineering feasibility, not pilot
accuracy, calibration or evidence that model explanations are correct.

## Durability, offline replay and artifact identities

Execution uses the existing durable pre-dispatch journal and no-retry state
machine. All 18 unique dispatches have raw responses and terminal results;
offline verification reconstructs their decoding and six three-vote aggregates.
One captured runtime event was sufficient; no restart was needed.

After stopping the owned server, a fresh-directory restore copied the saved
18-file source dependency closure, preparation and execution. With PYTHONPATH
cleared and HTTP/runtime/tokenizer calls disabled, `pilot.check` reproduced its
saved JSON bytes exactly. Running the already completed restored packet sent
no request and changed no execution bytes. The listener was confirmed released.
The pre-generation regression and token-preflight receipts still match, and the
original final request packet verifies as 1,440 pending slots with zero dispatches.

Artifacts are under `redesign/build/extensions/representation-study/`:

| Artifact | SHA-256 |
|---|---|
| `phase6-pilot-v1/manifest.json` — 268 preparation files, plus manifest | `641952fc8fd3b3033e166a4f664985e1580c67c0d3d88f4c24800ab8717ace13` |
| `phase6-execution-v1/coordinator/manifest.json` — 50 static inputs | `57ca8f65c841828a1e168706561f617eb73f4e4ee106eb22a7b4a7fb9c05d8d2` |
| `phase6-predeclared-v1.json` — selection and actual token fit, before generation | `c43911287a604a5a5c89b4f8444e2081bd0939b1edc573ee0cdafed88a09230c` |
| `phase6-regression-v1.json` — 408 passing offline tests, before generation | `5a3a942a0797f5a8a8fb8a6200b4dbad62d10fadbb6d637dc3bc70d86c301afd` |
| `phase6-integration-v1.json` — saved pilot check / six aggregates | `41f79bee0f5a27a47aff7c0432e6664d780f8947445b5eb13398795b857384da` |
| `phase6-checks-v1.json` — acceptance and restore receipt | `a8a6ae6a11434ba60e3bea7b5013502c1aa825db63424ded30adaac1f56cf8b7` |
| `phase6-completion-v1.json` — all 108 execution files, runtime files and receipts | `6c78d746ce2b9e4f90ca953165db01d4ab93fb030ec4eed5393c1e0472491db8` |

`phase6-slot-metadata-v1.json` retains per-slot timing, usage, finish reason,
reasoning length and evidence-reference counts. `phase6-runtime-v1/` retains the
launch, startup log and captured runtime identities. The completion manifest
binds all raw execution outcomes, runtime files and receipts without adding files
to the runner's strict inventory. Local hashes provide content binding, not a
third-party timestamp.

These read-only commands work with the server stopped:

```sh
.venv/bin/python -m redesign.extensions.representation_study.pilot verify \
  --directory redesign/build/extensions/representation-study/phase6-pilot-v1 \
  --manifest-sha256 641952fc8fd3b3033e166a4f664985e1580c67c0d3d88f4c24800ab8717ace13

.venv/bin/python -m redesign.extensions.representation_study.runner verify \
  --directory redesign/build/extensions/representation-study/phase6-execution-v1 \
  --manifest-sha256 57ca8f65c841828a1e168706561f617eb73f4e4ee106eb22a7b4a7fb9c05d8d2

.venv/bin/python -m redesign.extensions.representation_study.pilot check \
  --directory redesign/build/extensions/representation-study/phase6-pilot-v1 \
  --execution redesign/build/extensions/representation-study/phase6-execution-v1
```

Phase 6 is complete. Full final token preflight/scorer freeze, final generation,
analysis and release remain Phases 7–10. Only the 18 engineering requests ran;
pilot correctness was not used to select cells, tune the protocol or accept the
integration gate.
