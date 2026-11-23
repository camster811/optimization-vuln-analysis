# Phase 6: public-bundle LLM integration

Phase 6 implements `public-bundle-llm-v1`. Method lock remains pending Phase 7. The initial DeepSeek-R1-Distill-Qwen-14B Q5_K_M model, 8,192-token context, and full 4,096-token completion reservation are retained. No final inference or final-case selection is performed.

## Implementation and reuse

`redesign/llm_policy.json`, `redesign/llm/prompt.md`, and `redesign/llm/response.schema.json` define the independent redesign method. The prompt describes the selected entry scope, direct application calls, multiple functions, referenced bytes and permissions, and uncertain recovered boundaries. It requests compiled-behavior labels and instruction evidence; it prohibits benchmark, identifier, and class-balance shortcuts. Observation identifiers and private oracle facts stay outside requests.

`redesign/pipeline/llm.py` reuses only the predecessor's generic HTTP transport and usage parser. It does not reuse flat-function input discovery, response evidence validation, or retry/resume behavior. Evidence may reference instruction starts in any included function; data addresses and absent instructions are rejected. Duplicate JSON keys, nonfinite confidence, malformed answers, extra fields, empty answers, unexpected finish reasons, and duplicate evidence are failures. `finish_reason=length` remains a failure even if the answer parses. Raw reasoning and content remain separately available alongside the complete response body.

`llm_runtime.py` reuses generic process identity, listener ownership, model hashing, launcher configuration, and source identity helpers. Runtime capture verifies the pinned model hash, owned listener, exact server command/process start, context size, single slot, full GPU offload, and enabled flash attention. Every dispatch checks process/binary identity, model file metadata, server properties, and local llama.cpp shared-library hashes. The prompt, schema, policy, request bytes, public inputs, and implementation hashes are checked before and after requests. A detected change after dispatch makes the attempt a failure and stops the run.

`run_llm.py prepare` enumerates the declared pilot inventory and freezes only public inputs for inference. It calls the live server's `/apply-template` with the actual chat payload, then `/tokenize` with both `add_special` and `parse_special` enabled, matching the pinned server's chat tokenization path. Rendered prompts and token IDs are preserved for each request. Inputs are never cropped to fit.

`run` sends one stateless request at a time: one user message, no prior conversation, `cache_prompt=false`, fixed sampler settings and seeds 4101–4103. Slots follow ascending SHA-256 of `20261019\n{observation_id}\n{repetition}`, with identifier and repetition tie breakers. Requests are saved in the exact canonical encoding used by the reused transport. The transport has no automatic retry or redirect and ignores proxy environment settings.

An exclusive runner lock prevents concurrent dispatches within one run directory. Before HTTP dispatch, a complete marker is atomically published and fsynced. Results use the same exclusive publication mechanism. A dispatch without a durable result becomes terminal `interrupted` on resume, even if the request may never have reached the server. It is never retried. Corrupt completed results block further work. Only slots with no dispatch marker can run on continuation under the same runtime/method identity. New directories do not authorize replacement of prior attempts; Phase 7 must retain the selected run and its chronology.

Aggregation requires all three terminal slots: two matching valid labels win, including two `uncertain` votes. Valid votes without a majority yield `uncertain`; zero valid votes yield unavailable. Confidence is the median over all valid responses, including minority votes, and never weights a vote.

## Measured context gate

All 32 public pilot bundles and all 96 request payloads were tokenized using the pinned live model/template. Prompt sizes range from **1,601 to 6,657 tokens**. **26 bundles fit; six receive `context_unavailable`** with the full completion reserve. This is an explicit availability result, not extraction failure or an overflow prediction. No prompt or model changes were made from prediction inspection.

The server successfully loaded all layers with flash attention on the RTX 5070 Ti (16,303 MiB reported capacity). During live validation, `nvidia-smi` reported 12,503 MiB total device memory used, including other device consumers. Successful loading and requests establish feasibility at 8,192 tokens; they do not establish feasibility for a larger context.

The six unavailable identifiers are recorded in the machine-readable Phase 6 provenance. This **shared availability overlay must be applied to both methods in Phase 7 comparisons**. Phase 5's historical 32-cell results remain historical results under their original eligibility; they must not be presented as a paired comparison against the 26 eligible LLM inputs without applying the overlay. The public Phase 4 records and immutable Phase 5 replay artifacts are preserved.

## Validation and limits

Thirty new regression tests cover cross-function evidence, invalid evidence and response structures, exact context boundary accounting, stateless seed changes, aggregation, immutable publication, crash-after-dispatch continuation, unavailable-input suppression, corrupt terminal files, prompt mutation, and process/model/library/property mutation. The complete suite with `GHIDRA_HOME` unset passes **194 tests and 80 subtests**, with **55 optional Ghidra tests skipped**. Phase 6 changes no extraction or baseline method files; their previous Ghidra results are documented separately and are not claimed as rerun here.

Three scheduled pilot requests exercise actual dispatch, raw response capture, usage, timing, and strict validation. All three were valid, with 643–1,268 completion tokens; reported prompt counts matched preflight exactly. The machine-readable provenance records their outcomes. This is a partial pilot integration check, not the complete Phase 7 pilot or an accuracy estimate. No aggregate conclusions are drawn from incomplete repetition groups.

[Versioned provenance](../../redesign/provenance/phase6-validation.json) and the [accompanying archive](../../redesign/provenance/llm/phase6-a.tar.gz) preserve runtime capture, the complete preparation manifest, public request inputs, exact requests, rendered prompts/token IDs, dispatch markers, and completed responses. The live server must retain the same process identity to continue this particular run. Restarting it intentionally blocks continuation; any later replacement campaign needs a documented decision preserving all earlier attempts.

## Commands

From the repository root, use a new directory for initial preparation:

```bash
.venv/bin/python -m redesign.pipeline.llm_runtime serve --directory redesign/build/pilot/llm-runtime/phase6-a
# In another terminal after the server is ready:
.venv/bin/python -m redesign.pipeline.llm_runtime capture --directory redesign/build/pilot/llm-runtime/phase6-a
.venv/bin/python -m redesign.pipeline.run_llm prepare --directory redesign/build/pilot/llm/phase6-a --server redesign/build/pilot/llm-runtime/phase6-a/server.json
.venv/bin/python -m redesign.pipeline.run_llm run --directory redesign/build/pilot/llm/phase6-a --max-slots 3
.venv/bin/python -m redesign.pipeline.run_llm verify --directory redesign/build/pilot/llm/phase6-a
```

Existing directories are never overwritten. On the implemented workspace, use `verify` to inspect existing artifacts. In Phase 7, omit `--max-slots` to continue all remaining slots only while the frozen runtime and methods remain valid. `verify` is offline. Inference supports only the pilot; final prediction support requires the later campaign freeze.
