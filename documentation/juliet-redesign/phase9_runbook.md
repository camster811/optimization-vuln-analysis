# Phase 9 execution and results handoff

The user-requested **12,288-token amendment** now uses a separate campaign. Follow the [amended runbook](context12288_runbook.md) for the active configuration. The commands below preserve the original 8,192-token campaign.

Phase 9 execution and analysis are implemented in `redesign.pipeline.final_run` and `redesign.pipeline.final_analysis`. Actual final inference and measured results remain pending. No final predictor was run during implementation. The Phase 7 methods and Phase 8 release remain unchanged.

The frozen matrix contains 160 observations and 480 repetition slots. Exactly 112 observations fit the locked context budget: 336 actual LLM requests are eligible, and 144 slots must remain `context_unavailable`. Both predictors share those 48 unavailable observations. Do not increase context, crop requests, change seeds/settings, select replacement samples, or start another execution to replace failures.

## 1. Verify and prepare offline

Run from `/home/camst/repos/optimization-vuln-analysis`:

```bash
.venv/bin/python -m redesign.pipeline.method_lock verify
.venv/bin/python -m redesign.pipeline.final_freeze verify
.venv/bin/python -m redesign.pipeline.final_run prepare \
  --directory redesign/campaigns/final-v1/build/final/llm-runs/phase9-a
```

Preparation copies the exact frozen public bundles, wire requests, and token evidence. It does not contact the model or run the baseline. The final `manifest.json` marks successful preparation. An existing destination is never overwritten. Use this same directory for every subsequent command; do not rerun `prepare` to resume.

Execution records a single manifest identity in `redesign/campaigns/final-v1/provenance/phase9-execution.json`. Both methods must use that identity. A new preparation cannot be used to rerun failed final attempts.

## 2. Run the frozen baseline

```bash
export GHIDRA_HOME=/home/camst/repos/ghidra_12.1.4_PUBLIC
.venv/bin/python -m redesign.pipeline.final_run baseline \
  --directory redesign/campaigns/final-v1/build/final/llm-runs/phase9-a
```

This uses the unchanged public-only baseline worker with the pinned Ghidra/Java environment. Shared-unavailable observations are recorded without lifting. The worker receives public bundles and generic policy; private truth/source/debug artifacts are not process arguments. Saved IR supports offline prediction regeneration. Worker failures remain failures; rerunning this command resumes only never-dispatched work.

## 3. Run the LLM

If the original Phase 6 server is still running, its captured identity is already staged by preparation. Start the complete scheduled run with:

```bash
.venv/bin/python -m redesign.pipeline.final_run run \
  --directory redesign/campaigns/final-v1/build/final/llm-runs/phase9-a
```

The runner checks ownership, model, runtime configuration, and live properties before dispatching. If the old server is unavailable, use the following runtime startup instead. First ensure port 8081 is free; do not start a second server while the original one is listening. In a separate terminal, keep this process running:

```bash
.venv/bin/python -m redesign.pipeline.llm_runtime serve \
  --directory redesign/build/final-runtime/phase9-a
```

Once `redesign/build/final-runtime/phase9-a/startup.log` reports the server listening, capture its identity from your working terminal, then run:

```bash
.venv/bin/python -m redesign.pipeline.llm_runtime capture \
  --directory redesign/build/final-runtime/phase9-a
.venv/bin/python -m redesign.pipeline.final_run run \
  --directory redesign/campaigns/final-v1/build/final/llm-runs/phase9-a \
  --server redesign/build/final-runtime/phase9-a/server.json
```

A new process must match the locked computational configuration. Its identity is appended to `runtime-sessions/`; prior evidence and attempts remain unchanged. If another restart is necessary, use a fresh runtime directory (for example `phase9-b`), capture it, and pass its `server.json` to the same execution directory.

You can use `--max-slots N` to limit **new actual dispatches** in one invocation. It preserves schedule order and records all blocked slots. It is not a retry count. There are at most 336 actual final requests; request timeout is 600 seconds, so allow a long session. No measured final duration is available yet.

To inspect progress or resume, use:

```bash
.venv/bin/python -m redesign.pipeline.final_run verify \
  --directory redesign/campaigns/final-v1/build/final/llm-runs/phase9-a
.venv/bin/python -m redesign.pipeline.final_run run \
  --directory redesign/campaigns/final-v1/build/final/llm-runs/phase9-a
```

Pass `--server` again when using a newly captured process. A durable dispatch lacking a saved completion becomes terminal `interrupted`. Timeouts, invalid/schema/length failures, and other terminal results are preserved without retry. Do not delete attempt files, the execution claim, or completed results. Correctness changes after execution require an explicit amendment and a new campaign identity.

## 4. Regenerate analysis

After both predictors finish:

```bash
.venv/bin/python -m redesign.pipeline.final_analysis \
  --directory redesign/campaigns/final-v1/build/final/llm-runs/phase9-a \
  --output redesign/campaigns/final-v1/results/final/phase9-a
.venv/bin/python -m redesign.pipeline.final_analysis \
  --directory redesign/campaigns/final-v1/build/final/llm-runs/phase9-a \
  --check redesign/campaigns/final-v1/results/final/phase9-a
```

Analysis refuses pending or unresolved dispatch slots, revalidates saved responses, and regenerates completed baseline predictions from IR. It produces `evaluation.json`, `observations.csv`, and `report.md`. `--check` compares all three byte for byte without overwriting them. Keep analysis outputs outside the attempt directory.

The JSON retains all planned cells, exact-label counts and denominators, common-input and source-label analyses, 10,000 shared PCG64 family-cluster bootstrap draws, paired optimization contrasts, symbol contrasts within each level, per-family and leave-one-family-out results, collision sensitivities, source-variant discrimination, confidence/error summaries, and compute/failure accounting. Optimization/CWE disposition tables include operation states, source/binary class balance, extraction/context failures, and method counts. Intervals are exploratory with ten source families. Source labels and private binary truth remain separate. Private localization and lack of independent human adjudication remain limitations.

## 5. Attach the saved results

Create one archive from the repository root:

```bash
tar -czf /tmp/juliet-phase9-results.tar.gz \
  -C redesign/campaigns/final-v1 \
  provenance/phase9-execution.json \
  build/final/llm-runs/phase9-a \
  results/final/phase9-a
```

Attach `/tmp/juliet-phase9-results.tar.gz` here. It contains the saved raw attempts, dispatch records, public inputs, baseline IR/results, runtime evidence, manifest, and regenerated tables needed for review. If execution stops before analysis, archive the execution claim and run directory only and attach that partial archive; preserve all files for recovery. Keep the original frozen input release alongside the campaign.
