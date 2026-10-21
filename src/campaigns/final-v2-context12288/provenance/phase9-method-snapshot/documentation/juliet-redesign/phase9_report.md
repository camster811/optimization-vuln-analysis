# Phase 9: final inference, validity checks and analysis

Phase 9 is complete for `juliet-redesign-final-v2-context12288`. All 160 observations have replayable baseline results and terminal three-slot LLM aggregates. All 480 scheduled LLM slots are accounted for. Frozen inputs, methods, schedule, runtime configurations, raw responses, public-only baseline worker inputs, private oracle bindings and regenerated analysis pass verification. Phase 10 research release/manuscript work remains separate.

The [evaluation](../../redesign/campaigns/final-v2-context12288/results/final/phase9-a/evaluation.json), [observation CSV](../../redesign/campaigns/final-v2-context12288/results/final/phase9-a/observations.csv), [audit](../../redesign/campaigns/final-v2-context12288/results/final/phase9-a/closeout/validation.json), [tables](../../redesign/campaigns/final-v2-context12288/results/final/phase9-a/closeout/metrics.csv), and [figure](../../redesign/campaigns/final-v2-context12288/results/final/phase9-a/closeout/correct_rate.svg) preserve detailed results. The results archive is `redesign/campaigns/final-v2-context12288/release/phase9-results.tar.gz`, with separate content manifest `phase9-results.json`.

## Campaign and execution validity

The user increased context from 8,192 to 12,288 before final inference. The original Phase 7 lock and `final-v1` release remain unchanged. The amended campaign preserves selection, binaries, oracle, bundles, exact wire requests, model, prompt/template, sampling, seeds, repetition order, evaluator and recovery policy. Only context and shared eligibility change; the completion reserve stays 4,096. Live template/tokenization preflight reproduces the original token IDs/rendered prompts, and all 160 observations fit.

The amended input freeze is dated `2026-10-21T03:43:49.505649+00:00`, SHA-256 `740a291e1c7b413406b7ec797d33523fb47885b364168de96e29ff714046bbed`. Its input archive SHA-256 is `842f80e9ba40b15068b3548b64252fc1a01d004c6750a639e84fbb6a9fa4d041`. The execution manifest SHA-256 is `81d1e4dbd0856cd772190641a8b168d7b2c33b4c98f739fe3a3264fb3af0a613`; the campaign claim matches it and the freeze.

There are exactly 480 expected slot directories and 160 baseline jobs. Requests, budgets and public inputs match frozen identities. All baseline predictions regenerate from saved P-code; lifting/analysis output bindings agree. All 160 worker traces bind public inputs and generic policy without private/oracle arguments. LLM decoding, schema/evidence validation and majority votes regenerate, and an independent integer recount reproduces primary outcome counts.

Baseline dispatches range from `03:46:16` to `03:57:43` UTC on October 21. LLM dispatches range from `03:48:33` to `17:34:17` UTC that day, all after the freeze and in scheduled order. Two verified runtime identities account for 196 and 284 dispatches and match amended computational settings. Server restarts did not replace earlier results.

Of 480 LLM attempts, **472 are valid, six fail schema/evidence validation, and two are terminal interrupted attempts**. Four schema failures cite instructions outside the bundle and two repeat evidence addresses; the six raw responses remain saved. The interrupted slots retain durable dispatch records without saved completions and were not retried. There are no pending slots, unresolved dispatches, timeouts, length-limit failures, runtime-change failures, extraction failures or context failures. All 160 baseline jobs complete without runtime failures. All LLM aggregates have valid votes: 153 have a label majority and seven abstain for no agreement. Eight failed attempts therefore do not imply eight unavailable observations.

Recorded LLM elapsed time totals 7,667.77 seconds (2.13 hours), excluding interrupted-request time and inter-session idle time. Completed responses record 1,749,415 prompt tokens and 429,878 completion tokens; interrupted usage is unknown. Baseline worker time totals 658.46 seconds (10.97 minutes). These are recorded work totals, not continuous wall-clock time or energy estimates.

## Primary endpoints

All observations have adjudicated binary truth: A = 160. Correct, incorrect, abstention and unavailable outcomes partition that denominator. Intervals use the frozen 10,000 PCG64 draws of ten source-family clusters, seed 20261019, with shared multiplicities. They are exploratory with ten families; repetitions and treatment cells are not independent source samples.

| Method | Correct | Incorrect | Abstain | Unavailable | Correct / 160 | Coverage | Selective accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|
| Baseline | 18 | 0 | 142 | 0 | 11.25% | 11.25% | 100% (18/18) |
| LLM | 125 | 28 | 7 | 0 | 78.125% | 95.625% | 81.70% (125/153) |

The baseline correct-rate interval is [0%, 26.25%]; the LLM interval is [70%, 86.875%]. The paired LLM-minus-baseline difference is **66.875 percentage points**, interval [54.375, 78.75]. Baseline selective accuracy covers only 18 classifications, all adjudicated safe, from two source families. Its selective-accuracy interval is defined in 8,947/10,000 draws; other draws have no classifications. This is low coverage, not reliable vulnerability detection. The common-input subset equals the full matrix.

Secondary baseline alert TP/TN/FP/FN counts are 0/100/0/60; its 60 false negatives are abstentions. The LLM has 39/93/7/21, recall 65%, false-positive rate 7%, precision 84.78%, F1 73.58%, and balanced accuracy 79%. Two correct vulnerable alerts predict the wrong CWE and remain exact-label errors. Of 21 LLM missed vulnerable cells, 19 are explicit safe decisions and two are abstentions. Abstention never establishes safety.

## Treatments, dispositions and support

| Level | Planned / adjudicated | Binary CWE-121 / CWE-122 / safe | Present / inlined or merged / eliminated | Baseline C/E/U/M | LLM C/E/U/M |
|---|---:|---|---|---|---|
| O0 | 40 / 40 | 10 / 8 / 22 | 36 / 4 / 0 | 0 / 0 / 40 / 0 | 29 / 6 / 5 / 0 |
| O1 | 40 / 40 | 6 / 8 / 26 | 12 / 16 / 12 | 6 / 0 / 34 / 0 | 33 / 5 / 2 / 0 |
| O2 | 40 / 40 | 6 / 8 / 26 | 8 / 18 / 14 | 6 / 0 / 34 / 0 | 32 / 8 / 0 / 0 |
| O3 | 40 / 40 | 6 / 8 / 26 | 4 / 22 / 14 | 6 / 0 / 34 / 0 | 31 / 9 / 0 / 0 |

Each optimization/CWE stratum has 20 observations, with source labels split 10 vulnerable and 10 safe. Unresolved truth, build, extraction and context failures are zero throughout. `closeout/dispositions.csv` includes all eight strata, class balance, operation states and method partitions. Totals are 28 stack-vulnerable, 32 heap-vulnerable and 100 safe emitted observations; operations are present in 60, inlined/merged in 60 and eliminated in 40. Symbol partners share reference judgments.

Each optimized-minus-O0 comparison has 40 matched cells across ten families, no omissions, and four transitions from vulnerable stack binaries to safe binaries. LLM correct-rate changes are +10 points [−17.5, 35] at O1, +7.5 [−22.5, 40] at O2, and +5 [−25, 37.5] at O3. Baseline changes are +15 [0, 35] at every optimized level, from additional safe classifications. These data do not show monotonic LLM degradation with optimization. Binary truth, operation survival and abstention change alongside accuracy; no particular compiler pass's causal effect is identified.

Retained-symbol LLM C/E/U/M counts are 63/12/5/0; stripped counts are 62/16/2/0. Across 80 matched pairs, stripped-minus-retained correct rate is −1.25 points [−7.5, 5]. At O0/O1/O2/O3 it is −5 [−25, 15], +5 [0, 15], 0 [0, 0], and −5 [−15, 0], each with 20 matched pairs. Baseline counts are 9/0/71/0 in each symbol condition. Meaningful developer names are removed in all 80 pairs. The modest pooled difference does not establish that symbols never matter.

By source CWE provenance, baseline C/E/U/M counts are 6/0/74/0 for stack and 12/0/68/0 for heap; LLM counts are 57/20/3/0 and 68/8/4/0. For actually vulnerable binary classes, the LLM is exactly correct on 14/28 stack and 23/32 heap cells. It correctly labels all 40 eliminated-operation cells. All 18 baseline classifications occur on eliminated-operation cells. Leading baseline abstention reasons are unaccounted native writes (50), unsupported library calls (42), missing recovered stack-array extents (24) and cyclic flow (18); reason counts can overlap.

## Sensitivity and confidence

Source-label recovery remains separate: baseline 12/160 correct (7.5%), LLM 105/160 (65.625%). Source classes are 40 CWE-121, 40 CWE-122 and 80 safe, unlike binary truth. This endpoint is not binary vulnerability accuracy.

The frozen audit retains 24 exact-bundle equality groups and 66 code/data-scope groups. Two exact groups and one scope group conflict in source labels, none in binary truth. Excluding all members removes eight cells in either sensitivity: baseline correct rate becomes 10/152 (6.58%) and LLM 117/152 (76.97%). These conditional scores do not replace primary results. Every leave-one-family-out method difference stays positive, ranging from 63.89 to 71.53 points. Detailed per-family counts and intervals remain in the evaluation/metrics CSV.

The LLM recovers both original source-variant labels in 28/80 pairs; baseline 0/80. Only 60 pairs retain different binary labels, so source discrimination cannot uniformly be interpreted as binary discrimination. All LLM aggregate median confidences are at least 0.8, including all 28 exact-label errors; overall median is 0.9. Confidence is self-reported and not calibrated probability.

## Qualitative examples

These post-result examples cite saved oracle reviews and original model outputs. They are explanatory, not additional confirmatory tests.

* `re76bbb04c883b6eadfa3192b`, stack concatenation, vulnerable-source O2 retained: all three LLM votes say safe by comparing writes with the full 184-byte frame. The private emitted-code review identifies a 50-byte destination and a 16-byte store at `0x40121c` beginning at destination offset 48, crossing the object boundary. The baseline abstains for unaccounted native writes. This is an observed object-bound error in the model explanations, not evidence about a particular GCC pass.
* `ra4feb6f453d083924fa7fdff`, stack wide-character memmove, O2 retained: destination copying is eliminated and the binary is safe despite vulnerable source provenance. The aggregate is correctly safe by two votes to one. The dissenting vote confuses element counts, byte counts and stack space. A correct majority label does not validate all explanations.
* `refff22fb9dda398913e452c8`, heap `sizeof(int64_t)`, O0 retained: pointer and pointee are both eight bytes on LP64, so the eight-byte store fits. All LLM votes say safe, although one explanation calls the store four bytes. Vulnerable source provenance remains distinct; the baseline abstains under a stack-recovery support limit.
* `r6be872d5b6d2ac8a38ec24ce`, heap wide-character memmove, O0 retained: the oracle establishes a 400-byte copy into a 200-byte heap allocation. One vote correctly identifies CWE-122; two identify CWE-121 by treating the stack source as the overflow destination. The majority is an exact-label error and an alert true positive. The baseline abstains on an unsupported library contract.

## Reproduction and verification-only amendment

The frozen `final_analysis --check` has a post-run comparison defect: CSV generation emits CRLF but `read_text()` normalizes it to LF. `evaluation.json` regenerates identically, then the original checker falsely rejects `observations.csv`. Executed methods, saved outputs, scoring and input identities remain unchanged. The separately versioned `phase9_closeout` verifier uses the unchanged evaluator to regenerate the same three artifacts and compares UTF-8 bytes. It also regenerates supplementary tables and standalone PNG/SVG figures byte for byte. This amendment affects artifact verification only; no corrected predictor run or mixed-method campaign is introduced.

```bash
# Offline: no model server or new predictor execution.
.venv/bin/python -m redesign.pipeline.final_run verify \
  --root redesign/campaigns/final-v2-context12288 \
  --directory redesign/campaigns/final-v2-context12288/build/final/llm-runs/phase9-a
MPLCONFIGDIR=/tmp/juliet-phase9-matplotlib \
  .venv/bin/python -m redesign.pipeline.phase9_closeout check
.venv/bin/python -m redesign.pipeline.phase9_closeout verify-package
```

Regression verification passed **148 tests, zero failures/errors/skips**: 144 integration/regression checks and four new CSV-byte, chronology, independent-denominator and archive-tamper checks. Commands and source hashes are in `provenance/phase9-tests.json`. The results package includes frozen inputs, raw attempts, runtime evidence, baseline IR/results, regenerated analysis, audit/tables/figure, and method/test/documentation snapshots. A fresh archive restoration is checked offline. Preserve `phase9-results.json` alongside its archive; the original parent release and pinned repository/toolchain remain replay dependencies. The archive contains private evidence and is not a predictor input mount.

Limits remain ten homogeneous Juliet families, one Linux x86-64 GCC configuration, private-assisted localization, a deliberately incomplete heuristic baseline, source-template/input collisions and Codex oracle review without independent human adjudication. Juliet may have appeared in model training. The context amendment followed inspection of final input sizes, before final answer inspection, and is reported as a separate configuration. Local timestamps/hashes do not provide independent preregistration or timestamp authority. These results do not establish general binary-analysis accuracy or a reliable safety proof.
