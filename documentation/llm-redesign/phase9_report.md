# Phase 9 — Paired representation analysis

Completed November 22, 2026 (America/New_York). The predeclared primary contrast,
**combined minus decompilation in exact correct/adjudicated rate**, is
**−6.25 percentage points**, with a 95% family-cluster percentile interval of
**−13.75 to +0.625 points**. Combined input did not improve observed exact
correctness in this run. The exploratory interval includes zero; it does not
establish a population-wide negative effect.

The [Phase 8 review](phase8_report.md) verifies all 1,440 terminal slots and 480
aggregates. Analysis uses the unchanged frozen predictor/decoder/voting/scorer
and private emitted-binary judgments. No answer was repaired or retried, and no
new model request was made during analysis.

## Primary results and paired effects

All 160 observations are adjudicated: 28 stack-vulnerable, 32 heap-vulnerable
and 100 without a selected stack/heap overflow under the declared assumptions.
Each method retains `A = C + E + U + M`, including the four commonly blocked
observations. The unconditional safe control stays available for those cases.

| Method | A | C | E | U | M | Exact correct/A | 95% family interval |
|---|---:|---:|---:|---:|---:|---:|---|
| assembly | 160 | 72 | 35 | 49 | 4 | 45.00% | 29.375–61.875% |
| decompilation | 160 | 124 | 28 | 4 | 4 | 77.50% | 68.125–87.500% |
| combined | 160 | 114 | 32 | 10 | 4 | 71.25% | 59.375–82.500% |
| always not vulnerable | 160 | 100 | 60 | 0 | 0 | 62.50% | 50.000–75.000% |

Coverage is 66.875%, 95.000%, 91.250% and 100% respectively; selective accuracy
is 67.290%, 81.579%, 78.082% and 62.500%. These conditional selective values do
not replace correct/A. Assembly abstains on 49 observations and recognizes no
adjudicated positive through an alert in this run.

| Ordered contrast | Effect, percentage points | 95% family interval |
|---|---:|---|
| combined − decompilation (primary) | −6.25 | −13.750 to +0.625 |
| combined − assembly | +26.25 | +8.125 to +46.250 |
| decompilation − assembly | +32.50 | +17.500 to +49.375 |
| assembly − control | −17.50 | −28.750 to −7.500 |
| decompilation − control | +15.00 | +5.000 to +25.625 |
| combined − control | +8.75 | −2.500 to +21.250 |

The analysis reuses all 10,000 PCG64 family draws, seed 20261019, with sorted
family IDs and the same multiplicities for all methods, subsets and contrast
sides. Intervals use finite replicate estimates, linear 2.5/97.5 percentiles,
and exclude the observed estimate. All six full-denominator correct-rate
contrasts have 10,000 defined replicates. Undefined quantities are JSON null or
empty CSV cells, including control precision with zero alerts.

An independent Python vote/integer/paired recount agrees with the frozen
scorer. For combined versus decompilation, both are exactly correct on 104
observations, combined alone on 10, decompilation alone on 20 and neither on 26.
Combined versus assembly has 56 combined-only and 14 assembly-only correct
cases. These comparisons retain errors, abstention and unavailability as not
correct; they do not select only mutually classified cases.

## Alerts, binary classes and source endpoint

| Method | TP | TN | FP | FN | Recall | FPR | Precision | F1 | Balanced accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| assembly | 0 | 98 | 2 | 60 | 0.00% | 2.00% | 0.00% | 0.00% | 49.00% |
| decompilation | 49 | 86 | 14 | 11 | 81.67% | 14.00% | 77.78% | 79.67% | 83.83% |
| combined | 40 | 84 | 16 | 20 | 66.67% | 16.00% | 71.43% | 68.97% | 75.33% |
| control | 0 | 100 | 0 | 60 | 0.00% | 0.00% | NA | 0.00% | 50.00% |

Three decompilation aggregates are wrong-CWE alerts on vulnerable binaries:
alert true positives and exact-label errors. Exact class-correct counts for
stack/heap/nonvulnerable truth are assembly 0/0/72, decompilation 20/26/78,
combined 15/25/74 and control 0/0/100.

No alerts due to explicit safe/abstained/unavailable outcomes are respectively
105/49/4 for assembly, 89/4/4 for decompilation, 90/10/4 for combined and
160/0/0 for the control. Abstention and unavailability do not establish safety.

Original source-label recovery is reported separately. Its C/E/U/M counts are
assembly 57/50/49/4, decompilation 104/48/4/4, combined 94/52/10/4 and control
80/80/0/0. Compilation can change the binary label, so these are not alternative
binary-vulnerability accuracy estimates.

## Compiler/symbol effects and sensitivity

The complete binary-class, source-CWE, optimization, symbol and family tables
are in `metrics.csv`. Matched optimization comparisons each contain 40 cells
and ten families; stripped-minus-retained contains 80 pairs and ten families.
Both sides have adjudicated truth and are scored against their own binary
labels. No partner is omitted. Failures and blocked predictions stay in the pairs.

| Matched contrast | Assembly | Decompilation | Combined | Control |
|---|---:|---:|---:|---:|
| O1 − O0 | +25.0 pp | +5.0 pp | +12.5 pp | +10.0 pp |
| O2 − O0 | +17.5 pp | +5.0 pp | +2.5 pp | +10.0 pp |
| O3 − O0 | +17.5 pp | 0.0 pp | 0.0 pp | +10.0 pp |
| stripped − retained | −2.5 pp | +10.0 pp | +2.5 pp | 0.0 pp |

`matched-contrasts.csv` includes paired intervals, counts and label/operation/
eligibility/availability transitions. The control's optimization gains reflect
changes in compiled truth. Raw optimization differences therefore cannot be
interpreted solely as changes in model ability. O0 also contains the four
common-blocked observations.

The secondary common-eligible analysis retains A=156: assembly C=72,
decompilation C=124, combined C=114 and control C=96. Its combined-minus-
decompilation effect is −6.410 points; it does not replace the primary A=160
analysis. Leaving out one family at a time gives primary-contrast point
estimates from −8.333 to −3.472 points, with no point-estimate sign reversal.
This deletion stability is distinct from population inference.

Each representation has 24 exact-input equality groups, two with conflicting
source labels and none with conflicting binary labels. Excluding every member
of conflicting groups removes eight observations, leaving A=152 for every
method. C becomes assembly 64, decompilation 116, combined 106 and control 92;
the primary contrast is −6.579 points. Parent exact-bundle and code/data-scope
diagnostics are retained separately from these representation groups. The parent
scope audit contains input diagnostics, not historical prediction imports.

## Usage, failures and selected explanations

| Representation | Dispatched | Prompt tokens | Completion tokens | Recorded request seconds |
|---|---:|---:|---:|---:|
| assembly | 468 | 1,392,423 | 477,184 | 8,320.168002 |
| decompilation | 468 | 1,265,112 | 438,036 | 7,622.555624 |
| combined | 468 | 2,148,474 | 474,589 | 8,784.126831 |
| Total | 1,404 | 4,806,009 | 1,389,809 | 24,726.850457 |

Known costs include the six length-limited and 16 invalid-reference responses.
There are zero missing prompt/completion usage or elapsed records among
dispatched requests. Blocked slots consume no request and are not labeled
unknown consumption. Recorded request time is a sum of saved elapsed values,
not the execution's exact wall-clock span. Every actual prompt usage count
matches frozen preflight accounting.

The qualitative rule selects the first frozen observation ID in each of four
combined-correct/standalone-not-correct groups and their reverses. It yields
three unique observations because the reverse groups share one case. All group
memberships, empty-group handling, nine attempts per case, full supplied views,
summaries/reasoning, response hashes and oracle-review hashes are retained in
`qualitative.json` and `qualitative-review.json`.

- `r02713a1218c318c3404a13f9`: combined correct, assembly abstained. Public
  instructions pass 200 to malloc and perform 50 eight-byte copies into the
  resulting destination. The bound review identifies a 400-byte heap write.
  Assembly has a safe vote, an uncertain vote and an invalid citation; combined
  has three heap-overflow votes. Some size claims in correct combined answers
  are still wrong, including calling the recovered source array 99 bytes.
- `r027574463de9c9cd88948df6`: combined correct, decompilation wrong CWE. This
  retained-symbol observation is the same build as the stripped case above.
  Two decompilation votes blame the stack source; one treats 99 wchar_t as
  198 bytes and claims 51 iterations. The visible loop has count 0x32 and writes
  through the malloc-derived destination. Two combined votes choose CWE-122;
  the third repeats a stack-region error.
- `r10693886f4b3634a9e75cd55`: both standalone methods correct, combined
  abstained. The O3 safe binary has the selected indexed write eliminated and
  retains a global assignment and diagnostic output. Combined has one safe
  vote, one uncertain vote about a 16-byte data window and one invalid citation.
  Some correct safe assembly answers also misidentify memory regions.

The exploratory codes are source/destination-region confusion, element/byte
units, eliminated writes and unsupported reasoning. They describe reviewed
claims, not verified internal mechanisms or exhaustive corpus-wide error rates.
The view/response references supporting each note are validated. Confidence is
descriptive, does not affect voting, and is not a calibrated probability.

## Implementation, artifacts and reproduction

One new production module,
[`reporting.py`](../../src/optimization_vuln_analysis/studies/representation/reporting.py),
wraps the unchanged frozen scorer. It adds independent recounts, per-slot cost
and failure accounting, CSV export, deterministic scientific figures and
predeclared-case review validation. The Phase 7 source/environment guard still
passes; no frozen predictor, decoder, voting or metric component was modified.

The accepted output is:

```text
redesign/experiments/llm-representation-v1/representation-v1-context12288-final-v1-analysis-v2/
```

It has 57 bound files plus its manifest, including a 22-file imported source
closure and required resources. Key outputs are:

| Output | Contents |
|---|---|
| `evaluation.json`, `audit.json` | Frozen estimates/intervals, independent vote/integer/paired recount |
| `observation-condition.csv`, `control.csv` | 480 LLM-condition rows and 160 unconditional control rows |
| `attempts.csv`, `failed-slots.csv` | All 1,440 dispositions and 22 failed-response diagnostics/provenance |
| `metrics.csv`, `contrasts.csv` | 148 method/subset rows and 222 contrast/subset rows; one primary full-denominator contrast |
| `agreement.csv`, `disagreements.csv` | Six paired summaries and 96 observation-level representation disagreements |
| `matched-contrasts.csv`, `matched-pairs.csv` | 16 method/treatment estimates and 200 matched observation pairs |
| `stability.csv`, `collisions.json`, `transitions.json` | LOFO/collision sensitivity, input equality and operation/label transitions |
| `compute.csv` | Three conditions plus total; failed consumption and missing-record counts |
| `qualitative.json`, `qualitative-review.json` | Deterministic selection, saved answers/views and explicitly exploratory notes |
| `figures/{outcomes,contrasts,treatments}.{png,svg}` | Standalone scientific figures |
| `execution-files.json`, `phase8-check.json` | All 6,199 execution hashes and complete replayed state |

CSV rates are fractions, figure/report rates are percentages or percentage
points, and CSV line endings are fixed LF. The source/input bindings and parent
audit are included. Artifacts contain private judgments and saved model outputs
and are marked internal.

The full suite passed **443 tests in 480.36 seconds**. After visual review, v2
adjusted figure export bounds to retain a clipped legend; all nine reporting
tests then passed in 67.25 seconds. All 22 nonfigure analysis/evidence artifacts
are byte-identical between v1 and v2, including evaluation and selected cases.
The first export is preserved. The new tests cover frozen-score reuse, independent
recounts, failed-slot consumption/gaps, control availability, CSV fidelity,
deterministic replay, corruption and predeclared case/contrast selection.

A fresh-directory restore of the saved source, initial freeze, final execution
and analysis regenerated **all 28 JSON/CSV/PNG/SVG analysis/evidence outputs
byte for byte**. HTTP/runtime/tokenizer calls were disabled, no original project
source/data fallback was used, and evidence bytes stayed unchanged. The existing
pinned Python/package environment was reused. No inference or lifting is needed.

| Evidence | SHA-256 |
|---|---|
| Analysis v2 `manifest.json` | `e713248edf7e01ab2c493e348cb4afa427940672e39b627c4e23c2a56b173c37` |
| `evaluation.json` | `08ad9f8f88b8a6682f49cdfd172572be1a54276d49ccb5167555e2a270b57f24` |
| `audit.json` | `bbde354d9c7212e0ee45145a285041d950599ce4d049146f32e815072b430b55` |
| Build `phase9-checks-v1.json` | `e92ef53fbcb81c7a7e4d87b640cc73d1f2b52ae14384928d3c917ffab5d530e3` |
| Build `phase9-tests-v1.json` | `74625d17cd6113098e9a17af1a513387a42fceb215a0c9ca4af6c5c2a083ddcd` |

Run the read-only byte-reproduction check with:

```sh
.venv/bin/python -m redesign.extensions.representation_study.reporting verify \
  --freeze redesign/experiments/llm-representation-v1/representation-v1-context12288-final-v1 \
  --execution redesign/build/extensions/representation-study/phase7-final-v1 \
  --directory redesign/experiments/llm-representation-v1/representation-v1-context12288-final-v1-analysis-v2 \
  --manifest-sha256 e713248edf7e01ab2c493e348cb4afa427940672e39b627c4e23c2a56b173c37
```

Phase 9 passes its gate. Interpretation remains exploratory on ten previously
inspected Juliet-derived families, one model/runtime configuration and supplied
localization/context, with Codex-reviewed truth rather than independent human
adjudication. The work does not establish whole-program discovery, static-tool
superiority or absence from model pretraining. Complete final release packaging,
its archive verification and manuscript/claim rewrite remain Phase 10.
