# Baseline strengthening, checkpoint A

**The constant no-overflow control scores 100/160 (62.5%) while detecting zero vulnerable binaries.**

This post-hoc supplement preserves the original Phase 9 results. The controls are four declared constant labels, with the same shared eligibility and no code inspection, instruction evidence, confidence or voting records. The no-overflow control leads the report without selecting a favorable constant from the final labels.

All 160 cells have adjudicated binary truth. C/E/U/M are correct/incorrect/abstained/unavailable; every metric keeps the frozen denominators and NA rules.

| Method | C | E | U | M | Correct / A | Coverage | Selective accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|
| Constant no overflow | 100 | 60 | 0 | 0 | 62.500% | 100.000% | 62.500% |
| Saved LLM aggregate | 125 | 28 | 7 | 0 | 78.125% | 95.625% | 81.699% |
| Saved v2 baseline | 18 | 0 | 142 | 0 | 11.250% | 11.250% | 100.000% |
| Constant CWE-121 | 28 | 132 | 0 | 0 | 17.500% | 100.000% | 17.500% |
| Constant CWE-122 | 32 | 128 | 0 | 0 | 20.000% | 100.000% | 20.000% |
| Always uncertain | 0 | 0 | 160 | 0 | 0.000% | 0.000% | NA |

The saved LLM exceeds no-overflow by 15.625 percentage points; the exploratory shared-family interval is [5.625, 26.250] percentage points. Intervals use 10,000 PCG64 family draws with seed 20261019 and shared multiplicities across all six methods, subgroups and both truth endpoints. Treatment cells and LLM repetitions are not independently resampled.

## Alert tradeoffs

| Method | TP | TN | FP | FN | Recall | FPR | Precision | F1 | Balanced accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Constant no overflow | 0 | 100 | 0 | 60 | 0.000% | 0.000% | NA | 0.000% | 50.000% |
| Saved LLM aggregate | 39 | 93 | 7 | 21 | 65.000% | 7.000% | 84.783% | 73.585% | 79.000% |
| Saved v2 baseline | 0 | 100 | 0 | 60 | 0.000% | 0.000% | NA | 0.000% | 50.000% |
| Constant CWE-121 | 60 | 0 | 100 | 0 | 100.000% | 100.000% | 37.500% | 54.545% | 50.000% |
| Constant CWE-122 | 60 | 0 | 100 | 0 | 100.000% | 100.000% | 37.500% | 54.545% | 50.000% |
| Always uncertain | 0 | 100 | 0 | 60 | 0.000% | 0.000% | NA | 0.000% | 50.000% |

No alert from abstention or unavailability is not a safety classification. Wrong-CWE alerts can be true positives while remaining exact-label errors. Zero-denominator precision and selective accuracy are NA.

## Descriptive treatment patterns

| Treatment | LLM correct / A | No-overflow correct / A | Original baseline correct / A | LLM minus no-overflow (points) | Family interval |
|---|---:|---:|---:|---:|---|
| O0 | 72.500% | 55.000% | 0.000% | 17.500 percentage points | [-2.500, 37.500] percentage points |
| O1 | 82.500% | 65.000% | 15.000% | 17.500 percentage points | [5.000, 32.500] percentage points |
| O2 | 80.000% | 65.000% | 15.000% | 15.000 percentage points | [0.000, 30.000] percentage points |
| O3 | 77.500% | 65.000% | 15.000% | 12.500 percentage points | [0.000, 25.000] percentage points |
| retained | 78.750% | 62.500% | 11.250% | 16.250 percentage points | [7.500, 26.250] percentage points |
| stripped | 77.500% | 62.500% | 11.250% | 15.000 percentage points | [3.750, 27.500] percentage points |
| CWE-121 | 71.250% | 65.000% | 7.500% | 6.250 percentage points | [-6.250, 15.625] percentage points |
| CWE-122 | 85.000% | 60.000% | 15.000% | 25.000 percentage points | [9.375, 43.750] percentage points |

## Source-label recovery (separate endpoint)

| Method | C | E | U | M | Correct / A | Coverage | Selective accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|
| Constant no overflow | 80 | 80 | 0 | 0 | 50.000% | 100.000% | 50.000% |
| Saved LLM aggregate | 105 | 48 | 7 | 0 | 65.625% | 95.625% | 68.627% |
| Saved v2 baseline | 12 | 6 | 142 | 0 | 7.500% | 11.250% | 66.667% |
| Constant CWE-121 | 40 | 120 | 0 | 0 | 25.000% | 100.000% | 25.000% |
| Constant CWE-122 | 40 | 120 | 0 | 0 | 25.000% | 100.000% | 25.000% |
| Always uncertain | 0 | 0 | 160 | 0 | 0.000% | 0.000% | NA |

Binary truth is 100 safe / 28 CWE-121 / 32 CWE-122, whereas source provenance is 80 safe / 40 CWE-121 / 40 CWE-122. Recovery of source labels is not binary-vulnerability accuracy.

The common-input subset equals the primary matrix in this campaign. `comparison.json` and `comparison.csv` include all estimates, intervals, defined-replicate counts, integer counts, no-alert reasons, binary/source endpoints, common-input results and actual-binary-class, source-CWE, optimization, symbol and family breakdowns. Method IDs are explicit; historical estimates and intervals reproduce before controls are accepted. `claims.md` supplies the narrowed interpretation and proposed manuscript wording.

Reproduce with the separately versioned baseline-study CLI. The manifest binds source/test/plan snapshots, original input/result hashes and all supplementary files. No historical artifacts are changed, and no new LLM request or lifting occurs.
