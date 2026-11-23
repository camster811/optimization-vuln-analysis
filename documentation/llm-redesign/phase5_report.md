# Phase 5 — Controls and scoring

Completed November 22, 2026. Phase 5 implements the unconditional safe control
and four-method evaluation before live inference. All acceptance checks use
hand-counted fixtures or explicitly fabricated predictions. The real 1,440-slot
packet remains pending; no study answer or tokenizer query was generated.

## Implementation and reuse

One new production module,
[`scoring.py`](../../src/optimization_vuln_analysis/studies/representation/scoring.py), holds
the pure control, event construction, paired family resampling and scoring
adapter. Separate control, bootstrap and reporting modules were unnecessary.
The retained [`metrics.py`](../../src/optimization_vuln_analysis/common/metrics.py) supplies weighted
statistics, safe division and finite-replicate linear percentile intervals
without changes. The existing runner replays saved decoding and voting before
the file adapter accepts its aggregates; no predictor is called by scoring.

`always_not_vulnerable()` takes no arguments and returns only a classified
`not_vulnerable` decision. It reads no code, labels or eligibility, and creates
no repetitions or confidence. It stays available for blocked observations.

`evaluate(observations, aggregates, *, eligibility, input_hashes,
parent_diagnostics=None, replicates=10000)` is the pure evaluation interface.
It requires all three explicit condition dispositions for every planned
observation, including unavailable outcomes from preparation failures. It
rejects duplicates, unknown conditions, pending aggregates, missing hashes,
inconsistent decisions, duplicate treatment cells and available predictions for
blocked observations. Its caller supplies validated aggregates; this function
does not turn absent predictions into invented failures or votes.

`score_execution(inputs, projection, execution, ...)` is the file adapter. It
verifies the Phase 1 private truth release, Phase 2 projections and complete
Phase 4 execution, joins their manifest/condition/view/policy identities, then
evaluates replayed aggregates. It refuses incomplete execution and checks the
bound policy's adjudicated/control expectations. Its result records input,
projection, execution and evaluation-ledger hashes, run ID and engineering/final
purpose. Verification performs no server calls or file writes. The CLI exposes
these paths and optional expected manifest hashes:

```sh
.venv/bin/python -m redesign.extensions.representation_study.scoring --help
```

## Outcomes and uncertainty

Every planned observation contributes P; unresolved binary truth contributes
no A. On adjudicated observations, every method satisfies `A = C + E + U + M`.
The output includes all integer counts and correct/A, coverage, selective
accuracy, abstention, unavailability and truth availability. Wrong-CWE alerts
can be exact errors and alert true positives. Explicit safe, abstained and
unavailable no-alert counts remain separate. Alert TP/TN/FP/FN, recall, FPR,
precision, F1 and balanced accuracy reuse the retained arithmetic. Undefined
rates and interval bounds serialize as JSON null.

PCG64 seed 20261019 creates 10,000 rows of family multiplicities by drawing from
the lexicographically sorted family inventory with replacement. The final
inventory has ten draws per row. Every observation in one family receives the
same multiplicity. One draw matrix supplies all methods, subsets, collision
sensitivities, leave-one-family-out tables and both matched contrast sides.
Subsets never redraw a smaller family universe. Observed estimates use unit
weights; intervals exclude the observed estimate and use finite replicate
values only, with linear 2.5/97.5 percentiles and defined-replicate counts.
The matrix's little-endian int64 SHA-256 records its exact identity.

The ordered contrast list starts with combined minus decompilation correct/A,
then combined minus assembly, decompilation minus assembly and each condition
minus the control. Estimates are fractions; percentage-point display requires
multiplication by 100. Source-label recovery is a separately named endpoint.

The evaluator also emits:

- Full-denominator and secondary common-input-eligible tables, binary-class,
  source-CWE, optimization, symbol and family tables.
- Matched O1/O2/O3 minus O0 by family/variant/symbols, and stripped minus retained
  by family/variant/optimization. Both sides require adjudicated binary truth
  and are scored against their own labels. Failures stay in the pairs; missing
  partners and unresolved sides are listed explicitly. Label, operation,
  input-eligibility and prediction-availability transitions accompany the pairs.
- Source-to-binary label transitions and operation-survival counts.
- Exact canonical-view equality groups within each representation, conflicting
  binary/source labels and secondary analyses excluding every member of any
  conflicting group. Each sensitivity uses the same retained observations for
  all methods. Parent exact-bundle groups and optional supplied historical
  scope diagnostics remain separate.
- Leave-one-family-out sensitivity and the frozen qualitative selection rule:
  first observation ID in each combined-correct/standalone-not-correct group
  and its reverse, retaining errors, abstention and unavailability as not correct.

## Acceptance evidence

The complete offline suite passes: **397 tests in 264.19 seconds**. This
preserves the 369 previous checks and adds 28 scoring checks. `git diff --check`
also passes; no shared production helper needed modification.

[`test_representation_scoring.py`](../../tests/test_representation_scoring.py)
adds 28 checks. Hand-counted fixtures cover unresolved truth, wrong CWE,
abstention, failed inputs/predictions, unconditional control availability,
alignment and empty denominators. All 125 three-vote patterns pass through
retained aggregation into the event partition. An independent PCG64 loop checks
10,000-draw contrast intervals; unbalanced family fixtures check shared cluster
weights and defined-replicate counts for subsets and matched pairs. Other cases
cover treatment matching, omissions, conflicting inputs, LOFO, example ordering
and prediction-order/private-label independence.

A complete 288-slot synthetic execution exercises the actual file adapter with
network, tokenizer and runtime calls disabled during scoring. The execution
bytes stay unchanged. A mismatched input binding and a pending real execution
are rejected before evaluation.

The offline engineering packet is
`redesign/build/extensions/representation-study/phase5-offline-v1`. It contains
29 hash-bound files excluding its manifest, including 19 source dependencies,
their snapshots, synthetic fixtures/evaluation, extracted parent input audit and
the engineering check script. It preserves only input diagnostics from the
hash-bound historical evaluation; historical predictions and scores are not
scorer inputs.

| Evidence | SHA-256 |
|---|---|
| `phase5-offline-v1/manifest.json` | `1aabce85136d32cb7eb0cfdc4e661ba63aec6661a3e845024a4190467c7f3218` |
| `phase5-offline-v1/checks.json` | `dc6a1d9ff303af8fad112978e1e7addb7fec3c3d7d9ea8d35269deffcc9c0156` |
| Synthetic evaluation bytes | `a4d319f7ad532757413ac4ba2caca67dcf912083aa7ff2f0a15b85f0d9c72686` |
| Shared family multiplicities | `4e9ea9fd8b596009e8f805711064431999efc91080b5428520dccd09054843ff` |
| `phase5-restore-v1.json` | `11f13e0e5f3ee8136b3ae7d4315618eb2406468efa26f53e3f0edeed3d96e4db` |

Independent recounting on the full bound inventory verifies A=160 for all four
methods and control correctness **100/160 = 62.5%**, including the fabricated
blocked observation. Each optimization contrast has 40 matched cells; the
symbol contrast has 80. Each representation has 24 exact-input equality groups,
two with conflicting source labels and none with conflicting binary labels;
the secondary sensitivity excludes eight observations. These input diagnostics
and the control check do not supply real LLM predictions.

Reversing the observation and prediction order reproduces evaluation bytes.
A separate restore check copies the saved source dependencies and synthetic
inputs into a fresh directory, clears PYTHONPATH, disables HTTP requests and
reproduces the evaluation bytes with the pinned environment. Its receipt is
`redesign/build/extensions/representation-study/phase5-restore-v1.json`.

## Remaining boundary

The scorer's offline gate is complete. The 18-slot live engineering pilot,
actual final token preflight, final scorer/method freeze, final execution,
saved-result analysis, publication tables/figures and complete release remain
Phases 6–10. Synthetic outcomes are excluded from study results. The Phase 0
contract/policy and earlier immutable artifacts retain their existing bytes.
