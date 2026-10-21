# Baseline strengthening v1: checkpoints A and B complete

This is a separately versioned post-hoc supplement to the completed `final-v2-context12288` / `phase9-a` campaign. Its original methods, inputs, predictions, analysis, reports and archives remain unchanged. Checkpoint A implements the four deterministic constant controls without new inference/lifting. Checkpoint B adds the bounded five-contract v3 revision, 176 independent compiled observations, and a complete 160-observation relift/evaluation with two same-IR ablations. Neither track makes new LLM requests.

## Checkpoint B: completed negative result

V3 has **18 correct, zero incorrect, 142 abstained and zero unavailable** outcomes, identical to v2 on every cell. Both same-IR ablations also match those decisions. The five contracts pass independent support tests but do not improve final-corpus coverage or vulnerability detection; native-write, stack-recovery, termination and control-flow limits remain. Stop expansion at the declared five effects and preserve this negative result rather than promoting v3 as a stronger comparator.

See the [full closeout note](../../../documentation/juliet-redesign/baseline_strengthening_checkpoint_b.md), [comparison report](checkpoint-b-v3/analysis/report.md), [complexity decision](checkpoint-b-v3/analysis/decision.md), [JSON](checkpoint-b-v3/analysis/comparison.json), [CSV](checkpoint-b-v3/analysis/comparison.csv), and [independent audit](checkpoint-b-v3/analysis/independent-audit.json). All 160 new workers complete and replay without runtime failures; 56 IR digests differ from v2 despite identical classifications. The semantic/regression gate passes 106 tests. The 176-cell compiled matrix includes a repeat that reproduces identical IR/predictions and no incorrect supported fixture classifications. Historical methods and Checkpoint A still verify unchanged.

The [v3 archive](checkpoint-b-v3/checkpoint-b.tar.gz) and [detached release manifest](checkpoint-b-v3/release.json) bind 6,006 files including public inputs, new IR/results/ablations, fixture evidence and source/test/specification snapshots. Preserve both. [Fresh archive replay evidence](checkpoint-b-v3-replay.json) records verification without new lifting or a model server. V3 workflow and replay commands are in the [implementation README](../../extensions/baseline_study/baseline_v3/README.md).

```bash
MPLCONFIGDIR=/tmp/juliet-baseline-study-matplotlib \
  .venv/bin/python -m redesign.extensions.baseline_study.baseline_v3.release verify
```

## Checkpoint A: preserved controls and claims

The [report](checkpoint-a-v1/report.md) leads with the constant no-overflow control: **100/160 correct (62.5%), zero vulnerability recall**. The saved LLM scores 125/160 (78.125%), a gain of **15.625 percentage points**, with exploratory shared-family interval **[5.625, 26.250] points**. The constant CWE-121/CWE-122 controls have 28/32 correct cells; always uncertain abstains on all 160. The original bounded heuristic retains 18 correct classifications and 142 abstentions.

Deliverables:

- [Claims and proposed manuscript wording](checkpoint-a-v1/claims.md), limiting the comparison to these configurations and ten Juliet-derived families.
- [Comparison JSON](checkpoint-a-v1/comparison.json) and [CSV](checkpoint-a-v1/comparison.csv), with binary/source endpoints, common-input results, all subgroup metrics, alert/no-alert counts, and paired LLM-minus-control intervals.
- [Control predictions](checkpoint-a-v1/controls/predictions.json) and separate [eligibility-only inputs](checkpoint-a-v1/control-inputs/eligibility.json); controls have no instruction evidence, confidence or voting records.
- [Study manifest](checkpoint-a-v1/study-manifest.json), [acceptance counts](checkpoint-a-v1/acceptance.json), source/plan/test snapshots, and original artifact hash references.
- [Archive](checkpoint-a-v1/checkpoint-a.tar.gz) and accompanying [release manifest](checkpoint-a-v1/release.json); both must be preserved. Private historical evaluation data are included for scoring, separately from control inputs.
- [Fresh restore verification](checkpoint-a-v1-replay.json), proving byte-identical regeneration and unchanged original hashes without model-server access.

All **31 tests pass**, including 16 checkpoint A tests, 11 frozen-evaluator checks and four original closeout checks. Tests cover private-label independence, exact CWE versus alert scoring, unknown truth, shared missingness, abstention/NA denominators, shared two-family resampling, historical metric/interval equality, publication overwrite guards and archive tampering. The full accepted-campaign fixture regenerates outputs twice and verifies all declared integer partitions.

```bash
MPLCONFIGDIR=/tmp/juliet-baseline-study-matplotlib \
  .venv/bin/python -m redesign.extensions.baseline_study.study verify \
  --run-id checkpoint-a-v1
```

See the [implementation README](../../extensions/baseline_study/README.md) for creation and restore commands. Existing run IDs/publications are never replaced. Keep subsequent analyzer revisions separate from this accepted supplement.
