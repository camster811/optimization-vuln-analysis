# Final campaign v2: context 12,288

Phase 9 is complete. All 480 LLM slots are terminal (472 valid, six schema failures, two interruptions), and all 160 baseline results regenerate from saved IR. LLM C/E/U/M = 125/28/7/0; baseline = 18/0/142/0. See the [final report](../../../documentation/juliet-redesign/phase9_report.md). The results archive/manifest are `release/phase9-results.tar.gz` and `release/phase9-results.json`; preserve both. All inputs, raw attempts, runtime evidence, IR, evaluation, tables and figures are bound by that results manifest.

Offline verification uses `.venv/bin/python -m redesign.pipeline.phase9_closeout check` (set `MPLCONFIGDIR=/tmp/juliet-phase9-matplotlib` if needed) and `.venv/bin/python -m redesign.pipeline.phase9_closeout verify-package`. The supplementary verifier preserves CSV bytes to avoid the original checker's universal-newline comparison defect. Frozen predictor/evaluator code and results remain unchanged. Validation now totals 148 passing tests without skips. Earlier preparation notes below are historical.

This user-requested amendment changes the runtime context from 8,192 to 12,288 tokens, retaining 4,096 completion tokens and all other predictor/input/scoring settings. The original `final-v1` campaign and Phase 7 lock remain preserved. `provenance/context-amendment.json` records the parent release and rationale.

The verified server starts with full GPU offload and flash attention. Live template/token preflight of all 480 exact frozen requests reproduces the parent rendered prompts and token IDs. **All 160 observations and all 480 repetition slots are available**. No final baseline or LLM predictions ran during this amendment. The largest recorded prompt plus reservation is 11,710 tokens.

`release/freeze.json` and `release/final-v2-context12288-inputs.tar.gz` bind the amended inputs and runtime evidence. Verify with:

```bash
.venv/bin/python -m redesign.pipeline.context_campaign verify
```

The parent release is also checked. Do not use the original `final_freeze verify --root` command for this amended release; it deliberately retains the original 8,192-token authority. Execution/analysis commands accept `--root redesign/campaigns/final-v2-context12288`.

Follow the [amended runbook](../../../documentation/juliet-redesign/context12288_runbook.md) for final execution and results handoff. The original campaign's predictions, if any, must remain separate.

Validation: 65 tests pass without skips, including the original final-execution regressions and three amendment tests covering context-only policy changes, preserved runtime settings, exact request/token preservation, complete shared availability, amended execution preparation, and rejection of unrelated policy changes.
