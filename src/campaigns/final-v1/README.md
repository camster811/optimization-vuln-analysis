# Final Juliet campaign v1

Phase 9 tooling is ready; final execution/results are pending. Use the [runbook](../../../documentation/juliet-redesign/phase9_runbook.md) for baseline execution, scheduled LLM inference, safe resumption, analysis regeneration, and results handoff. Outputs are stored separately from the frozen release.

This is the isolated Phase 8 final-input workspace. The original `redesign/corpus/manifest.json` and Phase 7 method lock remain historical pilot evidence. This campaign's manifest assigns ten final families (80 references, 160 public observations, 480 scheduled LLM slots).

The [Phase 8 report](../../../documentation/juliet-redesign/phase8_report.md) explains selection, private adjudication, availability and limitations. `release/freeze.json` is the final-input authority; `release/final-v1-inputs.tar.gz` is its private, versioned input archive. Both must be retained together. No final predictor runs are part of Phase 8.

From the repository root:

```bash
.venv/bin/python -m redesign.pipeline.final_freeze verify
```

For archive replay, extract `release/final-v1-inputs.tar.gz` into a fresh directory preserving permissions, copy the accompanying `freeze.json` and original archive into that directory's `release/`, and run:

```bash
.venv/bin/python -m redesign.pipeline.final_freeze verify --root /path/to/restored-campaign
```

Verification uses the pinned repository methods and external toolchain/Ghidra hashes. It does not require model-server access or execute predictions. Method/specification snapshots are included under `provenance/method-snapshot/`; model weights, compiler/Ghidra installations and disposable Ghidra project caches are not vendored. Raw public exports and worker evidence are included.

`build/final/preflight/phase8-a/shared-eligibility.json` applies equally to both predictors. Only the public records under `data/final/records/`, exact opaque-ID requests under the preflight `requests/` directory, and shared eligibility are predictor inputs. The archive contains private source/debug/oracle material and is not a predictor input mount.

Keep the freeze immutable. Phase 9 outputs go in new paths and must cite its digest. The local timestamp is not an independent timestamp authority or an external preregistration. There was no independent human oracle adjudication.
