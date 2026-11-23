# Repository cleanup before implementation

November 21, 2026. The representation extension and new inference run have not
started. This cleanup follows the request to remove unused active code and favor
the smallest necessary extension. It builds on the existing move from `src/` to
`redesign/` without restoring deleted files or changing frozen methods.

The active static predictor, its v3 extension, lifting/interpreter code, policies,
schemas and dedicated tests were removed. The retired build/extraction workflows,
two-method evaluator, campaign preparation/freezing/execution/reporting and their
tests were also removed. In total, 76 source, configuration, schema and documentation
files were deleted, along with obsolete bytecode caches. The original backup
`optimization-vuln-analysis_old.7z` was left untouched.

Root transport, launch and runtime modules now contain only explicit-argument
helpers. Method-independent arithmetic was extracted unchanged into
`redesign/pipeline/metrics.py`. The metadata scanner retains the check used by
bundle validation; the unused source-rewriting implementation was removed.
Active documentation no longer points to retired commands or study supplements.

## Retained interfaces and checks

| Retained code | Regression evidence |
|---|---|
| `inventory.py` | Declared pilot/final matrices, stable identities, missing/duplicate/altered cells, source hashes, strict JSON and path containment |
| `bundles.py`, `sanitize.py`, bundle schema | All 32 accepted pilot bundles, canonical bytes, function closure, evidence visibility, nested private fields, known metadata leaks and explicit availability |
| `llm.py` | Stateless payloads, strict response decoding, malformed envelopes, finish reasons, transport failure and two-of-three voting including failed/uncertain votes |
| `llm_runtime.py`, pilot `run_llm.py` | Exact token-budget boundary, immutable publication, dispatch interruption without retry, corrupt results and changed prompt/runtime rejection |
| Root transport/launch/identity helpers | Exact UTF-8 wire bytes, one request, disabled proxy inheritance/redirects, timeout propagation, usage gaps, launch arguments, model hashing, process/source/template identities |
| `metrics.py` | Hand-counted weighted C/E/U/M and alert metrics, wrong-CWE alerts, failures in denominators, zero denominators and finite-replicate linear percentiles |

The bundle adapter and pilot runner retain their existing contracts. Their settings,
address evidence and slot identity require local adaptation for the representation
study; this cleanup does not claim that they implement that protocol. Add only
the needed adapters and orchestration, with regression checks for reused behavior.

The versioned pilot inputs are no longer hidden by the root `data/` ignore rule.
The study documentation is also visible to Git. Materialized campaigns and build
outputs remain ignored, as in the existing workspace configuration.

## Preserved evidence

The source/provenance inputs, accepted public bundles, private judgments, method
locks, historical results and frozen campaign snapshots were preserved. Archived
methods and their original references remain inside historical evidence; they
are not active dependencies of the new study.

Before/after SHA-256 checks found all **18,783** existing evidence files unchanged
across `redesign/campaigns/`, `provenance/`, `data/`, `corpus/` and `results/`.
The parent campaign's detached manifests also verified independently:

| Parent release | Manifest files checked | Archive SHA-256 |
|---|---:|---|
| Input freeze | 4,111 | `842f80e9ba40b15068b3548b64252fc1a01d004c6750a639e84fbb6a9fa4d041` |
| Saved results | 11,511 | `a7832a1c7c4d55e308fa659abff109df42b350dc3ce34af92bb5ecf16665577a` |

These checks establish preservation and manifest agreement, not a new inference
run or a fresh reproduction of the historical analysis.

## Validation

`.venv/bin/python -m pytest -q`: **100 passed**, without a model, GPU, compiler,
Ghidra or inference server. The transport and runtime tests use temporary local
fixtures. Active imports and documentation were checked for references to removed
modules. `git diff --check` passes.

The next work is the study design and smallest representation-specific extension,
following the implementation plan's offline gates before any live requests.
