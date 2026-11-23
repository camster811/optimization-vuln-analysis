# R2 inference primitives and protocol settings

Completed November 22, 2026, America/New_York. R2 separates reusable inference from bundle-protocol settings and decoding under the existing repository namespace. The representation study now uses `redesign/inference/` directly. The older bundle protocol and pilot runner remain available. All 58 selected critical checks passed; the full suite and campaign replay were skipped under the requested limited test scope.

## Inference boundary

[`inference/attempts.py`](../../src/optimization_vuln_analysis/inference/attempts.py) owns sampler validation, one transport attempt and three-attempt voting. `attempt(request, evidence, policy, schema, *, decoder, transport=None)` requires the caller's decoder and receives policy explicitly. Its default transport is the retained root HTTP helper; an explicit transport can be supplied without changing protocol settings. Timeout classification, raw response retention, elapsed accounting and no-retry behavior are preserved.

[`inference/runtime.py`](../../src/optimization_vuln_analysis/inference/runtime.py) owns explicit-policy runtime queries, exact template/token accounting, live identity checks, capture, launch and immutable file publication. It reuses the existing root launch/model/process helpers and common serialization/artifact primitives. Shared inference imports no corpus inventory, study adapter or legacy settings loader. Importing it does not inspect a configured model or load a policy file.

Each protocol still owns its settings, request builder, schema and response decoder. Representation answers retain typed failure details and visible line-reference validation. Bundle answers retain instruction-address validation. Voting and sampler checks are shared; neither decoder was generalized or replaced.

## Compatibility and consumers

- `redesign/pipeline/llm.py` retains bundle settings, payload construction, output validation and decoding. Its attempt adapter supplies the bundle decoder and its existing transport hook to shared inference. Voting and sampler names remain compatibility exports.
- `redesign/pipeline/llm_runtime.py` retains the original `serve`/`capture` CLI and function exports. Its settings loader imports the bundle protocol lazily when invoked. Shared runtime functions reside in the neutral package.
- Representation inventory, projection, pilot, runner, freeze and reporting import shared runtime directly. The representation adapter imports shared attempts directly.
- The retained pilot runner uses shared runtime and binds 14 source files, including both compatibility modules and all three inference files. Changing any common or inference source identity blocks dispatch.
- Existing fixtures now patch the canonical shared transport/runtime modules. Compatibility checks still exercise the older bundle API. Cross-test fixture organization remains R5 work.

The root transport, launch and process-identity modules remain below the adapters. R1 had already removed the root runtime's corpus-inventory dependency. Physical package consolidation remains R5.

The standalone release tool and R0 publications were unchanged. Their saved source continues to supply historical verification independently of the active imports.

## Focused verification

The [critical-check receipt](../../artifacts/history/redesign/build/refactor/r2-v1/critical-checks.json) records 58 passing cases, with zero failures or errors:

| Selection | Cases | Important boundary |
|---|---:|---|
| Transport, usage and launch configuration | 16 | Exact request bytes, local configuration, one request, timeout propagation, disabled proxy inheritance/redirects and unknown usage |
| Context budget, voting, source/runtime guards and interruption | 22 | Exact budget boundary, votes independent of confidence, identity drift rejection, helper-source binding and no retry |
| Representation adapter | 19 | Explicit decoder/transport wiring, raw responses, timeout classification, visible/duplicate references, policy independence and retained bundle validation |
| Representation interruption after dispatch | 1 | Updated runtime/transport wiring preserves committed dispatch and resumes without repeating it |

The aggregation case covers all 125 combinations of three classified/uncertain/failed votes. The interrupted-dispatch fixture uses fabricated transport responses and an owned-runtime fixture; no model server was contacted.

Static inspection confirms unchanged bodies for ten extracted functions: sampler validation, voting, canonical identity and seven runtime functions. Both protocols retain unchanged settings, payload, validation and decoder bodies. Modified Python files compile, and an isolated import confirms that shared inference does not load corpus, study or legacy settings modules.

The [inspection receipt](../../artifacts/history/redesign/build/refactor/r2-v1/inspection.json) confirms all 46,291 protected evidence files retain their hashes. Protocol resources, requirements and the installed environment were not changed. No model requests, full regression suite, bootstrap analysis, figure regeneration or saved-campaign replay were run for R2. R1's 500-test/full-artifact result remains a historical baseline, rather than a claim about the unrun R2 suite.

## Provenance and continuation

The [dependency receipt](../../artifacts/history/redesign/build/refactor/r2-v1/dependencies.json) records 25 working freeze source files and 26 reporting files. Both closures include the three inference files and exclude `redesign/pipeline/llm.py` and `redesign/pipeline/llm_runtime.py`. The retained legacy runner separately binds its protocol compatibility files.

Current source identities are recorded separately from the original frozen methods. Historical verification continues through the [R0](refactor_r0_report.md) saved method and matching environment. No old manifest, archived source, policy or saved outcome was rewritten.

The [completion receipt](../../artifacts/history/redesign/build/refactor/r2-v1/completion.json) binds the selected checks, source inspection, dependencies, tested source and preservation evidence. No files were staged or committed. Continue with R3's packet inspection and read-only replay boundary.
