# Phase 8: final corpus preparation and input freeze

Phase 8 is complete. The [freeze manifest](../../redesign/campaigns/final-v1/release/freeze.json), [private input archive](../../redesign/campaigns/final-v1/release/final-v1-inputs.tar.gz), and [validation record](../../redesign/provenance/phase8-validation.json) are preserved. No final predictor ran.

Phase 8 uses `redesign/campaigns/final-v1`, isolated from the hash-bound pilot workspace. The Phase 7 method lock remains unchanged. The final campaign has ten families, 80 reference builds, 160 retained/stripped observations, and 480 scheduled LLM repetitions. Final predictors belong to Phase 9.

## Selection and preservation

The source-only selection follows the locked ranking and the inter/intra/inter/intra/inter slot order within each CWE. Stack ranks are 4, 5, 6, 7, 8; heap ranks are 3, 4, 12, 13, 21. Selected interprocedural flows are 21; intraprocedural flows are 01. Each family contributes one original vulnerable path and the lexicographically first eligible original safe path. Six pairs pass relevant pointers or indices across a direct helper boundary, and four keep the reasoning within one function. All ten selected testcase units are single-file; the support translation unit is separate. Cross-file testcase diversity is zero and residual copy-template similarity remains a limitation.

The prior-adaptation ledger conservatively excludes earlier families with attempted sanitization, even when their inference exposure is uncertain, as well as both pilot families. The source-ineligible heap ranks include cases with stack destinations and cases requiring unspecified socket/stdin input. The full ledger and remaining ranked reserve (subject to the recorded exclusions) are in `corpus/final_selection.json`; the original exposure evidence is preserved privately. No case was replaced because of compiled behavior, extraction size, or a predictor result.

The upstream ZIP SHA-256 is `ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb`. All 9,562 inventoried C files were checked against the ZIP and extracted tree before import. Selected originals remain read-only. Per-file maps, hashes, executable-token preservation checks, diagnostic substitutions, diffs, and external drivers are preserved. Original arithmetic, capacities, control flow, qualifiers and safe/vulnerable logic are retained. The original pilot manifest remains unassigned for final slots as historical locked evidence; the isolated final manifest supplies the final assignments.

## Private emitted-code review

Codex reviewed all 80 reference scopes using bound disassembly, source and private DWARF before any final predictor execution. There was no independent human adjudication. The private oracle distinguishes original source provenance from emitted behavior: 14 reference builds have CWE-121, 16 have CWE-122, and 50 are not vulnerable within the selected scope. Operations are present in 30 builds, expanded/inlined/merged in 30, and eliminated in 20. Symbol partners inherit the same reference adjudication.

The review covers destination identity, object extent, actual write extent, branch feasibility, initialization, allocation failure, and whole-scope elimination. Native expanded stores count as surviving operations. In particular, the stack concatenation and memcpy cases at O2/O3 retain stores beyond a 50-byte destination; DWARF identifies the object separately from the larger frame. The O0 index-ten write crosses a ten-int object into padding. Its optimized variants eliminate that store. The heap `sizeof(int64_t)` family stays selected: both pointer and pointee are eight bytes on LP64, so both O0 allocations fit their eight-byte store; optimized variants eliminate the allocation/store. It is not replaced because its source-vulnerable path compiles safely.

These are object-bound judgments on the fixed Linux x86-64 platform, assuming ordinary libc behavior, one main invocation, and feasible successful allocation. Labels are not crash claims. Private review packets, cited instructions and conclusions remain outside public requests.

## Public input and runtime checks

The frozen Phase 4 extractor runs on each public binary in its own fresh Ghidra project, with private debug loading disabled. Only the allowlisted entry ticket reaches extraction. The audit checks schema, leakage, binary identity, oracle-evidence coverage, retained/stripped code/data scope parity, actual name loss, and input collisions. The final audit does not claim a second full extraction: the unchanged extraction method's repeatability was established in Phase 7.

`final_freeze.py preflight` uses the frozen adapter and owned local runtime. It calls only `/apply-template`, `/tokenize` and runtime identity endpoints. Complete wire requests, rendered prompts and token IDs are preserved. Prompt tokens plus the unchanged 4,096-token completion reservation must fit 8,192 tokens. Oversized observations keep their complete requests and receive shared `context_unavailable` status for both predictors. No context is cropped, no completion endpoint is called, and the three repetitions retain the locked schedule and seeds.

All **160 bundles** are available after extraction. Both the oracle-evidence coverage and code/data scope-parity gates pass. All **80 symbol pairs** lose developer names (including application entries/helpers and output helpers); zero pairs are identical or differ only trivially. Across the full matrix there are 24 exact-bundle collision groups, two with conflicting source labels, and 66 code/data-scope collision groups, one with conflicting source labels. None conflicts in binary truth. These groups are preserved for Phase 9 sensitivity analysis.

Prompt lengths range from **1,344 to 7,614 tokens**. With the locked completion reservation, **112 observations are available and 48 are shared-unavailable** (30% of the planned matrix). This produces **336 eligible slots and 144 blocked slots**; all 480 were preflighted without a completion request. The runtime was the existing verified Phase 6 server. Sandbox visibility caused two unsuccessful startup probes before the live host process was identified; neither generated predictions or changed the runtime configuration.

## Verification and release

The release binds upstream/source transformations, compiler settings and tool identities, reference/analysis binaries, private oracle and review evidence, public bundles and raw exports, exact requests and budget evidence, method snapshots, prompt/schema, model identity, runtime evidence, and test provenance. Its archive contains private truth and must not be mounted as a predictor's input directory. Predictor inputs are restricted to the public bundle/request and shared eligibility.

The release timestamp is `2026-10-20T22:32:05.662635+00:00`. Its 8,406,608-byte archive binds **3,144 files**, with SHA-256 `78fbad10f195dcc72220d66fefd4c90597c3b97b0e6a57356d7e394e7786e5f8`. A fresh archive restore passed full offline verification. Python's tar `data` filter adds owner write permission; replay restored the archive's read-only permissions before verification.

The Ghidra-enabled regression run passed **103 tests, zero failures/errors/skips**, including ten Phase 8 tests. Tests cover selection ordering, source-token preservation, private/public payload separation, exact budget boundaries, shared unavailability, incomplete schedules, changed requests/token evidence, failed test gates, changed campaign methods, and archive inventory/content tampering. Existing build/oracle/context/runtime regressions also passed. The full Phase 7 method lock still verifies; no locked method was edited.

The freeze is exclusive and hash-bound; bound files and release artifacts are also made read-only. Verification checks archive membership and every member digest, then revalidates the complete matrix and preflight offline. External pinned compiler/Ghidra installations are hash-checked and are not vendored into the archive. The model weights are identified by hash rather than copied into the release.

```bash
# Offline verification; does not invoke either predictor or require a live model server.
.venv/bin/python -m redesign.pipeline.method_lock verify
.venv/bin/python -m redesign.pipeline.final_freeze verify

# Preparation commands for a fresh, already imported/built/adjudicated campaign:
# GHIDRA_HOME=/path/to/ghidra .venv/bin/python -c \
#   "from redesign.pipeline.export_context import extract_run; from pathlib import Path; extract_run(Path('/path/to/campaign'), 'final', 'phase8-a', write=True)"
# .venv/bin/python -m redesign.pipeline.final_freeze preflight --root /path/to/campaign --server /path/to/server.json
# .venv/bin/python -m redesign.pipeline.final_freeze freeze --root /path/to/campaign
```

Creation refuses an existing destination. Restore the archive to a fresh directory to verify preserved inputs; it is not necessary to rebuild or retokenize to check their recorded identities. The chronology is a local UTC timestamp and versioned content-addressed release, not an independent timestamped deposit or external preregistration. Phase 9 must verify this freeze before either final predictor executes and retain shared missingness in all denominators.
