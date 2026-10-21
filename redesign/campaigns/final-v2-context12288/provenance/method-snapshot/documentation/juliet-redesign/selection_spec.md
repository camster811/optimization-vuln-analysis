# Juliet source selection specification

Version 1, October 19, 2026. Read with `analysis_plan.md`. The candidate table orders source families; it does not claim they are eligible or that final pairs have been selected.

## Universe and ordering

Inventory `.c` files recursively beneath extracted Juliet 1.3 `testcases/CWE121_Stack_Based_Buffer_Overflow` and `testcases/CWE122_Heap_Based_Buffer_Overflow`. Exclude C++ files. A family is the filename stem with its terminal `_[0-9]{2}[a-z]?` removed: `_01`, `_54a`, and `_54b` share a base family. Different families may still share templates; family count does not imply complete semantic independence.

`candidate_families.csv` records rank within CWE, family identifier, source-file count, available flow IDs, and source fingerprint. Seed is the literal UTF-8 string `20261019`. The ordering key is lowercase SHA-256 of UTF-8 `20261019\n{family_id}`, without a final newline. Sort lexicographically by hash within CWE, breaking collisions by family ID. Rank starts at one. Do not change seed or ranks after eligibility review.

For a source fingerprint, sort source paths relative to extracted `C` ordinally with forward slashes. Form UTF-8 lines `{relative_path}\t{lowercase_file_sha256}\n` and hash the concatenation. `candidate_snapshot.json` records the same fingerprint over all inventoried sources, counts, archive hash, and table hash. Phase 2 must verify extracted files against the archive before claiming upstream authenticity. The current fingerprint records the enumerated source state only.

## Review and assignment

Review source in rank order separately for each CWE. Keep an append-only ledger: family/rank, chosen flow/files, safe/vulnerable entries, eligibility/reason, split, reviewer, and prior exposure. No predictor execution informs eligibility. Enumeration alone is not behavioral review.

Eligible cases contain original vulnerable and safe paths for the target CWE, have identifiable Linux C/Juliet dependencies and input domains, and fit the direct-call, nonrecursive, single-threaded scope. Exclude application indirect dispatch, Windows-only dependencies, and cases requiring testcase-logic changes. Record concrete reasons. Anticipated difficulty and optimized disappearance are not eligibility criteria.

For each CWE, choose the first eligible family with a direct-helper-call flow as pilot, then its numerically smallest eligible helper-call flow. Where multiple safe entry paths exist, choose the lexicographically first eligible entry and preserve its helper chain. Record the choice privately. A minimal external driver may choose this original path. Families skipped only for lacking a helper-call flow remain candidates for final review.

Phase 2 interpretation, recorded before builds or predictions: qualifying buffer reasoning passes a buffer, extent, or index across an application helper boundary. Output helpers and helpers returning only control constants do not qualify by themselves. A safe entry is a single original safe path, not an aggregate wrapper invoking multiple safe paths. A family filed under CWE-122 whose overflowing destination is actually a stack object is source-ineligible for the heap stratum; preserve that exclusion in the ledger rather than relabeling or modifying its source.

After method lock, fill five slots per CWE in this fixed order: interprocedural, intraprocedural, interprocedural, intraprocedural, interprocedural. Interprocedural means relevant allocation/write reasoning crosses direct application helper calls; intraprocedural means it resides within one function. Classify from source, before optimization. For each slot, scan the same ranking from its start and take the first unused, nondevelopment eligible family with a flow of the required structure. Families without that structure remain available for other slots. Within the selected family choose the numerically smallest eligible flow of that structure; never choose according to compiled appearance. Use the lexicographically first eligible original safe entry when several exist. These rules produce six interprocedural and four intraprocedural final pairs from ten distinct families. This is stratified family sampling with deterministic flow selection, not uniform sampling of Juliet files. Record translation-unit counts; do not force source edits to create cross-file behavior.

Before final assignment, review known source-use provenance. Any family used to design/test methods, tune prompts, or inspect predictor behavior is development-only. Where provenance cannot establish non-use, treat the potentially exposed family as development-only and disclose uncertainty. General familiarity with a CWE does not establish exact-family exposure. Candidate inventory generation alone does not expose prediction behavior.

Continue source-only review until counts are met. The remaining ranking is an ordered reserve. Source-ineligible families may be skipped with reasons before assignment. Once assigned final, later build failure, eliminated writes, unresolved truth, extraction failure, oversized context, or poor predictions cannot cause replacement: retain cells and dispositions. If insufficient eligible families exist, amend before final predictions rather than silently relaxing criteria.

Publish ranking, eligibility/exclusion ledger, prior-exposure decisions, selected flows/entries, source fingerprints, and sanitization changes. Additional pilots become permanently development-only. Report residual template similarity and possible LLM training exposure.
