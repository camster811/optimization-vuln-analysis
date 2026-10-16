# Analysis plan

This plan applies to the held-out final campaign. The two pilot pairs are
development data and are excluded from every final table, interval, and figure.
The final corpus has 10 pairs (five per CWE), eight observations per pair, and
80 observations. Treatments cross vulnerable/fixed variants, O0/O2 optimization,
and retained/stripped symbols. Each LLM observation has three stateless runs.

Every LLM request uses the frozen prompt and response schema, with a 4096-token
completion budget and the configured three seeds. No pilot observations are
included in final evaluation.
The final campaign uses an 8192-token context, all GPU layers, flash attention,
512/128 batch/microbatch sizes, 12 generation/batch threads, f16 KV caches, and
automatic fitting disabled. These explicit runtime settings and the launcher
are frozen before this complete campaign restart; abandoned attempts are excluded.

The research question is how optimization and practical stripping affect
recognition of the selected buffer write. We examine whether the LLM differs
from the static baseline, and whether optimization or stripping changes either
method's performance. These are exploratory comparisons, not a general claim
about vulnerability scanners or unseen programs. No directional hypothesis or
minimum effect is imposed after seeing final results.

Decisions are indivisible labels: `vulnerable_CWE-121`, `vulnerable_CWE-122`,
`not_vulnerable`, and `uncertain`. Two identical valid votes establish the LLM
decision. With no valid runs it is `unavailable`; otherwise a missing majority
is `uncertain_due_to_insufficient_agreement`. Confidence is the median over all
valid runs, including votes outside the majority. Invalid runs stay unavailable
and are counted by their recorded failure status; they are never retried or
converted into model-produced `uncertain` votes.

Three-way correctness requires the exact truth label, including the CWE.
Both uncertainty types abstain; unavailability is separate. Report counts,
correct/N, coverage=(correct+incorrect)/N, abstain/N, unavailable/N, and selective
accuracy=correct/(correct+incorrect). Always accompany selective accuracy with
coverage and the underlying correct/incorrect/abstain/unavailable counts.

Forced-alert scoring maps either vulnerable label to alert and everything else
to no alert. Thus a wrong-CWE alert can be a forced TP while being three-way
incorrect. Report TP/TN/FP/FN, accuracy, balanced accuracy, precision, recall,
F1, FPR, and FNR. Identify TN and FN counts caused by abstentions and unavailable
results separately from explicit `not_vulnerable` decisions.

Primary paired comparisons are LLM majority minus static for correct/N,
coverage, forced recall, and forced FPR. Also retain the other metric differences.
Subgroups are O0/O2, retained/stripped, CWE-121/CWE-122, and vulnerable/fixed.
Within each method, compare O2 minus O0 and stripped minus retained using the
same complete pairs and matched variant/other-treatment cells. Never drop a
failed observation or replace a failed pair after viewing final performance.

Use the 10 final pair IDs as clusters. Generate 10,000 draws of 10 IDs with
replacement using the configured fixed bootstrap seed and NumPy PCG64. Include
all rows of each sampled pair, with multiplicity. Share these weights across
methods, subgroups, and both sides of every contrast. Intervals are the 2.5th and
97.5th percentiles with linear interpolation. There is no GLMM, significance
testing ladder, or multiplicity-adjusted confirmatory claim. With only 10
clusters these intervals are exploratory and may be unstable.

A rate with a zero denominator is undefined, not zero. Balanced accuracy is
undefined unless both truth classes are present. For a bootstrap interval, use
only replicates where that metric (or both sides of a difference) is defined;
report the number of defined replicates out of 10,000. An entirely undefined
estimate or interval is blank in CSV and NA in the report. These conditional
intervals need particular caution for sparse subgroups.

LLM stability includes three-valid-run counts, three-identical-decision counts
(requiring all three to be valid), pooled pairwise agreement among valid runs,
failure counts by status, and separate model-uncertainty, aggregation-uncertainty,
and all-unavailable counts. Confidence summaries use observation medians grouped
by three-way outcome. A high-confidence error is a three-way incorrect LLM
aggregate whose median confidence is at least the frozen configured threshold.

Produce only coverage/selective-accuracy, recall/FPR, and treatment-accuracy PNG
figures. Keep optimization and symbol panels separate. Report all exclusions
and failures; valid JSON is not evidence of classification correctness.
Qualitative examples, if added, illustrate observed disagreement, abstention,
or errors with evidence addresses; they do not change eligibility or metrics.
The release manifest binds the qualitative file when present.

Freeze this plan, settings, analyzer inputs, and method files before the final
campaign. Do not infer or fabricate a freeze from already completed final runs.
Create it with `python3 pipeline/freeze.py create` after final extraction and
before either final analyzer; verify it with `python3 pipeline/freeze.py check`.
Regeneration must reproduce every managed output byte for byte; no timestamps,
hostnames, or absolute machine paths appear in generated tables or reports.

## Post-review amendment: corrected GCC ABI campaign

The reviewed Windows-ABI campaign is preserved as `campaigns/windows-abi-v1.tar.gz`,
including its original plan, method files, input freeze, and outputs. Its final
outcomes were inspected. This amendment and the corrected campaign are therefore
post-review, not a new preregistration or an untouched held-out validation.
The earlier complete-campaign restart remains part of the disclosed history.

The corrected `gcc-abi-v2` campaign uses explicit Ghidra `-cspec gcc` and rejects
any other compiler specification in the exporter. It keeps the same sources,
binaries, selected target addresses, treatments, model, seeds, prompt, output
budget, and primary scoring/bootstrap definitions. Sampler defaults from the
predecessor are made explicit in every request, including their order.
The static comparator is separately identified as method revision 2: live
saved-frame slots are captured at write time and retired at pop/leave; findings
on unvalidated branch choices cannot support definite decisions. Repeated
register predicates propagate branch facts, invalidated by register writes.
This remains a restricted heuristic interpreter; it is not a general soundness
claim. No corpus-specific baseline tuning or label-based inference is added.

Before either analyzer runs, a new version 2 input freeze binds private truth,
the oracle worksheet, corrected records/methods, and sanitized startup and token
preflight evidence. The supervisor verifies the full freeze; the LLM runner
checks only analyzer-visible files and live server identity. Neither analyzer
uses private labels, sources, or oracle binaries for predictions.
The worksheet is checked against actual source/binary bytes and final truth;
its Codex reviewer entries do not establish independent human adjudication.
The server binary hash, source-tree hash/revision availability, chat-template
hash, effective sampler settings, hardware, model hash, and context/offload
checks enter release provenance. Hash inventories alone do not prove chronology;
a versioned commit or timestamped deposit should accompany publication.

Primary full-data tables remain unchanged in definition. Add explicitly
exploratory diagnostics: full-record collisions and source-label conflicts;
accuracy sensitivity excluding every member of a conflicting exact-input group;
paired repair discrimination (both vulnerable and fixed exact-label correct);
same-decision rates; per-pair counts; leave-one-pair-out differences; retained to
stripped decision/outcome transitions; and compute/failure accounting.
Exclusions depend only on complete input equality, never observed performance.
Repeat these audits on corrected inputs; never relabel uncertainty as correct.
The consistent-classifier input-collision ceiling is an empirical expectation
constraint, not an absolute limit on a finite stochastic realization.

Classification is conditional on oracle-provided target localization.
If stripping changes only a neutral function name, describe it as name
sensitivity plus sampling variation, with static invariance as a negative
control. Requested object capacity and aligned stack reservation are distinct.
The LLM versus static comparison changes representation as well as method.
Correct/N and coverage lead interpretation; forced accuracy rewards safe-case
abstention. Pair bootstrap intervals do not imply population precision or
soundness, including a degenerate interval after observing no decided errors.
Confidence is median self-reported run confidence across all valid labels, not
a calibrated majority-label probability. Closely related templates and input
collisions limit the effective diversity beyond the nominal ten pair clusters.

Add three illustrative cases after corrected inference: recoverable heap
allocation/copy bounds, indistinguishable optimized alloca inputs, and a
confident LLM error with a manually checked allocation/destination/write chain.
These cases do not change scores. An assembly-only LLM ablation and a broader
symbol-loss corpus remain optional future experiments; neither is silently
added to or substituted for this corrected primary campaign.

## Development follow-up: validation and interpreter fixes

New campaigns prepared from this checkout use static method revision 3. It
retains revision 2's checks and records write-time feasibility, so a later
unknown branch cannot erase an already-proven overflow. Writes reached only
through unvalidated branches still cannot establish an overflow or safety.
The LLM runner requires its own frozen record directory and checks the exact
80-record inventory before inference. Root test discovery is limited to `tests/`.

These are development changes, not changes to the completed `gcc-abi-v2`
campaign or its results. A new campaign must freeze its own revised methods
before inference; the archived v2 methods and freeze remain unchanged.
