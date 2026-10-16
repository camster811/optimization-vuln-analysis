# Repository and methodology review

Review date: 2026-10-15 (America/New_York). Scope: the current working tree, corpus, frozen 80-record final campaign, 240 saved LLM attempts, and published analysis. There is no paper manuscript in `paper/` to review yet. This is a code and experiment review, not a security-vulnerability scan.

**The experiment is reproducible, but its current LLM results should not support the intended method comparison until the extraction ABI is corrected.** All 80 extraction logs report the Windows x64 compiler specification for GCC/Linux binaries. Three fresh GCC-ABI exports demonstrate materially different, correct argument recovery from unchanged instructions. Two additional methodological limitations are exact input collisions across truth labels and a stripping treatment that changes only a neutral function name in this corpus.

The frozen methods, records, predictions, and results were left intact. The files added under `paper/` are explicitly post-hoc diagnostics. None is a new preregistered result.

## Verification performed

| Check | Result |
|---|---|
| Full test suite with installed Ghidra enabled | 35 passed, 40 subtests passed |
| Input freeze | All 107 files match |
| Published evaluator output | All eight artifacts reproduce byte for byte |
| Static predictions independently rerun from records | All 80 match saved predictions exactly |
| Analysis ELF hashes and `.text` hashes | All 80 match their observation rows |
| Final source/oracle hashes, survival status, and conclusions | All 40 builds match the manual worksheet |
| Saved HTTP answer content versus saved raw answer | No mismatches |
| Fresh extraction with explicit GCC ABI | Three examples corrected; instructions and calls unchanged |

Passing tests and hashes establish consistency, not semantic correctness. In particular, the current Ghidra tests check structure and nonempty decompilation, not recovery of known argument values. They invoke Ghidra differently from production and did not catch the ABI error. The existing `tests/` contains no direct tests of the static interpreter, LLM runner, freeze tool, or evaluator.

Reproduce the post-hoc audit from the repository's Linux environment:

```bash
.venv/bin/python paper/review_audit.py
.venv/bin/python paper/verify_abi.py
GHIDRA_HOME=/home/camst/repos/ghidra_12.1.4_PUBLIC .venv/bin/python -m pytest -q -rs
.venv/bin/python pipeline/freeze.py check
.venv/bin/python pipeline/evaluate.py --check
```

`review_audit.py` writes `paper/review_audit.json`. `verify_abi.py` uses temporary Ghidra projects and writes `paper/abi_examples.json`; its installation path is local and explicit. Neither script runs LLM inference or replaces experiment artifacts.

## Findings requiring action

### 1. High priority: the extraction pipeline selects the wrong calling convention

**Location:** `pipeline/extract.py:237–240`, `config.json`, `ghidra/ExtractFunction.java`.

Production extraction passes `-processor x86:LE:64:default` without `-cspec gcc`. Every `build/logs/ghidra/r0001.log` through `r0080.log` contains:

```text
Using Language/Compiler: x86:LE:64:default:windows
```

Ghidra's documented behavior is to choose the processor's default compiler specification when `-processor` is supplied alone. The installed x86 language definition lists the Windows compiler specification first. The production code validates the language/architecture but never validates the compiler specification. See the [official headless analyzer documentation](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md).

The defect has a direct semantic effect. For `r0059` (p10, vulnerable, O2, retained), the frozen assembly sets EDI to 10 before `malloc`, and EDX to 11 before `strncpy`. The frozen decompilation invents incoming parameters, calls `malloc(__size)` with an unknown size, and passes `(char *)0xb` as the copy source. Explicit `-cspec gcc` produces:

```c
__dest = malloc(10);
strncpy(__dest,local_13,0xb);
```

Its fixed partner `r0063` becomes `malloc(0xb)` with the same 11-byte copy. For `r0003`, the frozen decompilation reduces the function to `puts(param_1)`; the GCC-ABI export restores the local copy. Instructions and call exports remain identical in all three checks. Before/after evidence is in `abi_examples.json`.

**Impact:** the LLM received misleading pseudocode alongside correct assembly; the static baseline ignores pseudocode and models System V registers. This introduces an unintended asymmetric disadvantage. The size and direction of the LLM performance change cannot be determined without rerunning it. Current results describe the misconfigured extraction pipeline, not the intended GCC/Linux analysis pipeline.

**Correction:** explicitly configure `compiler_spec: gcc`, pass `-cspec gcc`, assert `currentProgram.getCompilerSpec().getCompilerSpecID()` in the exporter, and add a real extraction test for known malloc/copy arguments through the production invocation. Re-extract all final inputs in a separately versioned campaign, compare instruction/call exports, establish a new freeze, and rerun both analyzers and evaluation. Preserve this campaign as a documented defective predecessor. Do not edit its freeze to make corrected inputs appear original.

### 2. High priority for interpretation: identical inputs have contradictory labels

**Location:** `corpus/pairs/p02.c`, `p03.c`, the O2 records, and `analysis_plan.md`.

Two sets of records are exactly identical as complete JSON objects:

| Identical observations | Source truth within the group |
|---|---|
| r0003, r0007, r0011, r0015 | Two CWE-121; two not vulnerable |
| r0004, r0008, r0012, r0016 | Two CWE-121; two not vulnerable |

These are the vulnerable/fixed alloca variants of p02 and p03 at O2. This is already acknowledged qualitatively in the README and oracle notes, but it is absent from the generated interpretation. The full dataset has 74 distinct records; neutralizing only the exported function name reduces it to 37 distinct records.

The requested source sizes remain 10 and 11 bytes; the aligned reservations and exported operations coincide. Source truth is not thereby wrong. GCC documents allocation in terms of the requested object size and its alignment; source capacity and physical reservation must remain separate. See [GCC stack allocation](https://gcc.gnu.org/onlinedocs/gcc/Stack-Allocation.html). These examples cannot establish that a classifier recovered a source distinction absent from its input.

For a classifier that assigns the same decision to identical inputs, the empirical exact-label ceiling is **76/80 = 95%**, even with otherwise perfect predictions. On the eight conflicting observations, expected accuracy without external distinguishing information is at most 50%; a random finite run can fluctuate, so 95% is not an absolute ceiling for every stochastic realization. All six repeated request-hash groups in the saved campaign produced consistent decision labels across their duplicates.

**Addition:** retain the prespecified full analysis and add an explicit collision/observability table. Report an exploratory sensitivity analysis on distinguishable inputs, with exclusions fixed by input equality rather than observed performance. Do not redefine `uncertain` as a correct source label or silently drop these observations. Repeat the collision audit after the ABI correction.

### 3. The stripping comparison is mostly a neutral-name sensitivity experiment

**Location:** `pipeline/build.py:derive_retained/derive_stripped`, the exported records, and the treatment interpretation.

For all **40 retained/stripped matches**, instructions and call targets are identical. Replacing the function name with a common placeholder in both the function field and pseudocode makes every matched pair's entire record identical. Library names survive practical stripping, while every retained target is simply named `target`.

Consequently, the static baseline's zero stripping effect is guaranteed by its consumed inputs. It is a useful invariance control, but not evidence of general robustness to symbol loss. The LLM changes its majority label in **11/40** matched comparisons; its reported five-percentage-point accuracy reduction concerns this narrow name perturbation plus sampling variation.

The extractor also receives the oracle target address. The study measures classification **conditional on successful localization of the selected function**, not whole-binary discovery or stripping's effects on discovering functions.

**Addition:** state exactly what information stripping removes, report the 11/40 decision changes, and describe static invariance as a negative control. To study informative symbol loss, use meaningful but label-neutral helper names and function relationships in a future corpus. That is a new experiment, not a reinterpretation of these data.

### 4. Two reproducible static-interpreter correctness defects

**A. Retired saved-frame slots remain protected forever.** `static_baseline.py:365` adds a saved-RBP slot, but the pop/leave handling at lines 368–382 does not retire it. A valid sequence that pushes and pops RBP, then reserves 16 bytes and writes a local qword at RSP+8, is falsely labeled CWE-121 because that local storage overlaps the former slot. Stack-slot lifetime must be modeled at write time; removing slots only at final classification would also erase evidence of earlier real overwrites.

**B. Unknown branch exploration does not preserve path constraints.** `follow_paths` at lines 503–512 forks both directions without recording the condition. In the supplied fixture, `test edi,edi; je safe` followed on the nonzero path by another `test edi,edi; je overflow` reaches an impossible return-address write in the abstract interpreter. `classify_stack` reports a definite CWE-121 from it. At minimum, retain feasibility status and abstain on findings supported only by unvalidated paths; stronger handling propagates branch facts across unchanged registers. Merely checking `incomplete` would not fix this example.

Both fixtures and actual predictions are saved under `baseline_counterexamples` in `review_audit.json`. They demonstrate false positives in valid instruction sequences outside this corpus; they do **not** establish that the current 80 predictions are incorrect. The current static predictions reproduce exactly and have zero labeled errors on their 24 decisions. Describe the method as a restricted heuristic/interpreter, not a generally sound proof system.

### 5. Provenance checks are strong but incomplete at two boundaries

The freeze excludes `data/private/observations.csv` and `manual_oracle.csv`. Evaluation hashes the observation mapping when releasing results, but it does not bind that mapping before inference or validate the manual worksheet. The worksheet is also absent from the release manifest. For this review, all 40 final entries match their binaries, sources, survival statuses, and conclusions. The issue is missing automated provenance, not a demonstrated label error. The worksheet's reviewer is recorded as `Codex`; it is not evidence of independent human adjudication.

The server launcher checks the model hash, and existing startup/preflight logs show full GPU offload, flash attention, and requests fitting the context. However, these runtime records are outside the release manifest, the runner does not verify the live server's identity, and the saved server build reports `commit unknown`. Effective sampler defaults include `top_k=40` and `min_p≈0.05`, which are absent from request configuration. A future server change can therefore alter behavior without changing request hashes.

**Small improvements:** hash the private truth mapping and oracle evidence at freeze time while keeping them inaccessible to analyzers; include sanitized startup/preflight evidence in release provenance; record the server binary/source revision, chat-template hash, hardware, and all active sampler settings. The saved static predictions should also be regenerated and compared during `--check` or a separate audit: the current evaluator validates their schema/evidence but does not prove they came from the frozen implementation. Avoid implying that an untimestamped hash inventory independently proves when a freeze occurred; a versioned commit or timestamped deposit provides stronger chronology evidence.

## Assessment of the analysis and research claims

The core scoring and bootstrap code match the stated plan on inspection: indivisible CWE labels, separate abstention/unavailability, forced-alert scoring, shared pair-cluster weights, and jointly defined metric differences. The balanced 2×2×2 design and inclusion of failed attempts are strengths. I did not identify a numerical defect in the published metrics, and regeneration succeeds.

Several interpretations still need care:

- **Forced accuracy rewards abstention on fixed programs.** Static has 24 explicit correct decisions and 56 abstentions; 34 safe-program abstentions become true negatives. Its 72.5% forced accuracy is not 72.5% successful vulnerability/safety determination. The existing correct/N and coverage table handles this well and should lead the paper.
- **The units are ten source pairs, not 80 independent programs or 240 independent examples.** Several templates are close relatives, and p02/p03 collapse to identical O2 inputs across pairs. Pair clustering is appropriate for repeated treatments but cannot manufacture diversity or a representative sampling frame. Bootstrap intervals describe an exploratory sensitivity to this small corpus.
- **A degenerate 100% interval is not a guarantee.** Resampling an observed zero-error static sample cannot introduce unseen errors. The [100%,100%] selective-accuracy interval is an empirical bootstrap property, not proof of population precision or interpreter soundness.
- **LLM versus static also changes representation.** The LLM receives pseudocode and assembly, while static uses assembly/calls. After fixing the ABI, call this a comparison of complete analysis pipelines. A model-only comparison needs a representation ablation.
- **Aggregate confidence has a limited meaning.** The median pools confidence across different voted labels; it is not the probability that the majority label is correct. Keep the planned statistic but describe it as median self-reported run confidence, especially for the reported 37 high-confidence errors.
- **“Held out” means excluded from pilot tuning.** Two pilot pairs and ten closely related hand-built final pairs do not establish generalization to new projects, compilers, optimization levels, or vulnerability families. Report any final-result inspection and the complete-campaign restart transparently.

## Small additions with the highest paper value

These diagnostics use the existing results and cost no new model calls. Current values are provisional because of the ABI defect; regenerate them for the corrected campaign. Keep them explicitly exploratory.

| Addition | Current finding | Why it helps |
|---|---|---|
| Paired repair discrimination: both variants exact-label correct at the same optimization/symbol condition | Static 6/40; LLM 0/40 | Tests whether the method recognizes the repair instead of applying one label to both versions |
| Same decision for vulnerable and fixed partner | Static 22/40; LLM 30/40 | Shows how aggregate accuracy can hide failure to distinguish variants |
| Input collision/observability table | Eight observations with conflicting labels; 74 unique full records | Separates missing information from reasoning failure |
| Leave-one-pair-out method difference | LLM minus static correct/N ranges from −2.8 to +11.1 percentage points, versus +2.5 overall | Makes sensitivity to individual templates visible without adding a complex model |
| Treatment transition table | LLM changes labels on 11/40 symbol matches | Distinguishes correct→incorrect, incorrect→correct, and abstention changes |
| Compute and failure accounting | 5,253 seconds summed request time (~87.6 minutes); 719–2,544 prompt tokens; 334,360 completion tokens; four length-limit failures | Documents the practical cost of 240 attempts and makes replication feasible |

Add three short qualitative case studies after corrected extraction: a recoverable heap allocation/copy bound; an indistinguishable alloca pair where abstention is justified; and a confident LLM error with checked evidence. Evidence-address membership only proves that an address exists, not that it supports the claim. Manually verify the allocation-to-destination-to-write chain.

If there is budget for **one** new experiment after the corrected primary campaign, prefer an assembly-only LLM ablation with the same records, seeds, and budget. This directly tests whether decompilation helps, hurts, or merely changes confidence. Do not tune a larger baseline against these final outcomes and then present it as the originally frozen comparator. Broader compilers, extra models, O1/O3, and a large corpus expansion are lower-priority scope increases for this paper.

## Recommended order

1. Correct and regression-test the ABI selection; preserve the current campaign as defective historical evidence.
2. Create the corrected versioned extraction/freeze/campaign and regenerate the primary analysis. Do not claim the LLM comparison is repaired before new inference completes.
3. Add the observability and stripping limitations, paired repair metric, per-pair results, and three qualitative examples.
4. Add focused tests for scoring, aggregation/failures, shared-weight contrasts, freeze mutation detection, and the two interpreter counterexamples. Fix baseline defects in a separately identified method revision.
5. Strengthen provenance and obtain an independent check of the source/binary oracle, particularly the optimized stack cases.

The strongest defensible paper contribution is a controlled study of what binary evidence remains available under optimization, how methods handle missing bounds, and how often their predictions distinguish a repair. The current infrastructure provides a useful foundation, but the ABI correction is necessary before attributing the present LLM errors to its reasoning ability.
