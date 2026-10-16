# Historical exploratory diagnostics: defective Windows-ABI campaign

These are historical results from the misconfigured Windows-ABI extraction. They do not measure the corrected GCC/Linux pipeline.

These post-review additions retain the prespecified full analysis. Exclusions use input equality, never prediction performance.

Full records: 74 unique inputs across 80 observations; 8 observations have conflicting source labels within identical-input groups. Neutralizing only function names leaves 37 unique inputs.

A classifier consistent on identical inputs has an empirical exact-label ceiling of 76/80. A stochastic finite run can fluctuate above this value. Uncertainty remains an abstention, not a correct source label.

| Identical input IDs with conflicting truth | Truth counts |
|---|---|
| r0004, r0008, r0012, r0016 | {"not_vulnerable": 2, "vulnerable_CWE-121": 2} |
| r0003, r0007, r0011, r0015 | {"not_vulnerable": 2, "vulnerable_CWE-121": 2} |

| Method | Both variants exact correct | Same decision for both variants | Distinguishable correct/N |
|---|---:|---:|---:|
| static | 6/40 | 22/40 | 24/72 |
| llm_majority | 0/40 | 30/40 | 22/72 |

Stripping: 40/40 matches have identical instructions/calls; 40/40 are identical after neutralizing function names.

The static method consumes instructions/calls, so identical consumed inputs guarantee invariance as a negative control. With neutral retained names, the LLM treatment measures name sensitivity plus sampling variation. Extraction uses an oracle address: classification is conditional on successful target localization.

| Method | Changed decision | Retained outcome → stripped outcome | Count |
|---|---:|---|---:|
| static | 0/40 | abstain → abstain | 28 |
| static | 0/40 | correct → correct | 12 |
| llm_majority | 11/40 | abstain → abstain | 4 |
| llm_majority | 11/40 | abstain → correct | 3 |
| llm_majority | 11/40 | abstain → incorrect | 4 |
| llm_majority | 11/40 | correct → correct | 11 |
| llm_majority | 11/40 | correct → incorrect | 1 |
| llm_majority | 11/40 | incorrect → abstain | 2 |
| llm_majority | 11/40 | incorrect → incorrect | 15 |

Leave-one-pair-out LLM minus static correct/N ranges from -2.8 to 11.1 percentage points.

Compute: 240 attempts; 5253.2 summed request seconds; 334360 completion tokens; prompt tokens 719–2544. Status counts: {"length_limit": 4, "valid": 236}.

Per-pair counts, leave-one-pair-out results, equality groups, exclusions, and matched repair cells are in diagnostics.json.
