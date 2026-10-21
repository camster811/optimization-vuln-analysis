# Claims and proposed manuscript wording: checkpoint A

This is a post-hoc supplement after inspection of the completed Phase 9 results. The original results and reports remain historical evidence. No new LLM requests or lifting were performed. These fixed-label controls are uninformative descriptive controls, not trained models, oracle-selected majority-class predictors, or sound analyzers.

## Supported interpretation

On these ten Juliet-derived source families, this configured LLM recognized more adjudicated emitted behaviors than this bounded custom heuristic. Its 125 correct, 28 incorrect, seven abstained and zero unavailable outcomes compare with the original v2 baseline's 18 correct, zero incorrect, 142 abstained and zero unavailable outcomes. Baseline abstention is neither an incorrect explicit class label nor a conclusion of safety. Its 100% selective accuracy concerns only 18 safe classifications and does not establish vulnerability-detection ability.

The constant no-overflow control is correct on 100/160 cells (62.5%) while detecting none of the 60 vulnerable binaries. Safe-only correctness can therefore be high under the observed class imbalance. The LLM's 125/160 (78.125%) exceeds this control by 15.625 percentage points, with exploratory family-cluster interval [5.625, 26.250] percentage points. All four constants are declared and published; none was selected by fitting the final truth labels.

## Proposed manuscript paragraph

“On 160 matched binary observations from ten Juliet-derived families, the configured local LLM achieved 78.125% exact-label correctness, compared with 11.25% for our bounded custom heuristic and 62.5% for an always-no-overflow control. The LLM-minus-no-overflow difference was 15.625 percentage points; the exploratory shared family-cluster percentile interval was [5.625, 26.250] percentage points. The heuristic abstained on 142 observations, and its 18 classifications were all safe eliminated-operation cells. The LLM detected 39/60 vulnerable binaries at the alert level and produced seven alerts on 100 safe binaries; two detected vulnerabilities received the wrong CWE. These results describe the tested tool configurations and sampled benchmark, and do not establish superiority over static analysis generally.”

## Claims to avoid and remaining limits

Do not claim a sound safety detector, general superiority over static analysis, or generalization to arbitrary production binaries. The constants do not inspect code and cannot establish safe behavior; the no-overflow control and always-uncertain control both have zero vulnerability recall. Wrong-CWE predictions remain exact-label errors even when they are correct alerts. No-alert outcomes caused by explicit safe decisions, abstentions and unavailable predictions remain distinct in the metric tables.

Ten related source families, template similarity and input collisions, private-assisted entry localization, and Codex oracle review without an independent human adjudicator limit interpretation. Public Juliet may have appeared in pretraining. Family-cluster intervals are exploratory; cells and the three LLM repetitions are not independent source samples. The context amendment and this control study occurred after earlier evidence inspection and are reported as separate configurations/supplements.

Treatment-specific results and LLM-minus-control intervals are descriptive. Optimization changes binary class balance and operation survival as well as predictions. The supplementary results do not identify a particular GCC pass's causal effect. Source-label recovery is a separate endpoint and must not replace binary-vulnerability accuracy.

Checkpoint A does not implement or evaluate the proposed v3 library contracts. Track B, if undertaken, remains a separately versioned post-hoc extension requiring its own specification, fixtures and freeze.
