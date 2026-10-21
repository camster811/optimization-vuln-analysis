# Checkpoint B: bounded five-contract v3 extension

Post-hoc study on the same inspected ten families. Original Phase 9 and Checkpoint A remain unchanged.

| Method | C | E | U | M | Correct / A | Coverage | Selective accuracy | Recall | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| v3 | 18 | 0 | 142 | 0 | 11.250% | 11.250% | 100.000% | 0.000% | 0.000% |
| saved_baseline_v2 | 18 | 0 | 142 | 0 | 11.250% | 11.250% | 100.000% | 0.000% | 0.000% |
| saved_llm | 125 | 28 | 7 | 0 | 78.125% | 95.625% | 81.699% | 65.000% | 7.000% |
| control_not_vulnerable | 100 | 60 | 0 | 0 | 62.500% | 100.000% | 62.500% | 0.000% | 0.000% |
| without_memory | 18 | 0 | 142 | 0 | 11.250% | 11.250% | 100.000% | 0.000% | 0.000% |
| without_output | 18 | 0 | 142 | 0 | 11.250% | 11.250% | 100.000% | 0.000% | 0.000% |

New classifications: 0; correct safe gains: 0; correct vulnerable gains: 0.

Worker statuses: {'completed': 160}. Recorded worker seconds including fresh lifting and both evaluator ablations: 645.77.

Ablations reuse exactly the same v3 IR/prototypes and abstain at disabled effects. They do not reconstruct the saved v2 lifter.

Full class/optimization/symbol/family/API and reason/event accounting, binary/source endpoints, collision sensitivity and paired family-cluster intervals are retained in comparison.json. Reason/API counts overlap.

No safe label is inferred from abstention. Heap requests and heuristic recovered stack extents remain distinct. Ten-family intervals are exploratory; no outcome threshold on this already inspected corpus is confirmatory.

Scope remains five standard-library effects: no loop solver, new stack bounds, custom instruction decoder, testcase summaries, modified research sources or new LLM inference.
