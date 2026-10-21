# Complexity, support and benefit decision

This is a post-hoc engineering decision on already inspected families, not a confirmatory outcome threshold.

V3 has 18 correct, 0 incorrect, 142 abstained and 0 unavailable cells. Correct new safe classifications: 0; correct new vulnerability classifications: 0; new exact errors relative to v2: 0.

Decision: stop expansion at the five declared effects and preserve this version as an additional post-hoc comparator, with the supported heap behavior and measured errors documented. Do not replace the original v2 comparison. Further solver, loop, native-write or stack-inference work would be a new method and requires additional held-out validation.

A gain confined to safe classifications is weak evidence of a stronger vulnerability detector. Gained vulnerability detections and false-positive changes must be read with the complete denominators, not coverage alone.

Independent compiled matrix: 176 observations across O0–O3, retained/stripped and ordinary/contract-forcing modes. Classified fixture errors: 0. Stack observations: 16; their recovered extents and outcomes remain in the fixture report rather than being forced to match source sizes.

The engine inherits the existing 531-line v2 interpreter and 116-line stack helper. The new effects do not add a decoder, loop solver, alias engine or new stack-bound guesses. Existing Ghidra lifting/IR validation is reused unchanged, with only policy-supplied external prototypes differing. Maintenance includes five contracts, explicit units/ABI checks, worker/schema projection, fixture matrix, no-retry execution and reproducibility checks.

Added production Python lines by file (including orchestration/reporting): {'campaign.py': 215, 'release.py': 122, 'engine.py': 141, 'worker.py': 61, 'comparison.py': 130, '__init__.py': 1}. Fixture Python lines: 116. Modified historical/lifter-Java lines: zero.

Known limits include inherited O0 parameter-spill/stack recovery, enlarged inferred arrays, unaccounted native writes, cyclic flow, unsupported or unrecovered output arguments, unknown terminators and incomplete public memory windows. Reason/API/event counts overlap and do not promise coverage.

Development extraction probes exposed truncated unknown-data windows at the ELF section end. Independent literal padding was added before the accepted fixture run; the initial failed smoke attempts remain under build/extensions. Neither research inputs nor extraction budgets changed. O0 abstention was retained rather than repaired with new stack assumptions.

Same-IR ablations isolate the new memory/string effects and wide-output effects under the v3 prototypes. They are not equivalent to the saved v2 representation. No LLM requests or new source selections were made.
