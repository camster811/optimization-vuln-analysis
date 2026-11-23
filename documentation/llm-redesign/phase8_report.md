# Phase 8 — Frozen final execution

Completed November 22, 2026 (America/New_York). The user executed the frozen
schedule; the saved run was subsequently checked offline against the Phase 7
freeze. **All 1,440 scheduled slots are terminal, all 480 condition aggregates
replay, and there are no pending or uncommitted files.** No slot was retried.

## Integrity and accounting

The working execution is
`redesign/build/extensions/representation-study/phase7-final-v1`, purpose `final`,
run ID `phase7-final-v1`. Its immutable request manifest remains SHA-256
`139faa74b6967fe3dbcba9f88716890d6942d5c5424423035ac70d6817a0f1a9`.
The complete source/environment and request/preflight guard passes against the
[Phase 7 freeze](phase7_report.md). Predictor, decoder, voting, scorer, policy,
prompt, resource limits and eligibility were not changed during the review.

The original preflight runtime event is preserved. A matching Phase 8 server
capture was appended as event 2. All 1,404 dispatched slots reference its hash,
`e805ae99f2cba546e1b1e3236e7476f89b4523eb1fe87c9698140e2ff6965cee`;
the saved server capture agrees with that event. Dispatches have unique slot
identities and 1,404 distinct HTTP response IDs. Each raw response is bound to
its durable dispatch, frozen request and supplied representation. The combined
condition has fresh outcomes in this run, rather than imports from the historical
combined campaign.

| Representation | Scheduled | Dispatched | Valid | Length limit | Schema invalid | Input blocked |
|---|---:|---:|---:|---:|---:|---:|
| assembly | 480 | 468 | 462 | 2 | 4 | 12 |
| decompilation | 480 | 468 | 468 | 0 | 0 | 12 |
| combined | 480 | 468 | 452 | 4 | 12 | 12 |
| Total | 1,440 | 1,404 | 1,382 | 6 | 16 | 36 |

The 36 blocked slots are exactly those declared by common eligibility for four
observations. They have explicit terminal records and no dispatch. The six
length terminations retain their raw answers/reasoning and exhausted 4,096-token
completion reservations. The 16 schema-invalid responses consist of **13
nonvisible citations and three duplicate citations**. Saved output evidence
confirms the invalid references/duplicates against the supplied views. They
remain failed votes; no citation was repaired and no answer was regenerated.

There are no timeout, transport-error, runtime-changed or interrupted terminal
slots. Usage and elapsed records exist for every dispatched slot, including the
22 failed responses. Validity here means protocol validity, not correct
vulnerability classification.

## Saved evidence and completion gate

Fresh offline decoding and aggregation match both the user's run output and
verification output. `phase8-run-v1.json` and `phase8-verification-v1.json` are
byte-identical, SHA-256
`119177e65b7b9f3ea1f00507768a8d5cb75f4cd8bd1c002fb0d2e0515170fafe`.
The execution contains 6,199 files, including exact requests, raw response
envelopes, reasoning, terminal dispositions and runtime/dispatch evidence.

The review receipt is
`redesign/build/extensions/representation-study/phase8-integrity-v1.json`,
SHA-256 `42586d6fbd73b814e978e391fad9cc15cf93b8e580edceec844e46dcb00bee21`.
It binds the complete execution inventory, runtime event and completion counts.
The inventory and replay are also included in the [Phase 9 analysis](phase9_report.md).

The Phase 8 gate passes: 1,440 terminal dispositions, 480 aggregates, zero
ambiguous pending slots, preserved failures and no retries. The review sent no
new inference requests. Scoring and interpretation belong to Phase 9; complete
release packaging and manuscript changes remain Phase 10.
