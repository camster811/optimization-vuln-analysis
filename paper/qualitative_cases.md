# Qualitative cases from the corrected GCC-ABI campaign

All record IDs and `results/...` paths refer to the corrected campaign root
(`campaigns/gcc-abi-v2/` in this checkout).

These examples are post-review illustrations, not eligibility rules or additional
scoring criteria. Evidence chains were checked against corrected instructions,
call exports, and the hash-bound source/oracle worksheet by Codex. This is not
independent human adjudication. An address being present in a model response
alone does not validate its interpretation.

## Recoverable heap allocation and copy bound: r0059 and r0063

These are p10's vulnerable and fixed O2 retained observations. In both records,
`0x40118a` calls malloc; `0x401194` preserves its RAX return in RBX;
`0x4011ab` passes RBX as RDI to strncpy at `0x4011bb`; and `0x40119c`
sets EDX to 11. Thus the destination is the allocated heap object and the copy's
write interval is `[0,11)`. The source local contains ten A bytes and a terminator.
Subsequent puts/free calls use the same allocation.

The difference is the malloc argument at `0x401181`: EDI is 10 in r0059 and 11
in r0063. The vulnerable allocation is exceeded by one byte; its fixed partner
fits exactly. Corrected pseudocode recovers `malloc(10)` versus `malloc(0xb)`
and the same 11-byte strncpy. The historical Windows-ABI pseudocode did not
recover this allocation/destination/copy chain correctly. The restricted static
interpreter's decisions on this pair are vulnerable_CWE-122 and not_vulnerable.

## A source distinction absent from the input: r0003 and r0007

These are p02's vulnerable and fixed O2 retained observations. Their complete
corrected JSON inputs are identical, including pseudocode. Source alloca requests
are 10 and 11 bytes respectively, while both compiled targets reserve the same
aligned storage. At `0x40117d` and `0x40118d`, the destination address is
computed and aligned in RDI. Stores at `0x401191` (eight bytes at +0) and
`0x401194` (four bytes at +7) merge to `[0,11)`; puts consumes that buffer
at `0x40119b`.

The 32-byte reservation and decompiler's `local_30[29]` are not source object
bounds. A classifier seeing this input cannot recover which request was used.
Abstention is justified by missing information, though it remains an abstention
under the exact source-label score. The full collision audit includes the same
O2 input across p02/p03, within retained and stripped groups.

## A confident error despite recoverable bounds: r0079 repetition 2

This is p12's fixed O2 retained observation. The saved valid run at
`results/llm_runs/r0079/rep2.json` labels it vulnerable_CWE-122 at confidence
0.9, citing the strncat call at `0x4011dd` and claiming its length exceeds
the heap capacity. This is an individual-run example; majority aggregation is
reported separately in the campaign's complete results.

The allocation/destination/write chain is recoverable. `0x401181` sets EDI
to 100 and malloc is called at `0x40118a`. `0x401194` initializes its first
byte to zero, so the destination is empty. `0x401197` preserves that pointer
in RBX and `0x4011a7` passes it as RDI. RSI is the source at RSP
(`0x40119f`), and EDX is 100 (`0x4011a2`).

The source contains 99 C bytes and a NUL at offset 99. The byte store at
`0x4011ae` establishes that terminator; the six 16-byte stores cover offsets
0–95, and the dword store at `0x4011d5` covers offsets 95–98. Those stores
leave the byte at offset 99 intact. Thus strncat appends `min(99,100)` characters
and a terminator to an empty destination: exactly `[0,100)`, fitting malloc(100).
The bound argument is a maximum character count, not a command to copy 100
characters regardless of the earlier source terminator.

The cited address exists, but its existence alone cannot support an overflow
claim. This case distinguishes evidence membership from a checked bound
calculation. It illustrates one saved attempt and does not change any score,
eligibility rule, or failure handling.

For this observation, the completed three-run aggregate is `vulnerable_CWE-122`
with median self-reported run confidence 0.9; vote counts are
`{"vulnerable_CWE-122": 3}`. The single confident error
above remains an observed attempt even when another vote or aggregation differs.
