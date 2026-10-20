# Public context bundle version 2

Development policy `entry-closure-v1`, October 19, 2026. The executable schema is [bundle-v2.json](../../redesign/schemas/bundle-v2.json); limits and treatment-independent settings are in [context_policy.json](../../redesign/context_policy.json). Phase 7 must lock this policy before final preparation.

## Public/private boundary

A public record contains only the imported analysis ELF's recovered code/data and generic interpretation/completeness information. Its opaque observation ID remains in the filename and private inventory, outside the bundle and future model prompt. It contains no pair, source variant, CWE, optimization, symbol condition, source path, oracle label or private bound field. Strict schemas reject extra fields at every object level. Known benchmark labels are scanned in rendered text and decoded data bytes; source/treatment/path clues are also rejected. This detects known leakage markers, not all possible benchmark clues.

The private coordinator verifies Phase 3 inputs and creates a localization ticket containing exactly an observation ID, the analysis ELF hash and the selected entry address. Only a copied analysis ELF named `input.elf`, that address and the shared policy are passed to the worker subprocess. Worker code does not read source, debug references or oracle files. This is a process/input boundary, not an OS sandbox that prevents arbitrary filesystem access. Oracle instruction ranges, function names, bounds and labels do not participate in traversal. The later private audit may identify missing evidence, but cannot add it to a bundle or pick better functions.

Ghidra imports each retained/stripped artifact independently into a fresh project with the declared x86-64/GCC compiler specification. A pre-analysis script disables DWARF/PDB analyzers, and the exporter verifies that DWARF analysis is disabled. This prevents host build-ID/debug caches from restoring removed information. External library autoloading is disabled. Ghidra's shipped public type archives, function-identification databases and ordinary binary recovery remain enabled; their identities are recorded. No stripped function is renamed from its reference or retained partner. Names recovered independently by Ghidra are legitimate binary-analysis outputs.

All initial pilots use a privately localized driver `main`. Public `entry_address` and `completeness.localization` disclose this assistance. This is classification conditional on localization, not whole-program discovery.

## Selection and relationships

Start at the recovered function containing the entry. Follow direct call destinations and native inter-function jumps in ascending address order, then serialize functions in ascending entry order. Include every reachable application function, output/support helper and compiler clone, including wrappers in `.text`. Include inlined operations through their containing functions. Preserve every recovered body range; do not replace discontiguous bodies with a misleading single interval.

Select relationships using recovered addresses and function bodies, never developer names. Exclude external functions and PLT linkage bodies (`.plt`, `.plt.*`); preserve imported library identity on external edges. A `.text` application wrapper remains included even when Ghidra recognizes it as a thunk. Runtime startup is outside the closure because traversal begins at the selected entry and does not follow incoming callers. Local branches remain instructions rather than call edges. Native jump mnemonics determine tail-transfer kind even when Ghidra's call-return analyzer overrides their flow type to a call. Record indirect transfers and direct targets without recovered bodies explicitly; under this initial policy they make extraction unavailable.

The graph includes all recovered branches of each selected function, including branches infeasible for the driver inputs. It does not use oracle feasibility to prune functions or statements. It is a bounded recovered scope, not a proof of complete program semantics.

## Fields and interpretation

| Field | Meaning |
|---|---|
| `schema_version`, `architecture`, `policy_id` | Public format, instruction architecture and shared selection-policy version |
| `entry_address`, `assumptions` | Localized instruction and the same ABI/library/concurrency/interpretation assumptions for every observation |
| `status` | `available`, `extraction_unavailable` or `context_unavailable` |
| `functions` | Recovered entry/name/name origin, sorted body ranges, instructions and per-function decompilation status/text |
| `calls` | Caller entry, instruction site, actual destination, recovered callee entry/name, native call/tail kind and application/external/unresolved resolution |
| `data` | Direct referenced address, exact load-image bytes, size, writable/storage flags, recovered type/extent status, string prefix, referring instructions and truncation flag |
| `unresolved_transfers` | Instruction/caller/kind and the reason a code relationship remains unknown |
| `completeness` | Traversal/data/decompilation states, excluded external bodies, localization assistance and explicit omissions |

Each instruction includes its address, byte length, exact bytes, mnemonic and operands. Validation checks that instruction byte ranges lie within recovered bodies and agree with the public ELF load image. Call sites must belong to their stated caller. Available bundles must contain the entire declared application closure and no functions unreachable from the selected entry. Evidence validation accepts instruction starts from any included function and rejects data addresses, instruction interiors and absent instructions.

For each direct static data reference, export the remaining extent of a defined recovered datum, bounded by its memory block and the per-reference limit. An undefined datum instead uses an explicitly uncertain window of at most 16 bytes. Zero-filled load-image tails are represented as zero bytes. If an absolute data reference cannot be read, record a data omission and mark extraction unavailable. References into executable memory are included as data when the target is not a recovered instruction. This data policy is about direct static references; it does not promise transitive pointer resolution or the contents of dynamically allocated objects.

`recovered_type_extent` is Ghidra's interpretation, not an oracle capacity. `unknown_window` means no object extent was recovered. `string_prefix` is a convenience decoding of a nonempty printable ASCII prefix terminated by NUL within the recorded bytes, independently checked against those bytes. It does not imply the whole window is a string object. Decompiler array declarations, global labels, padding and overlapping windows are never automatically proven object boundaries. Overlapping data windows retain their own referring sites and may duplicate bytes; they count separately toward the declared data limit.

The data completeness state is `complete` when the direct-reference window policy is satisfied with recovered extents, `uncertain` when undefined windows occur, and `incomplete` when required data cannot be exported or a cap clips a window. `complete` is relative to this policy, not a guarantee that all runtime memory has been recovered.

## Shared limits and availability

| Limit | Development value |
|---|---:|
| Application functions | 32 |
| Instructions across functions | 4,096 |
| Exported referenced data bytes | 16,384 |
| Bytes per referenced datum | 256 |
| Undefined-data window | 16 |
| Canonical bundle UTF-8 bytes | 131,072 |
| Conservative token upper bound | 65,536 |
| Ghidra analysis / function decompilation / process timeout | 120 / 60 / 300 seconds |

Ordering is deterministic; there is no testcase-specific selection or prioritization. A function, instruction, data or serialization cap yields `context_unavailable`. Partial code/data may remain as a diagnostic record, but neither adapter may treat an unavailable record as usable context. No available record is silently clipped. A missing build or entry, engine failure, invalid export, unresolved transfer, unreadable required static data or function decompilation failure yields `extraction_unavailable`. Assembly and decompiler diagnostics are retained where the engine produced a valid partial export; assembly-only availability is disabled until both adapters explicitly support it under a later locked policy.

Token accounting uses canonical UTF-8 byte length as a conservative upper bound for the planned byte-based tokenizer. It does not invoke a model/tokenizer and does not demonstrate that a bundle fits the current 8,192-token runtime with a 4,096-token completion reserve. Exact tokenizer/chat-template/prompt budgeting and the shared inference availability gate remain Phase 6 work. These Phase 4 development limits may change uniformly on pilots before the Phase 7 lock.

Canonical public serialization uses UTF-8, sorted object keys, compact JSON separators and one trailing newline. Arrays have numeric address ordering with stable tie breakers; omissions sort by canonical content. Execution time, filesystem paths, analysis logs, artifact IDs and reference hashes stay in private run manifests. Two independent runs must produce byte-identical public records. Each run is preserved separately; existing published records must match before any new records are written.

## Private acceptance audit

After public extraction, compare every available bundle with its private review's destination, bound, write and path instruction addresses. Missing addresses fail the coverage gate; they do not authorize oracle-based context repair. Compare code/data scope and instruction addresses between symbol partners, and report the actual imported developer names removed. Report exact-bundle equality groups separately from binary-code/data-scope groups that ignore names and decompiler rendering. Identify conflicting source labels privately without assigning them to public inputs.

All declared observation files and their availability statuses must remain in the inventory, including unavailable records. The Phase 4 pilot gate requires the complete inventory, audited allocation-to-write scope, no known private leakage, symbol-partner scope parity and identical canonical records across two fresh extraction runs. This gate does not establish analyzer coverage, prediction accuracy, a final token budget or a final campaign freeze.
