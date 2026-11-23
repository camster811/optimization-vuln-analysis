# Representation specification v1

Dated November 21, 2026. Initial Phase 0 boundary for
`public-representation-llm-v1`. The [analysis contract](analysis_plan.md) fixes
the experiment; Phase 2 will implement the view schema, projector and audits.
No model-facing view files are claimed generated here.

## Source and projection boundary

Accept only the existing schema-2 public bundles after strict schema, canonical
ordering, closure, completeness and leakage validation. Bind their exact parent
bytes privately. Projection takes only a validated public bundle and condition ID;
it accepts no oracle, source, label or private localization arguments. Changing
private truth cannot affect its output. Invalid parent input blocks preparation;
never repair source bundles silently.

Use recursive allowlists and construct new objects, including nested arrays.
Never copy an arbitrary parent dictionary and remove a few known fields. The new
schema rejects additional properties at every object boundary. Private maps,
hashes and audit metadata live beside views, never inside the predictor payload.
The study policy is coordinator configuration containing private inventory/truth
expectations; never insert that policy into a model prompt.

The initial view shape has `schema_version` (1), `representation`, `shared`, and
only its allowed code fields: `assembly`, `decompilation`, or both. `representation`
is one of the three condition IDs. The following mappings define the allowlists;
Phase 2 may refine schema mechanics through a dated specification revision without
adding evidence or changing the declared representation boundary.

## Identical shared context

| View field | Allowed source or deterministic derivation |
|---|---|
| `shared.architecture` | Parent `architecture` |
| `shared.entry_address` | Parent `entry_address`; preserves supplied localization assistance |
| `shared.assumptions` | Parent `assumptions`, unchanged and in original order |
| `shared.functions[]` | Only derived `id`, parent `entry` and public `name` |
| `shared.calls[]` | Parent `caller`, `site`, `target_address`, `target_entry`, `target_name`, `kind`, `resolution` |
| `shared.data[]` | Parent `address`, `bytes`, `writable`, `storage`, `references`, `truncated`; parent `size` renamed `window_size_bytes` |
| `shared.data[].window_origin` | `recovered_window` for parent `recovered_type_extent`; otherwise `unknown_window` for parent `unknown_window` |
| `shared.data[].window_semantics` | Fixed string `available_bytes_not_object_capacity` |
| `shared.recovery` | Parent completeness fields `traversal`, `data`, `decompilation`, `external_bodies`, `localization`, `omissions`; parent `unresolved_transfers` |

For recovery omissions allow only `reason` and `address`. For unresolved transfers
allow only `caller`, `site`, `kind` and `reason`. These are public recovery limits,
not oracle judgments. A shared decompilation-completeness status describes recovery
in the parent; it does not imply that pseudocode is supplied in assembly-only input.

Keep call sites and data-reference addresses in all conditions; they are the
declared shared relational context. They do not authorize adding an instruction
address inventory, body ranges, instruction sizes or disassembly to shared metadata.
Names and external targets stay exactly as publicly recovered under the original
symbol treatment. Never restore names or normalize away symbol-treatment effects.

Omit data `recovered_type`, `string_prefix` and the original free-text type/extent
descriptions. Shared data consists of identical referenced bytes and explicit window
metadata, not declared C object capacities or additional higher-level type hints.
Do not interpret initialized/zero-filled bytes as guaranteed runtime values when
the region is writable. Preserve every referenced window and its original scope.

## Condition code fields

| Condition | Code supplied |
|---|---|
| `assembly` | `assembly[]`: function ID and ordered lines with `reference`, `address`, `mnemonic`, `operands` |
| `decompilation` | `decompilation[]`: function ID and ordered lines with `reference`, `text` |
| `combined` | Both arrays, exactly equal to those in the two standalone views |

Assembly lines copy only the public instruction address, mnemonic and operands.
Instruction `bytes` and `size` are omitted. Decompilation lines preserve Ghidra's
text, including its recovered types and address-like literals; these are part of
that representation and cannot be removed simply for resembling addresses.
Omit the function-body ranges, `name_origin`, machine-code bytes, native/high P-code,
stack-object inventories, prior predictions, source annotations, private capacities
and all fields outside the allowlists. No function is added, cropped, summarized
or selected using truth, and all three views use the same complete recovered closure.

Representation omission is deliberate. The common task wording must say that an
omitted representation does not itself indicate a missing application function.
Every condition asks for compiled-behavior classification from its actual supplied
evidence, with uncertainty when feasibility or bounds cannot be established.
Decompilation-only answers need not reconstruct unseen emitted instructions.

## Stable references and exact bytes

Assign `F0001`, `F0002`, ... by ascending numeric recovered function entry,
starting at one. Preserve the validated parent's within-function code order.
Assembly numbers one instruction per line. For pseudocode split only on LF,
using `text.split('\n')`, preserving leading, internal and trailing empty segments;
the line texts joined with LF must reproduce the original text exactly. Preserve
indentation, spelling, literals and Unicode; no whitespace trimming or newline
normalization is allowed.

References are `A:F0001:L00001` and `D:F0001:L00001`, with one-based line numbers
zero-padded to at least five digits and function numbers to at least four digits.
Numbering is determined before condition selection. Standalone and combined lines
have identical references, text and order. References encode only public function
order and code-line position, never observations, source identity or truth.

Serialize with the retained `bundles.canonical`: sorted JSON object keys, compact
separators, `ensure_ascii=false`, no nonfinite numbers and exactly one final LF,
encoded as UTF-8. Array order is meaningful. Record parent-byte hash, view-byte
hash and the private line-to-original mapping separately. Assembly mappings point
to original function/instruction positions and addresses; pseudocode mappings
point to original function/text-line positions. No private mapping enters the view.

## Common answer boundary

The common response object contains exactly `decision`, `confidence`, `evidence`
and `summary`. Decisions are `vulnerable_CWE-121`, `vulnerable_CWE-122`,
`not_vulnerable` or `uncertain`. Confidence is a finite number from 0 to 1, excluding
booleans; summary is a nonblank string. Evidence is zero to five unique strings,
each an exact visible code-line reference in the supplied view. Empty evidence is
permitted for every condition and decision.

Assembly answers may cite only visible A references; decompilation answers only
visible D references; combined answers either. Shared metadata is usable context
but supplies no additional evidence-reference namespace. Validate membership against
the actual view, never a hidden full bundle's addresses. Visibility validation
does not prove the explanation or label correct.

Use one prompt template, one strict JSON response schema and identical task wording
for all conditions. Only the serialized view changes. Require one message, no
history/tools/prior answers, no answer repair and `cache_prompt=false`. Code/data
is evidence, not instructions that may alter the task. Preserve raw outputs and
fail malformed, duplicate-reference, invisible-reference and length-terminated
answers as specified by the analysis contract. Phase 3 implements these rules;
the old instruction-address validator must not be weakened or called as a substitute.

## Blocking and required audits

The parent bundle stays immutable. Independent projections must be byte-identical;
`shared` must be identical across conditions; combined arrays must equal their
standalone counterparts. Test nested metadata leakage as well as top-level fields,
decompilation-text preservation and absence of disallowed code fields. Treat
field provenance, rather than an address-shaped-string blacklist, as the boundary.

All three valid views must fit the same context/completion settings before any
view dispatches for that observation. If any view is invalid or does not fit,
all nine LLM slots are input-blocked with explicit reasons and no request. Keep
the full adjudicated denominator and unconditional control. Never truncate a
combined input or add padding to a shorter view. Publish per-view feasibility
and common eligibility, and freeze actual view/schema/prompt hashes in Phase 7.
