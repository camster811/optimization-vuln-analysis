# Phase 3: campaign builds and private oracle

Implemented October 19, 2026. No final sources were assigned and no redesigned predictors ran.

## Build treatment and evidence

`redesign.pipeline.build` uses the declared GCC 15.2.0/binutils 2.46 treatment without optimization-pass exceptions, preservation modifiers, LTO or sanitizer instrumentation. Each treatment compiles the driver (which includes the selected testcase) and the output support unit separately. Support objects are rebuilt for every treatment. Manifest recipes also support additional testcase translation units and external drivers, deduplicating drivers already listed as translation units. A separate two-file fixture exercises direct calls across translation units at all four optimization levels.

Sixteen private debug references produced 32 retained/stripped artifacts, at the exact paths in the Phase 1 inventory. Every allocated ELF section matches between each reference and its two derivatives, including code beyond `.text`, literal bytes, writable data and zero-filled objects. Equivalence includes virtual addresses, sizes, flags and alignment. Both analysis derivatives have no debug sections and pass the known-label metadata scan; stripped artifacts have no static symbol table. Dynamic imports remain. Public record leakage and actual retained-name loss in exported contexts still require Phase 4 checks.

The generated `redesign/build/pilot/build-manifest.json` records commands, warnings, translation units, compiler/header dependencies and hashes, effective optimizer/target option output, compiler/assembler/linker/internal compiler tools, libc/loader/startup identities, environment, artifact hashes, allocated-section hashes, function ranges and instruction inventories. Disassembly, symbol listings, DWARF info, line tables and range lists are private evidence. Toolchain mismatch blocks preparation; per-build compilation/equivalence failures retain the planned cell as `build_unavailable`. Existing manifests cannot be overwritten by the build command. Interrupted or partial build manifests fail complete-inventory verification.

The versioned summary is [phase3-validation.json](../../redesign/provenance/phase3-validation.json). Generated artifacts remain reproducible under the ignored redesign `build/` directory. This is development evidence, not the final campaign freeze.

## Private review and transformations

The [private pilot oracle](../../redesign/corpus/private/pilot-oracle.json) binds each review to its exact reference and evidence hashes. Every review includes the source label independently from the compiled-behavior conclusion, assumptions, destination/object-bound/write-extent/path assessments, supporting instruction addresses, containing-function ranges, source-entry disposition and assembly excerpts. The verifier checks complete review inventory, stale hashes, instruction membership and containing ranges; it does not infer correctness of a semantic judgment from a source label. Missing or ambiguous evidence must be reviewed as unresolved.

| Pilot / selected variant | O0 | O1 | O2 | O3 | Binary conclusion |
|---|---|---|---|---|---|
| Stack / vulnerable | present | present | present | present | CWE-121 at every level |
| Stack / safe | present | present | present | present | No selected overflow at every level |
| Heap / vulnerable | present | inlined/merged | inlined/merged | inlined/merged | CWE-122 at every level |
| Heap / safe | present, guarded | present, guarded | eliminated | eliminated | No selected overflow at every level |

These are operation dispositions, independent of source-entry inlining. Across references: 11 present, three inlined/merged, two eliminated, zero unresolved. Binary labels comprise four CWE-121 overflows, four CWE-122 overflows and eight no-selected-overflow conclusions. Both symbol treatments inherit the same private conclusion only after artifact equivalence passes. All 32 planned observations remain in the disposition output.

The stack helper writes eleven bytes, including the terminator. At O0/O1 it uses a byte loop; at O2/O3 it uses an eight-byte store and an overlapping four-byte store at destination offset seven. Selected destinations are the privately mapped ten-byte or eleven-byte stack objects. Object boundaries use source/DWARF evidence corroborated by emitted address setup, rather than equating the entire reserved stack frame with the destination capacity. The one-byte overflow can land in frame padding; no claim about crashes or exploitability follows. The optimized standalone `process_case` body can differ from the path actually emitted in `main`; reviews follow the selected driver path.

The heap-vulnerable path allocates 40 bytes and emits a four-byte write at offset 40. O0 propagates index ten through a helper; O1 inlines that helper into `process_case`; O2 uses a constant-propagated clone; O3 emits the allocation and write in `main`. Ordinary optimization also changes malloc plus zeroing to calloc in the O2/O3 vulnerable builds. The selected heap-safe path rejects index ten at O0/O1. Its initialization writes remain within 40 bytes. At O2 the selected helper reduces to diagnostic tail calls, and at O3 the diagnostic call is emitted directly in `main`; the selected heap allocation and indexed write are absent. These are observations of emitted instructions, without attributing them to an experimentally isolated compiler pass.

All execution scopes start at the privately localized driver `main`. Mapping can describe multiple instruction ranges and containing functions, source-entry inlining, specialized helpers, absent operations and unresolved localization. Uninvoked aggregate wrappers and alternate safe paths are excluded from the reviewed execution scope. Output helpers were reviewed under fixed standard-library contracts: they read arguments and print; they do not write the selected destination. Reviews assume one driver invocation, no concurrent mutation or interposition, the x86-64 ABI and ordinary allocation-success/failure behavior. Safety concerns selected stack/heap writes under these assumptions, rather than every possible defect or libc internals.

Review was performed by Codex using emitted assembly, preserved source and private debug information. There was no independent human adjudicator. The oracle is private evaluation/localization evidence, not a third predictor, and none of its source bounds, labels or restored symbols may enter public context.

## Reproduction and acceptance

From a fresh workspace containing the versioned redesign inputs:

```bash
.venv/bin/python -m redesign.pipeline.import_juliet verify
.venv/bin/python -m redesign.pipeline.build build
.venv/bin/python -m redesign.pipeline.build verify
.venv/bin/python -m redesign.pipeline.oracle --write
.venv/bin/python -m pytest -q
```

For an existing build, omit `build build`; the command deliberately refuses to overwrite its manifest. Oracle verification writes private observation dispositions under `redesign/build/pilot/dispositions.json` and regenerates the versioned validation summary. It validates the recorded reviews against rebuilt binary identities and emitted evidence, rather than creating new conclusions on rebuild. Changed binaries require fresh review.

Validation: the full repository suite passed 91 tests and 83 subtests; six optional Ghidra checks were skipped because `GHIDRA_HOME` was unset. Five new regression tests exercise real multi-file builds at all levels, complete failure accounting, unresolved truth, stale review rejection, invalid instruction evidence, missing bound evidence, code/data tampering and independent rebuilds. Imported-source preservation verification also passed.

A separate clean workspace reproduced all 16 reference binaries, all 32 derivatives, instruction/function inventories and private disassembly/DWARF evidence byte for byte. The saved oracle validated unchanged against those independently built artifacts. Evidence capture passes relative artifact paths to binutils so workspace paths do not change the disassembly header. See [clean rebuild evidence](../../redesign/provenance/phase3-rebuild.json). Raw commands and dependency paths remain workspace-specific provenance and are not claimed to be identical.

Phase 3 acceptance requires complete pilot inventory, code/data-equivalent symbol partners, debug-free analysis artifacts, and explicit private dispositions for all builds. Phase 4 must implement public multi-function context selection and audit it against this private evidence without exposing the evidence to either predictor. Phase 3 does not establish analyzer coverage, context budgets, classification accuracy, method lock or final freeze.
