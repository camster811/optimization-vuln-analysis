# Phase 2: Juliet pilot import

Implemented October 19, 2026. No final predictions or final-case selection occurred.

## Source selection

| Pilot | Family rank | Original flow | Selected safe path | Reasoning |
|---|---:|---|---|---|
| pilot-01, CWE-121 | 1 | CWE193_char_declare_loop, 41 | goodG2B | Destination stack buffer is passed to a helper that copies an eleven-byte terminated string |
| pilot-02, CWE-122 | 2 | c_CWE129_large, 21 | goodB2G1 | Index passes to a helper that allocates a ten-int heap buffer and conditionally writes it |

The first heap candidate, `c_src_char_cpy`, allocates its source on the heap but overflows a stack `dest[50]` array. It was excluded using source-level CWE eligibility, before building or invoking predictors. Its original evidence files and the decision are preserved. No sample was excluded because optimization removed a write or a method struggled with it.

The helper-flow rule counts transfer of a buffer, extent, or index. Generic output calls and functions that only return a control constant do not satisfy that rule by themselves. Earlier flows and the chosen single safe paths are documented in the selection ledger. Both selected families are permanently development-only. Review was performed by Codex, not an independent human adjudicator.

## Preservation and harness

All 9,562 candidate C files and all 184 family fingerprints match the pinned archive and the Phase 0 source inventory. Seven exact original files are retained read-only: two pilot units, three support files, and two exclusion-evidence files.

The sanitizer tokenizes C and permits only explicit identifier renaming, include-filename renaming, comment removal, and allowlisted diagnostic-message replacement. Data literals, allocation sizes, operators, types, loops, conditions, calls, and qualifiers remain unchanged. Unsupported lexical forms fail closed. Every transformed file has a token comparison, hash record, and human-readable diff. The lexer is a bounded importer, not a complete C preprocessor or a formal semantic-equivalence proof.

Each external driver includes the original-shaped testcase translation unit and directly calls one selected entry. This makes the original static safe path callable without removing `static`, editing its body, or invoking an aggregate wrapper containing multiple safe paths. Renamed original omit macros select vulnerable versus safe sections. Both selected entries and their primary helpers receive the same neutral role names across variants. Uninvoked original safe paths remain present; Phase 4 must export only the selected application scope.

No new volatile, inlining controls, preservation barriers, bound changes, library substitutions, or output-call rewrites were introduced. The two selected flows contain their testcase helpers in the same source file; support code is a separate translation unit. This pilot does not claim to validate a testcase chain spanning several source files.

## Validation evidence

The versioned summary is `../../redesign/provenance/phase2-validation.json`; raw compiler and sanitizer logs are reproducible under `../../redesign/build/phase2-validation/`.

- Sixteen paired comparisons cover both pilots, both variants, and O0/O1/O2/O3. All compared object executable sections are byte-identical after metadata sanitization.
- Named relocations agree after identifier normalization. One O0 heap-safe object has diagnostic-string replacement/layout differences; the checker resolves the affected string references and verifies their bytes rather than ignoring relocated addresses.
- Derived retained and stripped artifacts preserve executable text. Both sanitized symbol treatments pass the known-label scan and contain no debug sections. This is not a guarantee against every possible statistical clue.
- Eight separate O0 AddressSanitizer runs cover original and sanitized forms of both variants. Both vulnerable forms report the expected stack/heap overflow type; all safe forms complete without an ASan error, with identical original/sanitized stdout.
- Regression checks reject changed bounds, types, qualifiers, statements, unapproved literal changes, incomplete lexical forms, unexplained relocations, and altered upstream bytes.
- Final full-suite check: 86 tests and 83 subtests passed; six optional real-Ghidra checks were skipped because `GHIDRA_HOME` was unset. Imported-source verification, the 29-file predecessor snapshot, and both historical campaign archive hashes passed verification.

These checks establish source-preservation evidence, not optimized binary ground truth. The Phase 3 campaign builds, mapping, and adjudication remain pending. Public record generation and record-level leakage checks belong to Phase 4 and have not run. The ten final slots remain unassigned.
