# Redesign corpus

`manifest.json` assigns the two pilot pairs and reserves ten unassigned final slots. `pilot_selection.json` records the source review, selected paths, earlier-flow reasoning, and excluded heap-family candidate.

`upstream/` contains exact read-only archive copies. `pairs/` contains neutral testcase units and minimal drivers; `support/` preserves renamed Juliet support code. `private/` contains identifier maps, transformation counts, hashes, and unified diffs. Original labels and these private maps must never become analyzer context.

Run `python -m redesign.pipeline.import_juliet verify` from the repository root to check the import. Run `python -m redesign.pipeline.validate_sources` for compiler and sanitizer validation. Use the importer with the pinned archive to reproduce files; do not hand-edit testcase logic or select final cases before method lock.
