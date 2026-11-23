# Historical artifacts

`history/redesign/` contains everything from the former `redesign/` directory that
is not a current input/source dataset or the accepted result/run. This includes
older phase workspaces, alternate analyses, archives, original protocol files,
maintenance reports, saved source copies and the former workspace README.

All files were preserved byte-for-byte. This is passive historical material,
separate from the active Python package and default tests; it adds no freeze,
restoration or automation workflow. Its old internal metadata remains unchanged.
The historical files are ignored by Git apart from this guide.

Use `data/` for current inputs/sources and `results/` for accepted results. The
[migration record](../documentation/llm-redesign/data_migration.md) maps former paths
to their new locations.
