# R1 shared serialization and artifact interfaces

Completed November 22, 2026, America/New_York. R1 passes under the existing import paths. Shared JSON formats, paths, hashing, create-once publication and archive primitives now live in `redesign/common/`. The full offline suite passes 500 tests, and saved requests, journals, aggregates, analysis exports and the original input archive retain their exact bytes. The [R0 release](refactor_r0_report.md) remains the source for historical method verification.

## Shared interfaces

[`serialization.py`](../../src/optimization_vuln_analysis/common/serialization.py) names the formats that previously had similar helper names across the two pipeline packages:

| Profile | Return type | Encoding and final newline |
|---|---|---|
| `request_json` | Unicode text | Compact sorted JSON, no final newline; transport encodes UTF-8 |
| `canonical_json` | Unicode text | Compact sorted JSON, one final LF |
| `journal_json` | ASCII text | Compact sorted JSON with Unicode escapes, one final LF |
| `report_json` | Bytes | Canonical UTF-8 JSON, one final LF |
| `inventory_json` | Unicode text | Sorted JSON with two-space indentation, one final LF |

`compact_json` supplies compact text for embedded report fields. All profiles reject nonfinite values. `strict_json` and `read_json` preserve duplicate-key rejection, nonfinite-constant rejection and UTF-8 input. Journals preserve unpaired surrogates through escaping; canonical UTF-8 output continues to reject them instead of repairing content. CSV line endings and figure serialization remain in reporting.

[`artifacts.py`](../../src/optimization_vuln_analysis/common/artifacts.py) supplies `digest`, `bytes_digest`, `local_path`, `plain_file`, `file_inventory`, `create_once`, `publish_bytes`, `write_archive` and `archive_members`. These helpers import only the standard library and the common precondition helper.

`create_once` writes a temporary file, flushes and syncs it, links the completed file without replacing an existing destination, then syncs the containing directory. Its default temporary prefix remains `.pending-`. Caught exceptions remove the temporary file; process interruption can leave it as uncommitted evidence. The primitive never adopts an orphan. Study code retains journal selection, read-only permissions and recovery rules.

Archive primitives retain sorted regular-file membership, PAX format, zero timestamps, fixed permissions, empty gzip filename and duplicate/type/path checks. Freeze still owns manifest validation, component bindings, destination overlap checks, detached identities and publication of the completion marker last.

## Adapted consumers and compatibility

Existing interfaces remain available through aliases or thin adapters: inventory parsing/path/hash exports, `inventory.encode`, `bundles.canonical`, root transport `canonical_json`, runtime `digest` and `write_new`, representation inventory `plain_file`, and freeze inventory/hash helpers. The root transport's existing `canonical_json` name continues to mean the request format without a trailing newline.

The representation runner uses the journal profile while preserving dispatch ordering, raw response retention and no-retry recovery. Reporting uses the report profile and shared inventories/hashes. Its binary file writer now also uses atomic create-once publication and directory synchronization; saved CSV/JSON/PNG/SVG bytes are unchanged.

The legacy pilot runner's explicit method inventory now includes all three common source files. Three added regression cases confirm that changing any of those identities blocks dispatch. The representation study's transitive dependency inventory discovers the common files automatically.

`release.py` and the published R0 standalone verifiers retain their embedded primitives. This preserves their ability to restore and verify evidence without importing the active repository. They were not changed to depend on `redesign/common/`.

## Verification

The [full regression receipt](../../artifacts/history/redesign/build/refactor/r1-v1/regression.json) records **500 tests passed in 483.89 seconds**, with zero failures, errors or skips. Tested source/resource bytes stayed unchanged during the run. The [36 common-helper checks](../../tests/test_common_artifacts.py) cover explicit byte formats, strict JSON, surrogate journals, file/directory synchronization order, collision handling, caught failures, real process interruption, orphan preservation, path/symlink boundaries, nonregular files, binary archives, metadata and import independence. Existing corruption, archive restoration, dispatch interruption, ownership and recovery checks also pass.

The [compatibility receipt](../../artifacts/history/redesign/build/refactor/r1-v1/compatibility.json) records the refactored code's comparison against the preserved completed study:

| Evidence | Result |
|---|---|
| Projected views | 480 verify against saved projection bytes |
| Request bodies | All 1,440 reconstruct byte for byte |
| Dispatch, response and terminal journals | All 4,248 serialize byte for byte |
| Saved decoding and aggregation | 1,440 terminal slots and 480 aggregates agree exactly |
| Evaluation and analysis exports | All 28 JSON/CSV/PNG/SVG outputs regenerate byte for byte |
| Phase 7 input archive | Recreated archive has the original SHA-256 `f711f9bd61c9aea0f82812ec1103c3841f08bc5af3ac00bcf66d1f64fd9bb7d5` |
| Protected evidence | All 46,291 inventoried files retain their hashes |

The resulting terminal counts remain 1,382 valid, six length-limited, 16 schema-invalid and 36 blocked slots. Evaluation retains SHA-256 `08ad9f8f88b8a6682f49cdfd172572be1a54276d49ccb5167555e2a270b57f24`. The comparison disabled transport and runtime access and made zero generation requests.

Separately, the [saved R0 method replay](../../artifacts/history/redesign/build/refactor/r1-v1/r0-saved-method-replay.json) again regenerates all 28 outputs using only its 22 saved local modules and matching environment outside the repository. Network/process/runtime access and original-workspace reads remain blocked. The preserved R0 completion receipt and its bound receipts also retain their identities.

## Source identity and continuation

The working freeze source closure now contains 24 files and reporting contains 25, compared with the original 21 and 22. The Python/package environment, requirements and protocol resources are unchanged. New code and dependency hashes are recorded separately in the R1 receipts and tested-source snapshot; no old manifest or frozen source was rewritten.

The historical freeze guard correctly rejects the refactored working method as a different source identity. Historical verification continues through R0's saved source and standalone replay command. Behavioral compatibility was checked through the current read-only projection/execution verifier, scorer and renderer, without bypassing or weakening the source guard.

The [completion receipt](../../artifacts/history/redesign/build/refactor/r1-v1/completion.json) binds regression, compatibility, historical replay, source and preservation evidence. No existing evidence was moved or deleted, and no files were staged or committed. Continue with R2's separation of inference primitives from protocol settings; package relocation remains R5.
