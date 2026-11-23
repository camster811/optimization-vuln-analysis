# R0 preservation and regression baseline

Completed November 22, 2026, America/New_York. R0 passes: the completed representation study has a separate internal release, a verified fresh restore and a byte-exact replay using its saved method. The existing predictor, decoder, runner, scorer, protocol and environment remain unchanged. R1 can proceed against this preserved baseline. Manuscript and research-documentation work from study Phase 10 remain separate.

## Accepted release

The accepted publication is [`representation-v1-context12288-final-v1-completed-r0-v2`](../../artifacts/history/redesign/experiments/llm-representation-v1/representation-v1-context12288-final-v1-completed-r0-v2). Its adjacent [archive](../../artifacts/history/redesign/experiments/llm-representation-v1/representation-v1-context12288-final-v1-completed-r0-v2.tar.gz), [detached manifest](../../artifacts/history/redesign/experiments/llm-representation-v1/representation-v1-context12288-final-v1-completed-r0-v2.json) and [standalone verifier](../../artifacts/history/redesign/experiments/llm-representation-v1/representation-v1-context12288-final-v1-completed-r0-v2-reproduce.py) support restoration after the active source has changed. The archive is 35,286,052 bytes, with 9,819 bound files plus `release.json`.

This release is internal. It includes private judgments, pilot fixtures, saved model answers/reasoning and local provenance. It was created locally; no external service received its contents.

| Release path | Role |
|---|---|
| `frozen/` | Unchanged initial Phase 7 publication, including its pending execution snapshot, inputs, views, pilot, method and contracts |
| `execution/` | Completed final execution with all exact requests, dispatches, responses, terminal records and runtime events |
| `analysis/` | Accepted Phase 9 analysis v2 and its saved 22-file local source closure |
| `baseline/workspace/` | 122-file snapshot of the pre-R0 source, resources, tests, current documentation and pilot fixtures |
| `baseline/` | File classification, source-control review, fresh regression receipt/log/JUnit, environment evidence and release-tool checks |
| `baseline/publication-archives/` | Original Phase 7 input archive and detached manifest, preserved and independently verified |
| `baseline/engineering-evidence/` | Existing engineering receipts and Phase 6–8 runtime evidence |
| `baseline-identities.json` | Exact request, attempt, terminal-record, aggregate, evaluation, bootstrap and analysis-output identities |
| `reproduce.py`, `environment-requirements.txt` | Standalone packaging/replay tool and exact installed-distribution pins |

The first R0 candidate is preserved as `completed-r0-v1` and is excluded from acceptance. Its replay wrapper raised the wrong exception when denying font-discovery subprocesses. V2 retains process denial and lets Matplotlib use its local-font fallback. The frozen study source and scientific outputs were unchanged by that correction.

## Source and evidence inventory

The [workspace inventory](../../artifacts/history/redesign/build/refactor/r0-v1/workspace-inventory.json) records 26,794 file hashes and classifies source/resources, documentation, tests, public pilot fixtures, private pilot fixtures, generated workspaces and historical/publication evidence. Its exclusions cover Git internals, the virtual environment, hidden directories, caches and the R0 output directory. The environment is recorded separately.

The [source-control review](../../artifacts/history/redesign/build/refactor/r0-v1/source-control-review.json) assigns a disposition to each of 3,634 modified or untracked files. Of these, 3,565 are internal evidence, two are private pilot fixtures and 67 are source/documentation/public-fixture candidates. No files were staged or committed. Private files were included explicitly in the internal preservation package, with no automatic source-add operation.

Use the active checkout for implementation and the offline tests. Use `baseline/workspace/` to recover the exact pre-refactor checkout contents, including required files that were untracked. A Git checkout alone does not supply the separately preserved campaigns and publications. Historical replay uses `analysis/method/source/` from the evidence package; it does not depend on the refactored checkout.

The [preservation check](../../artifacts/history/redesign/build/refactor/r0-preservation-v1.json) found all 26,794 inventoried originals unchanged after sealing, including 26,648 generated/evidence files. Subsequent maintenance edits update five navigation/planning documents; their earlier bytes remain in the source snapshot. Existing production sources, tests, protocol resources, publications, archives and final execution remain unchanged. Nothing was deleted or offloaded.

## Regression and independent replay

The fresh pre-change suite passed **443 tests in 482.66 seconds**, with zero failures, errors or skips. All 122 snapshotted source/resource/fixture files retained their hashes during the run. The [regression receipt](../../artifacts/history/redesign/build/refactor/r0-v1/regression.json) binds the source list, environment, JUnit and log.

The new [release tool](../../artifacts/history/redesign/build/refactor/r5-v1/source-before/redesign/extensions/representation_study/release.py) uses only the standard library and does not enter the frozen method's import closure. Its [18 checks](../../artifacts/history/redesign/build/refactor/r5-v1/source-before/tests/test_representation_release.py) passed, covering deterministic archive bytes, restoration, changed/missing/extra files, unsafe paths, duplicate and nonregular archive members, manifest identity, strict JSON, failed baselines, interpreter isolation and rendering with a fresh font cache while subprocesses are denied. This targeted receipt is separate from the pre-change 443-test baseline.

The accepted archive was restored to a new directory outside the repository. A separate copy of the matching virtual environment supplied Python 3.14.4 and the same 26 installed distributions. The child interpreter used isolated mode and disabled bytecode writes. Network connections, child processes, inference/runtime calls and reads under the original repository were blocked. Every imported local module came from the restored `analysis/method/source/`.

The [replay receipt](../../artifacts/history/redesign/build/refactor/r0-replay-v2.json) confirms:

- All 28 JSON/CSV/PNG/SVG analysis and evidence outputs regenerate byte for byte, including evaluation and figures.
- All 1,440 terminal slots and 480 aggregates verify: 1,382 valid, six length-limited, 16 schema-invalid and 36 blocked slots.
- The identity ledger binds 1,440 requests, 1,404 raw response records and saved attempts, 1,440 terminal records and 480 aggregates.
- The copied evidence remains unchanged and zero generation requests are sent.
- The original Phase 7 archive verifies against its existing detached identity.

The [historical-release check](../../artifacts/history/redesign/build/refactor/r0-historical-releases-v1.json) also verifies the parent input archive and all 4,111 bound files, plus the parent results archive and all 11,511 bound files, against their existing manifests.

The Python interpreter, installed packages, model weights and server binaries are external dependencies. Package versions and Python/system evidence are preserved; model/server identities remain in the frozen policy/runtime records. Saved-result replay requires the matching Python environment and requires no model, server, compiler or Ghidra. The independent check reused copied installed packages; it did not test downloading a new environment from a package registry.

## Restore and verify

The standalone verifier remains usable without the repository's Python packages. Run these commands from the repository root, choosing a fresh restore directory:

```sh
r0_publication=redesign/experiments/llm-representation-v1
r0_name=representation-v1-context12288-final-v1-completed-r0-v2

python3 -I -B "$r0_publication/$r0_name-reproduce.py" restore \
  --archive "$r0_publication/$r0_name.tar.gz" \
  --detached "$r0_publication/$r0_name.json" \
  --detached-sha256 4a2b89c2b08bbc70c7a2e9e9a1fb95843de43df80fe851fa7ee3d86fa5b5a9cc \
  --directory /tmp/representation-r0-fresh
```

With a matching environment, replay the restored method and write the receipt outside the evidence directory:

```sh
/path/to/matching/python -I -B /tmp/representation-r0-fresh/reproduce.py replay \
  --directory /tmp/representation-r0-fresh \
  --python /path/to/matching/python \
  --forbidden-root "$PWD" \
  --manifest-sha256 9d3638046d9620127316c2023eaff985289a868f7066dca08449618b2a850750 \
  --output /tmp/representation-r0-replay.json
```

Use `verify` for file/binding checks and `verify-archive` for archive membership/hashes; `replay` additionally regenerates the scientific outputs. These commands preserve evidence and refuse existing restore/receipt destinations. Keep the historical environment available separately from future refactor installations.

## Recorded identities

| Artifact | SHA-256 |
|---|---|
| Completed release `release.json` | `9d3638046d9620127316c2023eaff985289a868f7066dca08449618b2a850750` |
| Completed release archive | `3e03cac5f2f0088c897391883d2ce458ca666506c46d944ae32e54f98cf63062` |
| Detached manifest | `4a2b89c2b08bbc70c7a2e9e9a1fb95843de43df80fe851fa7ee3d86fa5b5a9cc` |
| Standalone verifier | `0d6a034fdd1f0660d75cd6d8a822b3cf3419689233ef124a5f5a618dbe268a20` |
| Baseline identities ledger | `0f0ac803187690359c36c5f409e0fe858210596d17a3299e17c25779b6ec734c` |
| Independent replay receipt | `39f4bc542853df5b5c2de3d23cfb3b9584c4c3d7209b9997d739e74f9545dd81` |

The final [R0 completion receipt](../../artifacts/history/redesign/build/refactor/r0-completion-v2.json) binds the release, regression, restoration, replay, historical-release and preservation checks. These local hashes establish content agreement, without claiming an external timestamp. Continue with R1's shared serialization/artifact interfaces under the existing import paths.
