# R5 package and test-support consolidation

Completed November 23, 2026, America/New_York. Active code now lives under
`src/optimization_vuln_analysis/`. The installed package finds its protocol resources
outside the checkout. Unused legacy orchestration is retired, and tests share plain
builders without importing test modules. No model, full suite or result regeneration ran.

## Source layout

| Location | Responsibility |
|---|---|
| `common/` | JSON byte profiles, artifacts, metric arithmetic, installed resources and provenance |
| `inference/` | Transport, attempts/voting, explicit runtime, launch and process identity |
| `inputs/` | Public bundle validation, metadata checks, historical corpus and parent adapters |
| `studies/representation/` | Study inventory, projection, response decoding, execution/replay, scoring, pilot, freeze, reporting and release |
| `tests/support/`, `tests/conftest.py` | Plain synthetic builders and shared pytest fixtures |
| `src/redesign/` | Thin aliases for the existing study commands/imports and corpus inventory command |

Removed the old `redesign.pipeline` bundle runner, decoder/settings module and
runtime facade, plus their obsolete test harness. Their only remaining active
consumers were regression tests. Shared budget and live-identity assertions now use
the inference primitives directly. The active representation tests retain stateless
requests, strict envelopes, response dispositions, voting and no-retry recovery;
public bundle tests retain instruction-address validation. A focused assertion also
checks that bundle evidence rejects representation line references.

Shared helpers are imported directly from `common`, avoiding incidental exports
through study inventory. No upward imports remain in `common`, `inference` or `inputs`.
No test imports another test module, and no fixture `__wrapped__` calls remain.
New freeze receipts bind all test Python files, including `conftest.py` and support
builders, rather than only top-level `test_*.py` files.

## Packaging and historical boundaries

`pyproject.toml` uses setuptools and the existing argparse functions. Runtime pins
remain exactly `jsonschema==4.25.1`, `matplotlib==3.10.7`, `numpy==2.3.5` and
`requests==2.32.5`. The packaged requirements file is the dependency source;
root `requirements.txt` delegates to it. The wheel includes all five unchanged
protocol resources and excludes campaign data, private judgments and result files.

Resources use `importlib.resources`. Historical corpus defaults are relative to the
caller; accepted parent/pilot paths remain explicit CLI inputs. New sealing requires
checkout tests/documentation in the working directory. Provenance records the new
logical package paths and packaged requirements location, while saved snapshots
without that location field continue to verify with their original requirements path.

The current standalone release tool recognizes either saved source layout. Old
release helpers, manifests, archives, publications and source snapshots were left
unchanged. Existing study commands remain available after installation through
`redesign.extensions.representation_study`; `redesign.pipeline.inventory` also
delegates to the installed implementation. These aliases do not preserve an old
source hash. Historical environment/source guards still require the saved method.

## Validation

- **35 critical cases passed** for provenance, transport/identity, interrupted
  dispatch recovery and the freeze method/environment guard.
- **13 final cases passed** after resolving direct common imports: provenance,
  bundle evidence, transport, copied pilot preparation, parent relocation and
  historical release verification. Six repeat provenance cases; **42 distinct
  critical cases** passed across the focused runs.
- Collected **473 offline cases** and one separately selected historical-evidence
  case. The default pytest job excludes the evidence marker. No full-suite run.
- Built and installed the final wheel in `/tmp/r5-installed-env`, with copied
  pinned dependencies and no changes to the historical environment. From `/tmp`,
  isolated Python loaded installed schemas/prompts, validated synthetic bundles,
  constructed and decoded all three representations, and captured/verified a
  source snapshot. All wheel source/resource members match the final checkout.
- All **16** canonical/compatibility command help invocations passed outside the
  checkout; the installed legacy corpus command also generated the 32-observation
  pilot inventory from an explicit input path.
- The archived R0 standalone helper independently verified the accepted completed
  release manifest and member hashes. Full historical result regeneration was
  not repeated. All **46,291** protected historical files remain byte-identical;
  the existing installed-distribution inventory also remains unchanged.

The [repository guide](../../README.md) gives installation and offline/evidence
commands. Detailed checks, a source snapshot, the built wheel and new method
inventories are recorded in
[`redesign/build/refactor/r5-v1/`](../../artifacts/history/redesign/build/refactor/r5-v1).
The working freeze/reporting closures contain **28/29 Python files**, respectively,
plus the same five protocol resources and pinned requirements. These identities
are separate from the original Phase 7/9 methods. No staging or commits were performed.
