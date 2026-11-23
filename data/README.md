# Study inputs and sources

| Directory | Contents |
|---|---|
| `sources/` | Original C sources, selection/provenance records, configurations and the 32 public pilot bundle fixtures used by tests |
| `parent-study/` | The earlier `final-v2-context12288` campaign, including all original source inputs, binaries, judgments and results |
| `representation/inputs/` | Accepted final study metadata, public bundles and private evaluation ledger |
| `representation/views/` | The 480 accepted assembly/decompilation/combined views and their line maps |
| `representation/pilot/` | Self-contained accepted pilot inputs, projections and selection metadata |

Inner dataset paths are preserved. For example, the source fixture workspace keeps
`config.json`, `corpus/` and `data/pilot/records/` together because its manifests use
those relative paths. The code's default corpus workspace is `data/sources`; the
default parent for input preparation is `data/parent-study`. Explicit CLI arguments
take precedence. The original workspace string in stored protocol metadata is a
dated provenance field, rather than the current default filesystem location.

Only the small `sources/` fixtures and this guide are included by the source-control
ignore rules. The parent and completed-study datasets remain local research data;
they are not included in Python wheels. See the
[data guide](../documentation/llm-redesign/data_locations.md) for current commands.
