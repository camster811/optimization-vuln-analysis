# Campaigns

Versioned experiment workspaces and complete archives.

- [gcc-abi-v2/](gcc-abi-v2/README.md): workspace for the completed corrected campaign.
- `gcc-abi-v2.tar.gz`: complete corrected campaign archive.
- `windows-abi-v1.tar.gz`: original campaign with the incorrect Windows ABI.
- Matching `.json` files: archive hashes and campaign metadata.

Use the workspace to inspect results and run verification. Keep the archives
unchanged. To restore one, compare its SHA-256 with its matching JSON file and
extract into a fresh directory. Run from this folder:

```bash
sha256sum gcc-abi-v2.tar.gz
mkdir /tmp/gcc-abi-v2-review
tar -xzf gcc-abi-v2.tar.gz -C /tmp/gcc-abi-v2-review
```

To start a new version, activate the repository's Python environment and run
from this folder:

```bash
python ../pipeline/campaign.py prepare --destination new-version
GHIDRA_HOME=/path/to/ghidra python ../pipeline/campaign.py extract --destination new-version
```

In the new workspace, capture runtime evidence and create its input freeze
before running either analyzer.
