#!/usr/bin/env python3
"""Prepare an isolated corrected campaign; never replace a predecessor's freeze."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def prepare(destination, root=ROOT):
    destination = Path(destination).resolve()
    if destination.exists():
        raise ValueError('Campaign destination already exists; use a new version')
    destination.mkdir(parents=True)
    for name in ('config.json', 'analysis_plan.md', 'requirements.txt', 'compile.sh'):
        shutil.copy2(root / name, destination / name)
    for name in ('pipeline', 'ghidra', 'llm', 'corpus', 'data/private',
                 'build/oracle', 'build/retained', 'build/stripped'):
        shutil.copytree(root / name, destination / name, ignore=shutil.ignore_patterns('__pycache__'))
    (destination / 'data/records').mkdir()
    (destination / 'results').mkdir()
    (destination / 'runtime').mkdir()
    metadata = {'campaign': destination.name, 'compiler_spec': 'gcc', 'baseline_revision': 3,
                'predecessor': 'windows-abi-v1',
                'status': 'prepared; extraction and new inference required',
                'interpretation': 'Post-review corrected pipeline; original final outcomes were inspected.'}
    (destination / 'campaign.json').write_text(json.dumps(metadata, indent=2) + '\n')
    return destination


def compare_exports(destination, root=ROOT):
    # Only the original 80 records have predecessor exports. The extension
    # occupies r0081-r0160 and is validated by extraction's full inventory check.
    differences = []
    decompilation_changed = []
    for index in range(1, 81):
        identifier = f'r{index:04d}'
        name = f'data/records/{identifier}.json'
        before, after = [json.loads((directory / name).read_text()) for directory in (root, destination)]
        if any(before[field] != after[field] for field in ('instructions', 'calls')):
            differences.append(identifier)
        if before['decompilation'] != after['decompilation']:
            decompilation_changed.append(identifier)
    result = {'observations': 160, 'predecessor_observations_compared': 80,
              'instructions_or_calls_changed': differences,
              'decompilation_changed': decompilation_changed}
    (destination / 'runtime/extraction_comparison.json').write_text(json.dumps(result, indent=2) + '\n')
    if differences:
        raise ValueError(f'Unexpected instruction/call changes: {differences}')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('prepare', 'extract'))
    parser.add_argument('--destination', type=Path, default=ROOT / 'campaigns/gcc-abi-v2')
    args = parser.parse_args()
    destination = args.destination.resolve()
    if args.command == 'prepare':
        prepare(destination)
    else:
        if (destination / 'data/input_freeze.json').exists():
            raise ValueError('Refusing extraction into an already frozen campaign')
        subprocess.run([sys.executable, str(destination / 'pipeline/extract.py'), '--split', 'final'], check=True)
        print(json.dumps(compare_exports(destination), indent=2))


if __name__ == '__main__':
    main()
