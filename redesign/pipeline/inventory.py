"""Validate declared inputs and generate the complete planned experiment matrix.

Run from the repository root: python -m redesign.pipeline.inventory --split final
This does not compile sources, export records, freeze a campaign, or run inference.
"""

import argparse
from collections import Counter
import hashlib
from itertools import product
import json
from pathlib import Path, PurePosixPath
import re


ROOT = Path(__file__).resolve().parents[1]
IDENTIFIER = re.compile(r"[a-z][a-z0-9_-]*\Z")
LABELS = {"vulnerable_CWE-121", "vulnerable_CWE-122", "not_vulnerable", "uncertain"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def strict_json(text):
    def unique(items):
        result = {}
        for key, value in items:
            require(key not in result, f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    def invalid(value):
        raise ValueError(f"Nonfinite JSON number: {value}")

    return json.loads(text, object_pairs_hook=unique, parse_constant=invalid)


def read_json(path):
    return strict_json(Path(path).read_text(encoding="utf-8"))


def encode(value):
    return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def local_path(root, name):
    require(isinstance(name, str) and name, "Missing relative path")
    path = PurePosixPath(name)
    require(not path.is_absolute() and '..' not in path.parts and '\\' not in name
            and ':' not in name and path.as_posix() == name, f"Unsafe path: {name}")
    result = root / name
    require(result.resolve().is_relative_to(root.resolve()), f"External path: {name}")
    return result


def validate_config(config):
    require(config.get('schema_version') == 2, 'Expected redesign configuration schema 2')
    require(IDENTIFIER.fullmatch(config.get('campaign_id', '')), 'Invalid campaign ID')
    matrix = config['matrix']
    for field in ('variants', 'optimizations', 'symbols'):
        values = matrix[field]
        require(isinstance(values, list) and values and len(values) == len(set(values)),
                f'Empty or duplicate matrix dimension: {field}')
    require(set(matrix['variants']) == {'vulnerable', 'safe'}, 'Expected vulnerable/safe paths')
    require(set(matrix['optimizations']) <= {'O0', 'O1', 'O2', 'O3'}, 'Unknown optimization')
    require(set(matrix['symbols']) == {'retained', 'stripped'}, 'Expected both symbol treatments')
    require(config['compiler']['optimizations'] == matrix['optimizations'],
            'Compiler and matrix optimization levels disagree')
    seeds = config['inference']['seeds']
    require(isinstance(seeds, list) and seeds and all(type(s) is int and s >= 0 for s in seeds)
            and len(set(seeds)) == len(seeds), 'Invalid repetition seeds')
    require(type(config['inference']['schedule_seed']) is int, 'Invalid schedule seed')
    require(set(config['splits']) == {'pilot', 'final'}, 'Expected pilot/final quotas')
    for quotas in config['splits'].values():
        require(set(quotas) == {'CWE-121', 'CWE-122'}, 'Expected both CWE quotas')
        for structures in quotas.values():
            require(set(structures) == {'intraprocedural', 'interprocedural'}, 'Invalid structures')
            require(all(type(n) is int and n >= 0 for n in structures.values()), 'Invalid pair quota')
        require(sum(sum(q.values()) for q in quotas.values()) > 0, 'Empty split')
    return config


def validate_manifest(config, manifest, root, require_assigned_split=None):
    require(manifest.get('schema_version') == 2, 'Expected corpus manifest schema 2')
    pairs = manifest['pairs']
    require(isinstance(pairs, list), 'Pairs must be a list')
    ids, families, counts = set(), set(), Counter()
    for pair in pairs:
        identifier = pair['pair_id']
        require(IDENTIFIER.fullmatch(identifier) and identifier not in ids, 'Invalid/duplicate pair ID')
        ids.add(identifier)
        key = (pair['split'], pair['cwe'], pair['structure'])
        require(key[0] in config['splits'] and key[1] in config['splits'][key[0]]
                and key[2] in config['splits'][key[0]][key[1]], 'Unknown corpus stratum')
        counts[key] += 1
        require(pair['status'] in {'unassigned', 'assigned'}, 'Unknown assignment status')
        if pair['status'] == 'unassigned':
            require(pair['split'] != require_assigned_split, f'Unassigned pair: {identifier}')
            require(set(pair) == {'pair_id', 'split', 'cwe', 'structure', 'status'},
                    'Unassigned pairs must not contain apparent source assignments')
            continue
        family = pair['family_id']
        require(isinstance(family, str) and family and family not in families,
                'Missing or reused family across pilot/final')
        families.add(family)
        require(isinstance(pair['upstream_case_id'], str) and pair['upstream_case_id'],
                'Missing upstream case identity')
        require(set(pair['entries']) == set(config['matrix']['variants']), 'Missing variant entry')
        require(all(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', v)
                    for v in pair['entries'].values()), 'Invalid entry symbol')
        sources = pair['sources']
        require(isinstance(sources, list) and sources and len(set(sources)) == len(sources),
                'Missing/duplicate source files')
        dependencies = pair['support_sources']
        require(isinstance(dependencies, list) and len(set(dependencies)) == len(dependencies)
                and not set(sources) & set(dependencies), 'Duplicate support sources')
        headers = pair.get('headers', [])
        require(isinstance(headers, list) and len(set(headers)) == len(headers)
                and all(PurePosixPath(p).suffix == '.h' for p in headers), 'Invalid support headers')
        units = pair.get('translation_units', sources)
        require(isinstance(units, list) and units and len(set(units)) == len(units)
                and set(units) <= set(sources), 'Invalid translation unit selection')
        for directory in pair.get('include_dirs', []):
            require(local_path(root, directory).is_dir(), 'Missing include directory')
        hashes = pair['file_sha256']
        files = sources + dependencies + headers + [pair['sanitization_manifest'], pair['selection_record']]
        require(set(hashes) == set(files), 'Source/provenance hash inventory mismatch')
        for name in files:
            path = local_path(root, name)
            require(path.is_file() and digest(path) == hashes[name], f'Missing/changed input: {name}')
        require(all(PurePosixPath(p).suffix == '.c' for p in sources + dependencies),
                'Expected C translation units')
        require(isinstance(pair['variant_selection'], dict)
                and set(pair['variant_selection']) == set(config['matrix']['variants']),
                'Missing variant selection recipes')
        for recipe in pair['variant_selection'].values():
            require(set(recipe) == {'defines', 'driver_sources'}, 'Invalid variant recipe')
            require(isinstance(recipe['defines'], list)
                    and all(isinstance(v, str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(=[A-Za-z0-9_]+)?', v)
                            for v in recipe['defines']), 'Invalid macro selection')
            require(isinstance(recipe['driver_sources'], list)
                    and set(recipe['driver_sources']) <= set(sources), 'Unknown driver source')
    expected = Counter({(split, cwe, structure): n
                        for split, quotas in config['splits'].items()
                        for cwe, structures in quotas.items() for structure, n in structures.items() if n})
    require(counts == expected, f'Corpus quotas disagree: expected {dict(expected)}, got {dict(counts)}')
    return sorted(pairs, key=lambda p: p['pair_id'])


def generate(config, manifest, root=ROOT, split='final', require_assigned=False):
    validate_config(config)
    pairs = validate_manifest(config, manifest, root, split if require_assigned else None)
    require(split in config['splits'], 'Unknown split')
    matrix = config['matrix']
    builds, observations, slots = [], [], []
    for pair in pairs:
        if pair['split'] != split:
            continue
        for variant, opt in product(matrix['variants'], matrix['optimizations']):
            # IDs are opaque to predictors; this private mapping is not public model context.
            key = f"{config['campaign_id']}\n{pair['pair_id']}\n{variant}\n{opt}"
            build_id = 'b' + hashlib.sha256(key.encode()).hexdigest()[:24]
            builds.append({'build_id': build_id, 'pair_id': pair['pair_id'], 'variant': variant,
                           'optimization': opt, 'assignment': pair['status'],
                           'reference_path': f'build/{split}/oracle/{build_id}'})
            for symbols in matrix['symbols']:
                obs_id = 'r' + hashlib.sha256(f'{key}\n{symbols}'.encode()).hexdigest()[:24]
                observations.append({'observation_id': obs_id, 'build_id': build_id,
                                     'pair_id': pair['pair_id'], 'variant': variant,
                                     'optimization': opt, 'symbols': symbols,
                                     'record_path': f'data/{split}/records/{obs_id}.json',
                                     'analysis_path': f'build/{split}/{symbols}/{build_id}'})
                for repetition, seed in enumerate(config['inference']['seeds'], 1):
                    order = hashlib.sha256(
                        f"{config['inference']['schedule_seed']}\n{obs_id}\n{repetition}".encode()).hexdigest()
                    slots.append({'observation_id': obs_id, 'repetition': repetition,
                                  'seed': seed, 'order_sha256': order})
    require(len({b['build_id'] for b in builds}) == len(builds), 'Build ID collision')
    require(len({o['observation_id'] for o in observations}) == len(observations), 'Observation ID collision')
    return {'schema_version': 2, 'campaign_id': config['campaign_id'], 'split': split,
            'status': 'planned_not_executed',
            'dimensions': {**matrix, 'cwe': list(config['splits'][split])},
            'counts': {'pairs': sum(p['split'] == split for p in pairs),
                       'reference_builds': len(builds), 'observations': len(observations),
                       'inference_slots': len(slots)},
            'builds': builds, 'observations': observations,
            'inference_slots': sorted(slots, key=lambda s: (s['order_sha256'], s['observation_id'], s['repetition']))}


def check_cells(expected, actual, key):
    """Reject omissions, duplicates, additions, or altered matrix metadata."""
    keys = [row[key] for row in actual]
    require(len(keys) == len(set(keys)), f'Duplicate {key}')
    require({row[key]: row for row in expected} == {row[key]: row for row in actual},
            f'Missing, unexpected, or altered {key} cells')


def check_record_inventory(inventory, root):
    """Check the actual chosen directory, including unexpected files, before later freeze/inference."""
    expected = {row['record_path'] for row in inventory['observations']}
    directory = local_path(root, f"data/{inventory['split']}/records")
    actual = {p.relative_to(root).as_posix() for p in directory.rglob('*') if p.is_file()}
    require(actual == expected, 'Record inventory missing or unexpected files')
    for name in expected:
        path = local_path(root, name)
        require(not path.is_symlink(), 'Record symlinks are not allowed')
    return {name: digest(root / name) for name in sorted(expected)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, default=ROOT)
    parser.add_argument('--split', choices=('pilot', 'final'), default='pilot')
    parser.add_argument('--require-assigned', action='store_true')
    parser.add_argument('--write', action='store_true', help='Write deterministic planned inventory under build/')
    parser.add_argument('--check-plan', type=Path, help='Verify a saved plan against current declarations')
    args = parser.parse_args()
    root = args.workspace.resolve()
    result = generate(read_json(root / 'config.json'), read_json(root / 'corpus/manifest.json'),
                      root, args.split, args.require_assigned)
    if args.check_plan:
        require(read_json(args.check_plan) == result, 'Saved plan differs from declared matrix')
    if args.write:
        path = root / 'build' / args.split / 'planned_inventory.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(encode(result), encoding='utf-8')
    print(encode({'status': result['status'], 'counts': result['counts'], 'dimensions': result['dimensions']}), end='')


if __name__ == '__main__':
    main()
