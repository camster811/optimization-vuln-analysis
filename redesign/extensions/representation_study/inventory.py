"""Bind a frozen parent and stage inputs; never compile, lift or request predictions."""
import argparse
import ast
from collections import Counter
import hashlib
from importlib import metadata, util
from pathlib import Path
import sys
import tarfile

from redesign.pipeline import bundles
from redesign.pipeline.inventory import (
    ROOT, IDENTIFIER, check_record_inventory, digest, generate,
    local_path, read_json, require, strict_json,
)
from redesign.pipeline.llm_runtime import write_new


POLICY = Path(__file__).with_name('policy.json')
REPO = ROOT.parent
PARENT_FILES = ('config.json', 'corpus/manifest.json', 'build/final/build-manifest.json',
                'corpus/private/final-oracle.json', 'build/final/dispositions.json',
                'schemas/bundle-v2.json')
MANIFEST = 'coordinator/manifest.json'
COUNT_FIELDS = ('families', 'reference_builds', 'observations', 'observation_condition_units', 'final_slots')


def identity(value):
    return hashlib.sha256(bundles.canonical(value).encode('utf-8')).hexdigest()


def policy_check(policy):
    require(policy['schema_version'] == 1 and policy['method_id'] == 'public-representation-llm-v1',
            'Unknown representation policy')
    for key in ('study_id', 'configuration_id'):
        require(IDENTIFIER.fullmatch(policy[key]), f'Invalid {key}')
    matrix = policy['matrix']
    require(matrix['representations'] == ['assembly', 'decompilation', 'combined'],
            'Expected three representation conditions')
    seeds = policy['llm']['seeds']
    require(len(seeds) == policy['llm']['repetitions'] == 3 and len(set(seeds)) == 3
            and all(type(s) is int and s >= 0 for s in seeds), 'Invalid repetition seeds')
    require(type(policy['schedule']['seed']) is int
            and policy['schedule']['seed'] == policy['llm']['schedule_seed'], 'Schedule seeds differ')
    return policy


def plain_file(root, name):
    path = local_path(root, name)
    require(path.is_file(), f'Missing input: {name}')
    require(all(not p.is_symlink() for p in (path, *path.parents) if p != root.parent),
            f'Symlink input: {name}')
    return path


def verify_parent(parent, policy):
    """Check every released file and archive member without extracting or executing it."""
    binding = policy['parent']
    freeze_path = plain_file(parent, binding['freeze_manifest'])
    require(digest(freeze_path) == binding['freeze_manifest_sha256'], 'Parent freeze changed')
    freeze = read_json(freeze_path)
    require(freeze['schema_version'] == 1 and freeze['freeze_id'] == binding['freeze_id']
            and freeze['status'] == 'frozen_before_predictions', 'Unexpected parent freeze')
    require(freeze['archive'] == binding['input_archive']
            and freeze['archive_sha256'] == binding['input_archive_sha256'], 'Parent archive binding differs')
    files = freeze['files']
    require(files and files[binding['llm_policy']] == binding['llm_policy_sha256'],
            'Parent policy binding differs')
    for name, expected in files.items():
        require(digest(plain_file(parent, name)) == expected, f'Changed parent input: {name}')
    archive = plain_file(parent, binding['input_archive'])
    require(digest(archive) == binding['input_archive_sha256'], 'Parent archive changed')
    seen = set()
    with tarfile.open(archive, 'r|gz') as stream:
        for member in stream:
            local_path(parent, member.name)
            require(member.isfile() and member.name in files and member.name not in seen,
                    f'Unexpected/duplicate/nonregular archive member: {member.name}')
            seen.add(member.name)
            with stream.extractfile(member) as content:
                require(hashlib.file_digest(content, 'sha256').hexdigest() == files[member.name],
                        f'Archive content differs: {member.name}')
    require(seen == set(files), 'Parent archive membership differs')
    return freeze


def _indexed(rows, key, expected=None):
    result = {row[key]: row for row in rows}
    require(len(result) == len(rows), f'Duplicate {key}')
    if expected is not None:
        require(set(result) == set(expected), f'Missing/unexpected {key}')
    return result


def conditions_and_slots(observations, policy):
    """Only public bundle identities and opaque IDs influence predictor scheduling."""
    conditions, slots = [], []
    for observation in sorted(observations, key=lambda r: r['observation_id']):
        obs = observation['observation_id']
        for representation in policy['matrix']['representations']:
            key = {'study_id': policy['study_id'], 'configuration_id': policy['configuration_id'],
                   'observation_id': obs, 'representation': representation,
                   'parent_bundle_sha256': observation['parent_bundle_sha256']}
            conditions.append({**key, 'condition_id': identity(key),
                               'bundle_path': observation['bundle_path'],
                               'view_path': f'public/views/{representation}/{obs}.json',
                               'aggregate_path': f'results/{representation}/{obs}.json'})
            for repetition, seed in enumerate(policy['llm']['seeds'], 1):
                block = f"{policy['schedule']['seed']}\n{obs}\n{repetition}"
                slot_key = {**key, 'repetition': repetition, 'seed': seed}
                slots.append({**slot_key, 'condition_id': identity(key), 'slot_id': identity(slot_key),
                              'slot_path': f'slots/{representation}/{obs}/{repetition}',
                              'block_order_sha256': hashlib.sha256(block.encode('utf-8')).hexdigest(),
                              'condition_order_sha256': hashlib.sha256(
                                  f'{block}\n{representation}'.encode('utf-8')).hexdigest()})
    slots.sort(key=lambda r: (r['block_order_sha256'], r['observation_id'], r['repetition'],
                              r['condition_order_sha256'], r['representation']))
    require(len({c['condition_id'] for c in conditions}) == len(conditions), 'Condition identity collision')
    require(len({s['slot_id'] for s in slots}) == len(slots), 'Slot identity collision')
    return conditions, slots


def ledgers(policy, documents, public, frozen_files):
    """Join only bound metadata; keep truth out of observation/condition/slot construction."""
    config, corpus, builds, oracle, dispositions, schema = (documents[n] for n in PARENT_FILES)
    plan = builds['plan']
    matrix = policy['matrix']
    pairs = _indexed([p for p in corpus['pairs'] if p['split'] == 'final'], 'pair_id')
    require(len(pairs) == matrix['families'] and len({p['family_id'] for p in pairs.values()}) == len(pairs),
            'Final family inventory differs')
    require(Counter(p['cwe'] for p in pairs.values()) == matrix['families_per_source_cwe'],
            'Source CWE quotas differ')
    for field in ('variants', 'optimizations', 'symbols'):
        require(config['matrix'][field] == matrix[field], f'Parent {field} matrix differs')
    planned = _indexed(plan['observations'], 'observation_id')
    require(len(planned) == matrix['observations'] and set(public) == set(planned),
            'Observation inventory differs')
    cells = _indexed(builds['builds'], 'build_id')
    require(len(cells) == matrix['reference_builds'], 'Reference-build inventory differs')
    require(oracle['schema_version'] == dispositions['schema_version'] == 3
            and builds['split'] == oracle['split'] == dispositions['split'] == 'final', 'Private schema/split differs')
    for document in (builds, oracle):
        require(document['config_sha256'] == frozen_files['config.json']
                and document['manifest_sha256'] == frozen_files['corpus/manifest.json'],
                'Private source/config binding differs')
    require(dispositions['build_manifest_sha256'] == frozen_files[PARENT_FILES[2]]
            and dispositions['oracle_sha256'] == frozen_files[PARENT_FILES[3]], 'Disposition binding differs')
    reviews = _indexed(oracle['reviews'], 'build_id', cells)
    judged = _indexed(dispositions['observations'], 'observation_id', planned)
    extraction_name = next(n for n in documents if n.endswith('/extraction-manifest.json'))
    extraction = documents[extraction_name]
    require(extraction['plan'] == plan
            and extraction['build_manifest_sha256'] == frozen_files[PARENT_FILES[2]]
            and extraction['oracle_sha256'] == frozen_files[PARENT_FILES[3]], 'Extraction binding differs')
    extracted = _indexed(extraction['observations'], 'observation_id', planned)
    observations, evaluation = [], []
    treatments = set()
    for obs, cell in sorted(planned.items()):
        require(IDENTIFIER.fullmatch(obs), 'Invalid observation ID')
        pair = pairs[cell['pair_id']]
        build = cells[cell['build_id']]
        review = reviews[cell['build_id']]
        for field in ('pair_id', 'variant', 'optimization'):
            require(cell[field] == build[field], f'Build treatment differs: {obs}')
        treatment = (pair['family_id'], cell['variant'], cell['optimization'], cell['symbols'])
        require(treatment not in treatments, 'Duplicate treatment cell')
        treatments.add(treatment)
        require(cell['variant'] in matrix['variants'] and cell['optimization'] in matrix['optimizations']
                and cell['symbols'] in matrix['symbols'], 'Unknown treatment cell')
        require(build['status'] == 'built', 'Parent reference build unavailable')
        artifact = build['artifacts'][cell['symbols']]
        require(artifact['path'] == cell['analysis_path']
                and frozen_files[artifact['path']] == artifact['sha256']
                and frozen_files[build['artifacts']['reference']['path']] == review['reference_sha256']
                == build['artifacts']['reference']['sha256'], 'Stale binary review binding')
        require(review['evidence_sha256'] == build['evidence']['files'], 'Stale private evidence binding')
        for name, expected in review['evidence_sha256'].items():
            require(frozen_files[f"{build['evidence_directory']}/{name}"] == expected,
                    'Private evidence release binding differs')
        require(review['cwe'] == pair['cwe'] and review['source_label'] ==
                ('vulnerable_'+pair['cwe'] if cell['variant'] == 'vulnerable' else 'not_vulnerable'),
                'Source label/provenance differs')
        require(review['binary_label'] in {'vulnerable_CWE-121', 'vulnerable_CWE-122', 'not_vulnerable', 'unresolved'}
                and review['operation_status'] in {'present', 'inlined/merged', 'eliminated', 'unresolved'},
                'Unknown private judgment')
        require(all(judged[obs][k] == v for k, v in cell.items())
                and judged[obs]['review_build_id'] == cell['build_id']
                and all(judged[obs][k] == review[k] for k in ('binary_label', 'source_label', 'operation_status')),
                'Observation judgment differs from bound review')
        record_hash = hashlib.sha256(public[obs]).hexdigest()
        require(frozen_files[cell['record_path']] == record_hash, 'Public bundle binding differs')
        bundle = strict_json(public[obs].decode('utf-8'))
        bundles.validate(bundle, schema=schema)
        require(bundles.canonical(bundle).encode('utf-8') == public[obs], 'Noncanonical public bundle bytes')
        row = extracted[obs]
        require(all(row[k] == v for k, v in cell.items()) and row['record_sha256'] == record_hash
                and row['analysis_sha256'] == artifact['sha256'] and row['status'] == bundle['status']
                and row['entry_address'] == bundle['entry_address'] == hex(review['mapping']['entry_address']),
                'Public extraction/localization binding differs')
        bundles.evidence_addresses(bundle, [hex(a) for fact in review['facts'].values()
                                           for a in fact['instruction_addresses']])
        observation = {**cell, 'family_id': pair['family_id'], 'cwe': pair['cwe'], 'structure': pair['structure'],
                       'bundle_path': f'public/bundles/{obs}.json', 'parent_bundle_sha256': record_hash,
                       'reference_sha256': review['reference_sha256'], 'analysis_sha256': artifact['sha256']}
        observations.append(observation)
        evaluation.append({**observation, **{k: review[k] for k in ('binary_label', 'source_label', 'operation_status')},
                           'review_sha256': identity(review)})
    expected_cells = matrix['families']
    for field in ('variants', 'optimizations', 'symbols'):
        expected_cells *= len(matrix[field])
    require(len(treatments) == expected_cells == matrix['observations'], 'Incomplete treatment matrix')
    require(Counter(r['binary_label'] for r in evaluation) == policy['evaluation']['expected_binary_label_counts'],
            'Parent truth inventory differs; documented repair required')
    conditions, slots = conditions_and_slots(observations, policy)
    require(len(conditions) == matrix['observation_condition_units'] and len(slots) == matrix['final_slots'],
            'Condition/slot counts differ')
    return {'coordinator/observations.json': observations, 'coordinator/conditions.json': conditions,
            'coordinator/slots.json': slots, 'private/evaluation.json': evaluation}


def dependencies():
    """Inventory local transitive imports, including package initializers, without importing snapshots."""
    pending = ['redesign.extensions.representation_study.inventory']
    sources = {}
    while pending:
        module = pending.pop()
        path = REPO.joinpath(*module.split('.'))
        path = path/'__init__.py' if path.is_dir() else path.with_suffix('.py')
        if not path.is_file() or path.relative_to(REPO).as_posix() in sources:
            continue
        sources[path.relative_to(REPO).as_posix()] = digest(path)
        parts = module.split('.')
        pending.extend('.'.join(parts[:i]) for i in range(1, len(parts)))
        package = module if path.name == '__init__.py' else module.rsplit('.', 1)[0]
        for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
            if isinstance(node, ast.Import):
                pending.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                base = util.resolve_name('.'*node.level+(node.module or ''), package) if node.level else node.module
                if base:
                    pending.append(base)
                    pending.extend(base+'.'+alias.name for alias in node.names)
    requirements = (REPO/'requirements.txt').read_text().splitlines()
    packages = {line.split('==')[0] for line in requirements if '==' in line} | {'urllib3'}
    return {'source_files': dict(sorted(sources.items())), 'requirements_sha256': digest(REPO/'requirements.txt'),
            'python': sys.version, 'packages': {name: metadata.version(name) for name in sorted(packages)},
            'installed_distributions': dict(sorted((d.metadata['Name'], d.version)
                                                   for d in metadata.distributions()))}


def prepare(parent, directory, policy_path=POLICY):
    parent, directory = Path(parent).resolve(), Path(directory).absolute()
    require(not directory.exists() and not directory.is_symlink(), 'Preparation destination already exists')
    require(not directory.resolve().is_relative_to(parent) and not parent.is_relative_to(directory.resolve()),
            'Preparation destination overlaps parent')
    policy = policy_check(read_json(policy_path))
    freeze = verify_parent(parent, policy)
    extraction = [n for n in freeze['files'] if n.endswith('/extraction-manifest.json')]
    require(len(extraction) == 1, 'Ambiguous parent extraction manifest')
    names = (*PARENT_FILES, extraction[0])
    documents = {n: read_json(plain_file(parent, n)) for n in names}
    build_report = documents[PARENT_FILES[2]]
    expected = generate(documents['config.json'], documents['corpus/manifest.json'], parent, 'final', True)
    require(expected == build_report['plan'], 'Frozen build plan differs from declared parent matrix')
    check_record_inventory(expected, parent)
    public = {}
    for row in expected['observations']:
        raw = plain_file(parent, row['record_path']).read_bytes()
        bundles.validate(strict_json(raw.decode('utf-8')), binary=plain_file(parent, row['analysis_path']),
                         schema=documents['schemas/bundle-v2.json'])
        public[row['observation_id']] = raw
    content = {name: bundles.canonical(value).encode('utf-8') for name, value in
               ledgers(policy, documents, public, freeze['files']).items()}
    content.update({f'public/bundles/{obs}.json': raw for obs, raw in public.items()})
    for name in (*names, policy['parent']['freeze_manifest']):
        content['private/parent/'+name] = plain_file(parent, name).read_bytes()
    content['coordinator/policy.json'] = Path(policy_path).read_bytes()
    dependency_map = dependencies()
    content['coordinator/dependencies.json'] = bundles.canonical(dependency_map).encode('utf-8')
    for name in (*dependency_map['source_files'], 'requirements.txt'):
        content['coordinator/dependency-snapshot/'+name] = (REPO/name).read_bytes()
    binding = {'schema_version': 1, 'freeze_manifest_sha256': policy['parent']['freeze_manifest_sha256'],
               'archive_sha256': policy['parent']['input_archive_sha256'],
               'verified_parent_files': freeze['files'], 'staged_parent_files': list(names),
               'status': 'parent_release_verified_no_predictors_run'}
    content['coordinator/parent-binding.json'] = bundles.canonical(binding).encode('utf-8')
    manifest = {'schema_version': 1, 'status': 'inputs_bound_execution_pending',
                'study_id': policy['study_id'], 'configuration_id': policy['configuration_id'],
                'counts': {k: policy['matrix'][k] for k in COUNT_FIELDS},
                'files': {n: hashlib.sha256(raw).hexdigest() for n, raw in sorted(content.items())}}
    directory.mkdir(parents=True, exist_ok=False)
    for name, raw in sorted(content.items()):
        path = local_path(directory, name)
        write_new(path, raw.decode('utf-8'))
        path.chmod(0o444)
    write_new(directory/MANIFEST, manifest)  # Completion marker, published last.
    (directory/MANIFEST).chmod(0o444)
    return verify(directory)


def verify(directory, expected_manifest_sha256=None):
    """Read-only staged-input verification, with no parent or server fallback."""
    directory = Path(directory).resolve()
    manifest_path = plain_file(directory, MANIFEST)
    if expected_manifest_sha256 is not None:
        require(digest(manifest_path) == expected_manifest_sha256, 'Preparation manifest changed')
    manifest = read_json(manifest_path)
    require(manifest['schema_version'] == 1 and manifest['status'] == 'inputs_bound_execution_pending',
            'Unknown preparation manifest')
    nodes = list(directory.rglob('*'))
    require(not any(p.is_symlink() for p in nodes), 'Staged symlinks are not allowed')
    actual = {p.relative_to(directory).as_posix() for p in nodes if p.is_file()}
    require(actual == set(manifest['files']) | {MANIFEST}, 'Staged file inventory differs')
    for name, expected in manifest['files'].items():
        require(digest(plain_file(directory, name)) == expected, f'Changed staged input: {name}')
    policy = policy_check(read_json(directory/'coordinator/policy.json'))
    freeze_path = 'private/parent/'+policy['parent']['freeze_manifest']
    require(digest(directory/freeze_path) == policy['parent']['freeze_manifest_sha256'], 'Staged freeze differs')
    freeze = read_json(directory/freeze_path)
    binding = read_json(directory/'coordinator/parent-binding.json')
    require(binding['verified_parent_files'] == freeze['files']
            and binding['archive_sha256'] == freeze['archive_sha256'] == policy['parent']['input_archive_sha256']
            and binding['freeze_manifest_sha256'] == policy['parent']['freeze_manifest_sha256'],
            'Staged parent binding differs')
    documents = {}
    for name in binding['staged_parent_files']:
        path = plain_file(directory, 'private/parent/'+name)
        require(digest(path) == freeze['files'][name], f'Staged parent file differs: {name}')
        documents[name] = read_json(path)
    public = {p.stem: p.read_bytes() for p in (directory/'public/bundles').glob('*.json')}
    regenerated = ledgers(policy, documents, public, freeze['files'])
    for name, value in regenerated.items():
        require(plain_file(directory, name).read_bytes() == bundles.canonical(value).encode('utf-8'),
                f'Staged ledger differs: {name}')
    dependency_map = read_json(directory/'coordinator/dependencies.json')
    for name, expected in {**dependency_map['source_files'],
                           'requirements.txt': dependency_map['requirements_sha256']}.items():
        require(digest(plain_file(directory, 'coordinator/dependency-snapshot/'+name)) == expected,
                f'Staged dependency differs: {name}')
    counts = {k: policy['matrix'][k] for k in COUNT_FIELDS}
    require(manifest['counts'] == counts and manifest['study_id'] == policy['study_id']
            and manifest['configuration_id'] == policy['configuration_id'], 'Preparation identity/counts differ')
    return {'status': manifest['status'], 'counts': counts, 'manifest_sha256': digest(manifest_path),
            'parent_files_verified': len(freeze['files']), 'staged_files': len(manifest['files'])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'verify'))
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--parent', type=Path)
    parser.add_argument('--policy', type=Path, default=POLICY)
    parser.add_argument('--manifest-sha256')
    args = parser.parse_args()
    if args.action == 'prepare':
        policy = read_json(args.policy)
        result = prepare(args.parent or REPO/policy['parent']['workspace'], args.directory, args.policy)
    else:
        result = verify(args.directory, args.manifest_sha256)
    print(bundles.canonical(result), end='')


if __name__ == '__main__':
    main()
