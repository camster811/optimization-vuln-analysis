"""Bind a frozen parent and stage inputs; never compile, lift or request predictions."""
import argparse
import hashlib
from pathlib import Path

from optimization_vuln_analysis.inputs import bundles, parent as parent_input
from optimization_vuln_analysis.inputs.corpus import IDENTIFIER
from optimization_vuln_analysis.common.artifacts import digest, local_path, plain_file
from optimization_vuln_analysis.common.serialization import read_json
from optimization_vuln_analysis.common import require
from optimization_vuln_analysis.inference.runtime import write_new
from optimization_vuln_analysis.common.resources import resource


POLICY = resource('studies/representation/policy.json')
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
    observations, evaluation = parent_input.bind(policy, documents, public, frozen_files)
    conditions, slots = conditions_and_slots(observations, policy)
    require(len(conditions) == policy['matrix']['observation_condition_units']
            and len(slots) == policy['matrix']['final_slots'], 'Condition/slot counts differ')
    return {'coordinator/observations.json': observations, 'coordinator/conditions.json': conditions,
            'coordinator/slots.json': slots, 'private/evaluation.json': evaluation}


def prepare(parent, directory, policy_path=POLICY):
    parent, directory = Path(parent).resolve(), Path(directory).absolute()
    require(not directory.exists() and not directory.is_symlink(), 'Preparation destination already exists')
    require(not directory.resolve().is_relative_to(parent) and not parent.is_relative_to(directory.resolve()),
            'Preparation destination overlaps parent')
    policy = policy_check(read_json(policy_path))
    accepted = parent_input.read(parent, policy)
    documents, public = accepted['documents'], accepted['bundles']
    freeze, names = accepted['freeze'], accepted['staged_files']
    content = {name: bundles.canonical(value).encode('utf-8') for name, value in
               ledgers(policy, documents, public, freeze['files']).items()}
    content.update({f'public/bundles/{obs}.json': raw for obs, raw in public.items()})
    for name in (*names, policy['parent']['freeze_manifest']):
        content['private/parent/'+name] = plain_file(parent, name).read_bytes()
    content['coordinator/policy.json'] = Path(policy_path).read_bytes()
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
    counts = {k: policy['matrix'][k] for k in COUNT_FIELDS}
    require(manifest['counts'] == counts and manifest['study_id'] == policy['study_id']
            and manifest['configuration_id'] == policy['configuration_id'], 'Preparation identity/counts differ')
    return {'status': manifest['status'], 'counts': counts, 'manifest_sha256': digest(manifest_path),
            'parent_files_verified': len(freeze['files']), 'staged_files': len(manifest['files'])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'verify'))
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--parent', type=Path, default=Path('data/parent-study'))
    parser.add_argument('--policy', type=Path, default=POLICY)
    parser.add_argument('--manifest-sha256')
    args = parser.parse_args()
    if args.action == 'prepare':
        result = prepare(args.parent, args.directory, args.policy)
    else:
        result = verify(args.directory, args.manifest_sha256)
    print(bundles.canonical(result), end='')


if __name__ == '__main__':
    main()
