"""Phase 4 private coordinator: public-only extraction jobs, full inventory and post-export audits."""
import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from .build import verify as verify_builds
from .bundles import (address, apply_budget, canonical, empty_bundle, evidence_addresses,
                      normalize, policy_check, validate)
from .context_worker import engine_home
from .inventory import ROOT, digest, encode, generate, local_path, read_json, require
from .oracle import adjudicate


METHODS = ('pipeline/export_context.py', 'pipeline/context_worker.py', 'pipeline/bundles.py',
           'ghidra/ExtractBundle.java', 'ghidra/ConfigurePublicAnalysis.java',
           'schemas/bundle-v2.json', 'context_policy.json')


def engine_identity(policy):
    home = engine_home(policy)
    paths = [home / 'support/analyzeHeadless', home / 'support/launch.sh', home / 'Ghidra/application.properties']
    paths += sorted((home / 'Ghidra').glob('**/lib/*.jar'))
    paths += sorted((home / 'Ghidra/Processors/x86/data').rglob('*'))
    paths += sorted((home / 'Ghidra').glob('**/*.gdt'))
    paths += sorted((home / 'Ghidra').glob('**/*.fidb'))
    paths += sorted((home / 'Ghidra/Features/Decompiler/os/linux_x86_64').glob('*'))
    files = {p.relative_to(home).as_posix(): digest(p) for p in paths if p.is_file()}
    java = shutil.which('java')
    require(java, 'Java is unavailable')
    version = subprocess.run([java, '-XX:-UsePerfData', '-version'], capture_output=True, text=True, check=True)
    return {'home': str(home), 'version': policy['ghidra_version'], 'files': files,
            'java': {'path': str(Path(java).resolve()), 'sha256': digest(Path(java).resolve()),
                     'version': version.stderr.strip() or version.stdout.strip()}}


def load_inputs(root, split):
    config = read_json(root / 'config.json')
    plan = generate(config, read_json(root / 'corpus/manifest.json'), root, split, require_assigned=True)
    policy = policy_check(read_json(root / 'context_policy.json'))
    require(policy['ghidra_version'] == config['ghidra']['expected_version']
            and policy['language'] == config['ghidra']['language']
            and policy['compiler_spec'] == config['ghidra']['compiler_spec'], 'Context/compiler configuration differs')
    report = read_json(root / 'build' / split / 'build-manifest.json')
    verify_builds(report, root)
    reviews_path = root / 'corpus/private' / f'{split}-oracle.json'
    reviews = read_json(reviews_path)
    adjudicate(report, reviews, root)
    return plan, policy, report, reviews, reviews_path


def record_path(directory, observation):
    return directory / 'records' / (observation['observation_id'] + '.json')


def run_directory(root, split, run_id):
    require(re.fullmatch(r'[a-z][a-z0-9_-]*', run_id), 'Invalid extraction run ID')
    return local_path(root, f'build/{split}/context/{run_id}')


def extract_run(root=ROOT, split='pilot', run_id='primary', write=False):
    plan, policy, builds, reviews, reviews_path = load_inputs(root, split)
    directory = run_directory(root, split, run_id)
    directory.mkdir(parents=True, exist_ok=False)
    (directory / 'records').mkdir()
    by_build = {c['build_id']: c for c in builds['builds']}
    by_review = {r['build_id']: r for r in reviews['reviews']}
    identity_error = None
    try:
        identity = engine_identity(policy)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        identity, identity_error = None, str(error)
    tickets = []
    for observation in plan['observations']:
        cell, review = by_build[observation['build_id']], by_review[observation['build_id']]
        entry = review.get('mapping', {}).get('entry_address')
        tickets.append({'observation_id': observation['observation_id'],
                        'entry_address': None if entry is None else hex(entry),
                        'analysis_sha256': cell.get('artifacts', {}).get(observation['symbols'], {}).get('sha256')})
    # This allowlisted localization artifact contains no source capacities, names, ranges or labels.
    (directory / 'localization.json').write_text(encode(tickets))
    methods = {name: digest(root / name) for name in METHODS}
    report = {'schema_version': 2, 'phase': 4, 'split': split, 'run_id': run_id,
              'plan': plan, 'policy': policy, 'methods': methods, 'engine': identity,
              'engine_error': identity_error, 'oracle_sha256': digest(reviews_path),
              'localization_sha256': digest(directory / 'localization.json'),
              'build_manifest_sha256': digest(root / 'build' / split / 'build-manifest.json'),
              'observations': []}

    def one(arguments):
        observation, ticket = arguments
        cell = by_build[observation['build_id']]
        job = directory / observation['observation_id']
        job.mkdir()
        entry = ticket['entry_address']
        error = None
        if cell['status'] != 'built':
            bundle = empty_bundle(entry, 'build_unavailable')
        elif entry is None:
            bundle = empty_bundle(None, 'entry_unavailable')
        elif identity is None:
            bundle = empty_bundle(entry, 'engine_unavailable')
        else:
            # The worker's process arguments carry only an analysis ELF, entry and shared policy.
            binary = job / 'input.elf'
            shutil.copyfile(root / observation['analysis_path'], binary)
            require(digest(binary) == ticket['analysis_sha256'], 'Staged analysis artifact differs')
            output = job / 'bundle.json'
            command = [sys.executable, '-m', 'redesign.pipeline.context_worker',
                       '--input', str(binary), '--entry', entry,
                       '--policy', str(root / 'context_policy.json'), '--work', str(job / 'engine'),
                       '--output', str(output)]
            try:
                result = subprocess.run(command, cwd=ROOT.parent, capture_output=True, text=True,
                                        timeout=policy['process_timeout_seconds'] + 60)
                (job / 'worker-console.log').write_text(result.stdout + result.stderr)
                require(result.returncode == 0 and output.is_file(), 'Extraction worker failed')
                bundle = read_json(output)
                validate(bundle, binary)
            except (ValueError, OSError, subprocess.SubprocessError) as failure:
                error = str(failure)
                bundle = empty_bundle(entry, 'engine_failed')
        bundle = normalize(bundle)
        validate(bundle)
        target = record_path(directory, observation)
        target.write_text(canonical(bundle))
        row = {**observation, 'status': bundle['status'], 'record_sha256': digest(target),
               'entry_address': entry, 'analysis_sha256': ticket['analysis_sha256'],
               'functions': len(bundle['functions']),
               'instructions': sum(len(f['instructions']) for f in bundle['functions']),
               'data_bytes': sum(d['size'] for d in bundle['data']),
               'bundle_utf8_bytes': len(target.read_bytes()), 'worker_error': error,
               'omission_reasons': sorted({x['reason'] for x in bundle['completeness']['omissions']})}
        return row

    with ThreadPoolExecutor(max_workers=2) as workers:
        for row in workers.map(one, zip(plan['observations'], tickets)):
            report['observations'].append(row)
            (directory / 'extraction-manifest.json').write_text(encode(report))
            print(f"{len(report['observations'])}/{len(tickets)} {row['status']}", flush=True)
    report['counts'] = dict(Counter(o['status'] for o in report['observations']))
    (directory / 'extraction-manifest.json').write_text(encode(report))
    verify_run(root, split, run_id)
    if write:
        publish(root, directory, report)
    return report


def verify_run(root=ROOT, split='pilot', run_id='primary'):
    plan, policy, builds, reviews, reviews_path = load_inputs(root, split)
    directory = run_directory(root, split, run_id)
    report = read_json(directory / 'extraction-manifest.json')
    require(report['schema_version'] == 2 and report['phase'] == 4 and report['run_id'] == run_id
            and report['split'] == split and report['plan'] == plan and report['policy'] == policy,
            'Extraction plan/policy differs')
    require(report['methods'] == {name: digest(root / name) for name in METHODS}, 'Extraction methods changed')
    require(report['oracle_sha256'] == digest(reviews_path)
            and report['build_manifest_sha256'] == digest(root / 'build' / split / 'build-manifest.json'),
            'Private input identity changed')
    require(report['localization_sha256'] == digest(directory / 'localization.json'), 'Localization changed')
    tickets = read_json(directory / 'localization.json')
    by_review = {r['build_id']: r for r in reviews['reviews']}
    by_build = {b['build_id']: b for b in builds['builds']}
    expected_tickets = []
    for observation in plan['observations']:
        entry = by_review[observation['build_id']].get('mapping', {}).get('entry_address')
        cell = by_build[observation['build_id']]
        expected_tickets.append({'observation_id': observation['observation_id'],
                                 'entry_address': None if entry is None else hex(entry),
                                 'analysis_sha256': cell.get('artifacts', {}).get(observation['symbols'], {}).get('sha256')})
    require(tickets == expected_tickets, 'Localization contains altered or extra private inputs')
    require([{k: r[k] for k in o} for r, o in zip(report['observations'], plan['observations'])]
            == plan['observations'] and len(report['observations']) == len(plan['observations']),
            'Extraction inventory missing, duplicate or unexpected')
    require({p.name for p in (directory / 'records').iterdir()}
            == {o['observation_id'] + '.json' for o in plan['observations']}, 'Record inventory differs')
    for row, ticket in zip(report['observations'], tickets):
        target = record_path(directory, row)
        bundle = read_json(target)
        binary = root / row['analysis_path'] if row['analysis_sha256'] else None
        validate(bundle, binary)
        require(bundle['entry_address'] == ticket['entry_address'] == row['entry_address']
                and row['analysis_sha256'] == ticket['analysis_sha256'], 'Entry/artifact identity differs')
        require(target.read_text() == canonical(bundle) and row['record_sha256'] == digest(target), 'Record changed')
        require(row['status'] == bundle['status'] and row['bundle_utf8_bytes'] == len(target.read_bytes())
                and row['functions'] == len(bundle['functions'])
                and row['instructions'] == sum(len(f['instructions']) for f in bundle['functions'])
                and row['data_bytes'] == sum(d['size'] for d in bundle['data']), 'Extraction counts differ')
        if bundle['status'] == 'available':
            require(apply_budget(bundle, policy) == bundle, 'Available bundle exceeds shared budget')
        job = directory / row['observation_id']
        staged = job / 'input.elf'
        if staged.exists():
            require(digest(staged) == row['analysis_sha256'], 'Staged artifact changed')
        worker_path = job / 'engine/worker.json'
        if worker_path.is_file():
            worker = read_json(worker_path)
            require(worker['input_sha256'] == row['analysis_sha256']
                    and worker['entry_address'] == row['entry_address'], 'Worker input identity differs')
            raw_path = job / 'engine/raw.json'
            if worker['error'] is None:
                raw = normalize(read_json(raw_path))
                validate(raw, staged)
                require(apply_budget(raw, policy) == bundle, 'Bundle differs from public-only engine export')
    require(report['counts'] == dict(Counter(r['status'] for r in report['observations'])), 'Status counts differ')
    if report['engine'] is not None:
        home = Path(report['engine']['home'])
        for name, expected in report['engine']['files'].items():
            require(digest(home / name) == expected, 'Ghidra installation changed')
        require(digest(report['engine']['java']['path']) == report['engine']['java']['sha256'], 'Java changed')
    return report


def publish(root, directory, report):
    destination = root / 'data' / report['split'] / 'records'
    destination.mkdir(parents=True, exist_ok=True)
    expected = {r['observation_id'] + '.json' for r in report['observations']}
    require({p.name for p in destination.iterdir()} <= expected, 'Unexpected published records')
    # Check all existing records before writing any new ones.
    for row in report['observations']:
        target = root / row['record_path']
        if target.exists():
            require(not target.is_symlink() and digest(target) == row['record_sha256'],
                    'Existing public record differs; preserve it and review the method change')
    for row in report['observations']:
        target = root / row['record_path']
        if not target.exists():
            target.write_bytes(record_path(directory, row).read_bytes())


def scope_identity(bundle):
    """Binary code/data identity without names or decompiler rendering; not a prediction input."""
    return {'entry_address': bundle['entry_address'],
            'functions': [{'entry': f['entry'], 'ranges': f['ranges'],
                           'instructions': [{k: i[k] for k in ('address', 'size', 'bytes')}
                                            for i in f['instructions']]} for f in bundle['functions']],
            'calls': [{k: c[k] for k in ('caller', 'site', 'target_address', 'target_entry', 'kind', 'resolution')}
                      for c in bundle['calls']],
            'data': [{k: d[k] for k in ('address', 'size', 'bytes', 'references')} for d in bundle['data']]}


def audit_run(root=ROOT, split='pilot', run_id='primary', compare=None):
    report = verify_run(root, split, run_id)
    directory = run_directory(root, split, run_id)
    reviews_path = root / 'corpus/private' / f'{split}-oracle.json'
    reviews = {r['build_id']: r for r in read_json(reviews_path)['reviews']}
    bundles = {r['observation_id']: read_json(record_path(directory, r)) for r in report['observations']}
    checks, partners = [], []
    groups = {'exact_bundle': defaultdict(list), 'binary_code_data_scope': defaultdict(list)}
    for row in report['observations']:
        bundle = bundles[row['observation_id']]
        review = reviews[row['build_id']]
        required = sorted({hex(a) for f in review.get('facts', {}).values() for a in f['instruction_addresses']}, key=address)
        included = {i['address'] for f in bundle['functions'] for i in f['instructions']}
        missing = [a for a in required if a not in included]
        if bundle['status'] == 'available':
            evidence_addresses(bundle, [a for a in required if a in included])
            for mode, value in (('exact_bundle', bundle), ('binary_code_data_scope', scope_identity(bundle))):
                key = hashlib.sha256(canonical(value).encode()).hexdigest()
                groups[mode][key].append(row['observation_id'])
        checks.append({'observation_id': row['observation_id'], 'status': bundle['status'],
                       'oracle_evidence_covered': not missing, 'missing_instruction_addresses': missing,
                       'decompilation_statuses': dict(Counter(f['decompilation']['status'] for f in bundle['functions'])),
                       'uncertain_data_windows': sum(d['extent_status'] == 'unknown_window' for d in bundle['data'])})
    by_build = defaultdict(dict)
    for row in report['observations']:
        by_build[row['build_id']][row['symbols']] = row
    for build_id, rows in by_build.items():
        retained, stripped = [bundles[rows[k]['observation_id']] for k in ('retained', 'stripped')]
        lookup = {f['entry']: f for f in stripped['functions']}
        changed = [{'entry': f['entry'], 'retained_name': f['name'], 'stripped_name': lookup[f['entry']]['name']}
                   for f in retained['functions'] if f['entry'] in lookup and f['name_origin'] == 'imported'
                   and f['name'] != lookup[f['entry']]['name']]
        partners.append({'build_id': build_id,
                         'both_available': retained['status'] == stripped['status'] == 'available',
                         'identical_bundles': retained == stripped,
                         'same_binary_code_data_scope': scope_identity(retained) == scope_identity(stripped),
                         'developer_names_removed': changed})
    observation_map = {r['observation_id']: r for r in report['observations']}
    equality = {}
    for mode, values in groups.items():
        equality[mode] = [{'sha256': key, 'observations': ids,
                           'source_labels': sorted({reviews[observation_map[i]['build_id']]['source_label'] for i in ids}),
                           'conflicting_source_labels': len({reviews[observation_map[i]['build_id']]['source_label'] for i in ids}) > 1}
                          for key, ids in sorted(values.items()) if len(ids) > 1]
    result = {'schema_version': 2, 'phase': 4, 'split': split, 'run_id': run_id,
              'extraction_manifest_sha256': digest(directory / 'extraction-manifest.json'),
              'methods': report['methods'], 'engine': report['engine'], 'policy': report['policy'],
              'counts': report['counts'], 'observations': checks, 'symbol_partners': partners,
              'context_sizes': {field: {'min': min(r[field] for r in report['observations']),
                                        'max': max(r[field] for r in report['observations'])}
                                for field in ('functions', 'instructions', 'data_bytes', 'bundle_utf8_bytes')},
              'all_observations_available': all(c['status'] == 'available' for c in checks),
              'equality_groups': equality,
              'oracle_coverage_gate': all(c['oracle_evidence_covered'] for c in checks if c['status'] == 'available'),
              'scope_parity_gate': all(p['same_binary_code_data_scope'] for p in partners if p['both_available'])}
    if compare:
        other = verify_run(root, split, compare)
        rows = {r['observation_id']: r for r in other['observations']}
        differences = [r['observation_id'] for r in report['observations']
                       if rows[r['observation_id']]['record_sha256'] != r['record_sha256']]
        result['repeatability'] = {'compared_run': compare, 'identical': not differences,
                                   'different_observations': differences,
                                   'comparison_manifest_sha256': digest(run_directory(root, split, compare) / 'extraction-manifest.json')}
    result['status'] = ('passed' if result['all_observations_available'] and result['oracle_coverage_gate']
                        and result['scope_parity_gate'] and result.get('repeatability', {}).get('identical')
                        else 'pending_or_failed_gates')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('extract', 'verify', 'audit'))
    parser.add_argument('--split', choices=('pilot', 'final'), default='pilot')
    parser.add_argument('--run-id', default='primary')
    parser.add_argument('--compare')
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    if args.action == 'extract':
        result = extract_run(ROOT, args.split, args.run_id, args.write)
    elif args.action == 'verify':
        result = verify_run(ROOT, args.split, args.run_id)
    else:
        result = audit_run(ROOT, args.split, args.run_id, args.compare)
        if args.write:
            name = 'phase4-validation.json' if args.split == 'pilot' else 'phase4-final-validation.json'
            (ROOT / 'provenance' / name).write_text(encode(result))
    print(encode({k: v for k, v in result.items() if k in ('status', 'counts', 'oracle_coverage_gate', 'scope_parity_gate', 'repeatability', 'all_observations_available')}), end='')


if __name__ == '__main__':
    main()
