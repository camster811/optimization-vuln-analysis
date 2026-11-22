"""Bind accepted pilot bundles, predeclare smoke cells and check saved integration evidence."""
import argparse
from collections import Counter
from copy import deepcopy
import hashlib
from pathlib import Path

from redesign.pipeline import bundles
from redesign.pipeline.inventory import ROOT, check_record_inventory, digest, generate, read_json, require
from redesign.pipeline.llm_runtime import write_new
from . import adapter, inventory, runner, views


SOURCES = ('config.json', 'corpus/manifest.json', 'build/pilot/build-manifest.json',
           'build/pilot/context/phase4-d/extraction-manifest.json',
           'build/pilot/llm/phase6-a/manifest.json', 'schemas/bundle-v2.json')


def _bind(documents, sources, policy):
    config, corpus, builds, extraction, accepted, schema = (documents[n] for n in SOURCES)
    # Source selection was validated against the actual workspace before copying.
    plan = builds['plan']
    require(plan['split'] == builds['split'] == extraction['split'] == accepted['split'] == 'pilot',
            'Expected pilot-only inputs')
    require(extraction['plan'] == plan and extraction['build_manifest_sha256'] == documents['_build_sha256'],
            'Pilot extraction build binding differs')
    require(builds['config_sha256'] == documents['_config_sha256']
            and builds['manifest_sha256'] == documents['_corpus_sha256'], 'Pilot source binding differs')
    pairs = {p['pair_id']: p for p in corpus['pairs'] if p['split'] == 'pilot'}
    require(len(pairs) == policy['pilot']['families'] == 2
            and len({p['family_id'] for p in pairs.values()}) == 2
            and Counter(p['cwe'] for p in pairs.values()) == {'CWE-121': 1, 'CWE-122': 1}
            and not {p['family_id'] for p in pairs.values()} &
                    {p.get('family_id') for p in corpus['pairs'] if p['split'] == 'final'}, 'Pilot family inventory differs')
    extracted = {r['observation_id']: r for r in extraction['observations']}
    require(len(extracted) == len(extraction['observations']) == len(plan['observations']) == 32
            and set(sources) == set(extracted) == set(accepted['inputs']), 'Pilot observation inventory differs')
    rows = []
    for cell in sorted(plan['observations'], key=lambda r: r['observation_id']):
        obs = cell['observation_id']
        raw, row = sources[obs], extracted[obs]
        sha = hashlib.sha256(raw).hexdigest()
        require(all(row[k] == v for k, v in cell.items()) and sha == row['record_sha256'] == accepted['inputs'][obs],
                'Accepted pilot bundle binding differs')
        bundle = inventory.strict_json(raw.decode('utf-8'))
        bundles.validate(bundle, schema=schema)
        require(bundles.canonical(bundle).encode() == raw and row['status'] == bundle['status'] == 'available',
                'Pilot bundle unavailable/noncanonical')
        pair = pairs[cell['pair_id']]
        rows.append({**cell, 'family_id': pair['family_id'], 'cwe': pair['cwe'],
                     'bundle_path': f'public/bundles/{obs}.json', 'parent_bundle_sha256': sha})
    selection = policy['pilot']['selection']
    require(selection == {'variant': 'vulnerable', 'optimization': 'O0', 'symbols': 'retained'},
            'Smoke selection differs from predeclared metadata rule')
    selected = [r for r in rows if all(r[k] == v for k, v in selection.items())]
    require(len(selected) == policy['pilot']['observations'] == 2
            and {r['family_id'] for r in selected} == {p['family_id'] for p in pairs.values()},
            'Missing/duplicate pilot smoke cell')
    return rows, selected


def _configuration(policy, rows, configuration_id):
    result = deepcopy(policy)
    result['configuration_id'] = configuration_id
    result['matrix'].update(families=2, families_per_source_cwe={'CWE-121': 1, 'CWE-122': 1},
        variants=sorted({r['variant'] for r in rows}), optimizations=sorted({r['optimization'] for r in rows}),
        symbols=sorted({r['symbols'] for r in rows}), reference_builds=len({r['build_id'] for r in rows}),
        observations=len(rows), observation_condition_units=3*len(rows), final_slots=9*len(rows))
    result['engineering'] = {'purpose': 'pilot', 'included_in_final_scores': False,
                             'parent_protocol_sha256': inventory.identity(policy),
                             'evaluation_contract': 'final_only_not_applied_to_pilot'}
    return adapter.policy_check(result)


def _export(rows, sources, policy, parent_schema):
    """Use the existing projection format/verifier with an explicit pilot input manifest."""
    conditions, _ = inventory.conditions_and_slots(rows, policy)
    schema = read_json(views.SCHEMA)
    content = _stringify(views._render(conditions, {r['observation_id']: sources[r['observation_id']] for r in rows},
                                      schema, parent_schema))
    content.update({'coordinator/conditions.json': bundles.canonical(conditions),
                    'schemas/view.json': bundles.canonical(schema),
                    'schemas/bundle-v2.json': bundles.canonical(parent_schema)})
    content.update({f"source/bundles/{r['observation_id']}.json": sources[r['observation_id']].decode() for r in rows})
    counts = {k: policy['matrix'][k] for k in inventory.COUNT_FIELDS}
    binding = {'schema_version': 1, 'status': 'pilot_public_inputs_bound', 'counts': counts,
               'files': {'coordinator/conditions.json': inventory.identity(conditions),
                         'private/parent/schemas/bundle-v2.json': inventory.identity(parent_schema),
                         **{r['bundle_path']: r['parent_bundle_sha256'] for r in rows}}}
    content['coordinator/input-manifest.json'] = bundles.canonical(binding)
    deps = inventory.dependencies('redesign.extensions.representation_study.pilot')
    content['coordinator/dependencies.json'] = bundles.canonical(deps)
    content.update({'coordinator/dependency-snapshot/'+n: (inventory.REPO/n).read_text()
                    for n in (*deps['source_files'], 'requirements.txt')})
    content[views.MANIFEST] = bundles.canonical({'schema_version': 1, 'status': 'views_projected_not_tokenized',
        'input_manifest_sha256': inventory.identity(binding), 'counts': counts,
        'files': {n: _sha(v) for n, v in sorted(content.items())}})
    return content


def _sha(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def _stringify(content):
    return {n: raw.decode('utf-8') for n, raw in content.items()}


def prepare(directory, root=ROOT, protocol_root=adapter.HERE, configuration_id='representation-v1-context12288-pilot-v1'):
    """Offline: project all 32 accepted observations, then select exactly two by metadata."""
    directory, root = Path(directory).absolute(), Path(root).resolve()
    require(not directory.exists() and not directory.is_symlink(), 'Pilot preparation destination exists')
    policy, prompt, response_schema = adapter.settings(protocol_root)
    plan = generate(read_json(root/'config.json'), read_json(root/'corpus/manifest.json'), root, 'pilot', True)
    check_record_inventory(plan, root)
    documents = {n: read_json(inventory.plain_file(root, n)) for n in SOURCES}
    require(documents['build/pilot/build-manifest.json']['plan'] == plan, 'Pilot build plan differs')
    documents.update(_build_sha256=digest(root/SOURCES[2]), _config_sha256=digest(root/SOURCES[0]),
                     _corpus_sha256=digest(root/SOURCES[1]))
    sources = {r['observation_id']: inventory.plain_file(root, r['record_path']).read_bytes() for r in plan['observations']}
    rows, selected = _bind(documents, sources, policy)
    full_policy = _configuration(policy, rows, configuration_id)
    smoke_policy = _configuration(policy, selected, configuration_id)
    content = {'protocol/policy.json': bundles.canonical(smoke_policy), 'protocol/prompt.md': prompt,
               'protocol/schemas/response.json': bundles.canonical(response_schema),
               'parent-protocol/policy.json': (Path(protocol_root)/'policy.json').read_text(),
               'selection.json': bundles.canonical({'split': 'pilot', 'purpose': 'engineering',
                   'included_in_final_scores': False, 'rule': policy['pilot']['selection'],
                   'selected': selected, 'observations': rows, 'slots': 18}),
               'source-bindings.json': bundles.canonical({n: digest(root/n) for n in SOURCES})}
    content.update({'provenance/'+n: (root/n).read_text() for n in SOURCES})
    content.update({f'accepted-bundles/{obs}.json': raw.decode() for obs, raw in sources.items()})
    for prefix, subset, config in [('projection', rows, full_policy), ('smoke', selected, smoke_policy)]:
        content.update({prefix+'/'+n: value for n, value in _export(subset, sources, config, documents[SOURCES[-1]]).items()})
    manifest = {'schema_version': 1, 'status': 'pilot_predeclared_before_generation',
                'configuration_id': configuration_id, 'files': {n: _sha(v) for n, v in sorted(content.items())}}
    directory.mkdir(parents=True, exist_ok=False)
    for name, value in sorted(content.items()):
        path = inventory.local_path(directory, name)
        write_new(path, value); path.chmod(0o444)
    write_new(directory/'manifest.json', manifest); (directory/'manifest.json').chmod(0o444)
    return verify(directory)


def verify(directory, expected_manifest_sha256=None):
    """Offline replay of predeclared selection and projections, without original workspace."""
    directory = Path(directory).resolve()
    manifest = read_json(inventory.plain_file(directory, 'manifest.json'))
    require(expected_manifest_sha256 is None or digest(directory/'manifest.json') == expected_manifest_sha256,
            'Pilot preparation identity differs')
    require(manifest['schema_version'] == 1 and manifest['status'] == 'pilot_predeclared_before_generation',
            'Unknown pilot preparation')
    nodes = list(directory.rglob('*'))
    require(not any(p.is_symlink() for p in nodes) and
            {p.relative_to(directory).as_posix() for p in nodes if p.is_file()} == set(manifest['files']) | {'manifest.json'},
            'Pilot file inventory differs')
    require(all(digest(inventory.plain_file(directory, n)) == sha for n, sha in manifest['files'].items()),
            'Pilot preparation file changed')
    bindings = read_json(directory/'source-bindings.json')
    require(set(bindings) == set(SOURCES) and all(digest(directory/'provenance'/n) == sha for n, sha in bindings.items()),
            'Pilot source binding differs')
    documents = {n: read_json(directory/'provenance'/n) for n in SOURCES}
    documents.update(_build_sha256=bindings[SOURCES[2]], _config_sha256=bindings[SOURCES[0]], _corpus_sha256=bindings[SOURCES[1]])
    sources = {p.stem: p.read_bytes() for p in (directory/'accepted-bundles').glob('*.json')}
    policy = read_json(directory/'parent-protocol/policy.json')
    rows, selected = _bind(documents, sources, policy)
    selection = read_json(directory/'selection.json')
    require(selection == {'split': 'pilot', 'purpose': 'engineering', 'included_in_final_scores': False,
                           'rule': policy['pilot']['selection'], 'selected': selected, 'observations': rows, 'slots': 18},
            'Pilot selection differs')
    smoke_policy, _, _ = adapter.settings(directory/'protocol')
    require(smoke_policy == _configuration(policy, selected, manifest['configuration_id']), 'Pilot protocol differs')
    full, smoke = views.verify(directory/'projection'), views.verify(directory/'smoke')
    require(full['observations'] == 32 and smoke['observations'] == 2, 'Pilot projection counts differ')
    return {'status': manifest['status'], 'manifest_sha256': digest(directory/'manifest.json'),
            'configuration_id': manifest['configuration_id'], 'projected_observations': 32,
            'projected_views': 96, 'selected_observation_ids': [r['observation_id'] for r in selected],
            'smoke_projection_manifest_sha256': smoke['manifest_sha256'], 'slots': 18}


def check(directory, execution):
    """Summarize engineering integration only; correctness is not an acceptance test."""
    directory, execution = Path(directory).resolve(), Path(execution).resolve()
    preparation = verify(directory)
    result = runner.verify(execution)
    manifest = read_json(execution/runner.MANIFEST)
    require(result['purpose'] == 'engineering' and manifest['projection_manifest_sha256'] ==
            preparation['smoke_projection_manifest_sha256'] and result['slots'] == 18,
            'Execution is not the predeclared engineering pilot')
    require(read_json(execution/'protocol/policy.json') == read_json(directory/'protocol/policy.json')
            and (execution/'protocol/prompt.md').read_bytes() == (directory/'protocol/prompt.md').read_bytes()
            and read_json(execution/'protocol/response.json') == read_json(directory/'protocol/schemas/response.json'),
            'Pilot execution protocol differs')
    valid, statuses, timings, usage = Counter(), {r: Counter() for r in views.CONDITIONS}, [], Counter()
    for slot in read_json(execution/'coordinator/schedule.json'):
        path = execution/slot['slot_path']
        if not (path/'result.json').exists(): continue
        status = read_json(path/'result.json')['status']
        statuses[slot['representation']][status] += 1
        if status == 'valid': valid[slot['representation']] += 1
        if (path/'response.json').exists():
            response = read_json(path/'response.json')['attempt']
            timings.append(response['elapsed_seconds'])
            usage.update({k: v for k, v in response['usage'].items() if v is not None})
    unusual = {k: v for k, v in result['attempt_statuses'].items() if k not in {'valid', 'length_limit'}}
    passed = result['status'] == 'complete' and result['terminal_slots'] == 18 and len(result['aggregates']) == 6 \
        and all(valid[r] for r in views.CONDITIONS) and not unusual and result['blocked_observations'] == 0
    return {'status': 'passed' if passed else 'not_passed', 'purpose': 'engineering', 'included_in_final_scores': False,
            'preparation_manifest_sha256': preparation['manifest_sha256'],
            'execution_manifest_sha256': result['manifest_sha256'], 'terminal_slots': result['terminal_slots'],
            'attempt_statuses': result['attempt_statuses'], 'statuses_by_representation': statuses,
            'valid_by_representation': {r: valid[r] for r in views.CONDITIONS}, 'requires_review': unusual,
            'aggregates': result['aggregates'], 'recorded_response_seconds': sum(timings), 'recorded_usage': dict(usage),
            'correctness_used_for_acceptance': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'verify', 'check'))
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--protocol-root', type=Path, default=adapter.HERE)
    parser.add_argument('--execution', type=Path)
    parser.add_argument('--manifest-sha256')
    args = parser.parse_args()
    if args.action == 'prepare': result = prepare(args.directory, args.root, args.protocol_root)
    elif args.action == 'verify': result = verify(args.directory, args.manifest_sha256)
    else:
        require(args.execution is not None, 'check requires --execution')
        result = check(args.directory, args.execution)
    print(bundles.canonical(result), end='')


if __name__ == '__main__':
    main()
