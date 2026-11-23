"""Allowlisted public code views and read-only projection audits; no oracle interface."""
import argparse
from collections import Counter
import hashlib
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from optimization_vuln_analysis.common import require
from optimization_vuln_analysis.common.resources import resource
from optimization_vuln_analysis.inputs import bundles
from optimization_vuln_analysis.inputs.corpus import IDENTIFIER
from optimization_vuln_analysis.common.artifacts import digest, local_path, plain_file
from optimization_vuln_analysis.common.serialization import read_json, strict_json
from optimization_vuln_analysis.inference.runtime import write_new
from . import inventory


SCHEMA = resource('studies/representation/schemas/view.json')
PARENT_URI = 'urn:representation-study:parent-bundle-v2'
KINDS = ('assembly', 'decompilation')
CONDITIONS = (*KINDS, 'combined')
MANIFEST = 'coordinator/manifest.json'


def validator(schema=None, parent_schema=None):
    schema = read_json(SCHEMA) if schema is None else schema
    parent_schema = read_json(resource('inputs/schemas/bundle-v2.json')) if parent_schema is None else parent_schema
    Draft202012Validator.check_schema(schema)
    # Registry() fails on unknown resources: no URL retrieval or filesystem fallback.
    registry = Registry().with_resource(PARENT_URI, Resource.from_contents(parent_schema))
    return Draft202012Validator(schema, registry=registry)


def visible_references(view):
    """Return code references from an already validated supplied view, with no hidden bundle."""
    return {line['reference'] for kind in KINDS for function in view.get(kind, []) for line in function['lines']}


def validate(view, *, schema=None, parent_schema=None):
    validator(schema, parent_schema).validate(view)
    functions = view['shared']['functions']
    ids = [f['id'] for f in functions]
    entries = [bundles.address(f['entry']) for f in functions]
    require(entries == sorted(set(entries)) and ids == [f'F{i:04d}' for i in range(1, len(ids)+1)],
            'Noncanonical function IDs/order')
    references, instruction_addresses = [], []
    for kind, prefix in zip(KINDS, ('A', 'D')):
        if kind not in view:
            continue
        require([f['function_id'] for f in view[kind]] == ids, 'Code function closure/order differs')
        for function in view[kind]:
            expected = [f"{prefix}:{function['function_id']}:L{i:05d}"
                        for i in range(1, len(function['lines'])+1)]
            actual = [line['reference'] for line in function['lines']]
            require(actual == expected, 'Noncanonical line references/order')
            references.extend(actual)
            if kind == 'assembly':
                addresses = [bundles.address(line['address']) for line in function['lines']]
                require(addresses == sorted(set(addresses)), 'Assembly instruction ordering differs')
                instruction_addresses.extend(addresses)
    require(len(references) == len(set(references)), 'Duplicate visible reference')
    require(len(instruction_addresses) == len(set(instruction_addresses)), 'Duplicate instruction address')
    for window in view['shared']['data']:
        require(len(bytes.fromhex(window['bytes'])) == window['window_size_bytes'], 'Data window size differs')
    return view


def _take(value, fields):
    return {key: value[key] for key in fields}


def _code(bundle):
    code = {kind: [] for kind in KINDS}
    mapping = []
    for position, function in enumerate(bundle['functions'], 1):
        fid = f'F{position:04d}'
        for kind, prefix in zip(KINDS, ('A', 'D')):
            source = function['instructions'] if kind == 'assembly' else function['decompilation']['text'].split('\n')
            lines = []
            for index, item in enumerate(source, 1):
                reference = f'{prefix}:{fid}:L{index:05d}'
                lines.append({'reference': reference, **(_take(item, ('address', 'mnemonic', 'operands'))
                                                        if kind == 'assembly' else {'text': item})})
                mapping.append({'reference': reference, 'representation': kind, 'function_id': fid,
                                'source_function_index': position, 'function_entry': function['entry'],
                                **({'source_instruction_index': index, 'address': item['address']}
                                   if kind == 'assembly' else {'source_line_index': index})})
            code[kind].append({'function_id': fid, 'lines': lines})
    return code, mapping


def project(bundle, representation, *, schema=None, parent_schema=None):
    """Project solely from public evidence; construct every nested object by allowlist."""
    require(representation in CONDITIONS, 'Unknown representation')
    bundles.validate(bundle, schema=parent_schema)
    require(bundle['status'] == 'available', 'Parent bundle unavailable; no projection')
    code, _ = _code(bundle)
    windows = []
    for window in bundle['data']:
        windows.append({**_take(window, ('address', 'bytes', 'writable', 'storage', 'truncated')),
                        'references': list(window['references']), 'window_size_bytes': window['size'],
                        'window_origin': 'recovered_window' if window['extent_status'] == 'recovered_type_extent'
                        else 'unknown_window', 'window_semantics': 'available_bytes_not_object_capacity'})
    shared = {'architecture': bundle['architecture'], 'entry_address': bundle['entry_address'],
              'assumptions': list(bundle['assumptions']),
              'functions': [{'id': f'F{i:04d}', **_take(f, ('entry', 'name'))}
                            for i, f in enumerate(bundle['functions'], 1)],
              'calls': [_take(c, ('caller', 'site', 'target_address', 'target_entry', 'target_name', 'kind', 'resolution'))
                        for c in bundle['calls']],
              'data': windows,
              'recovery': {**_take(bundle['completeness'], ('traversal', 'data', 'decompilation',
                                                           'external_bodies', 'localization')),
                           'omissions': [_take(o, ('reason', 'address')) for o in bundle['completeness']['omissions']],
                           'unresolved_transfers': [_take(t, ('caller', 'site', 'kind', 'reason'))
                                                    for t in bundle['unresolved_transfers']]}}
    view = {'schema_version': 1, 'representation': representation, 'shared': shared,
            **{kind: code[kind] for kind in KINDS if representation in (kind, 'combined')}}
    return validate(view, schema=schema, parent_schema=parent_schema)


def render(conditions, raw_bundles, schema, parent_schema):
    """Deterministic projection/audit from public sources and condition identities only."""
    grouped = {}
    for condition in conditions:
        obs, representation = condition['observation_id'], condition['representation']
        require(IDENTIFIER.fullmatch(obs) and representation in CONDITIONS, 'Invalid observation/condition identity')
        require(condition['view_path'] == f'public/views/{representation}/{obs}.json'
                and condition['bundle_path'] == f'public/bundles/{obs}.json', 'Unexpected view/source path')
        require(representation not in grouped.setdefault(obs, {}), 'Duplicate observation-condition unit')
        grouped[obs][representation] = condition
    require(set(grouped) == set(raw_bundles), 'Projection source inventory differs')
    content, ledger, audit_rows = {}, [], []
    for obs, units in sorted(grouped.items()):
        require(set(units) == set(CONDITIONS), 'Missing representation condition')
        raw = raw_bundles[obs]
        parent_hash = hashlib.sha256(raw).hexdigest()
        bundle = strict_json(raw.decode('utf-8'))
        require(bundles.canonical(bundle).encode('utf-8') == raw, 'Noncanonical parent bytes')
        views = {rep: project(bundle, rep, schema=schema, parent_schema=parent_schema) for rep in CONDITIONS}
        # A second independent parse/projection detects state/mutation dependencies.
        for rep in CONDITIONS:
            require(bundles.canonical(views[rep]) == bundles.canonical(project(
                strict_json(raw.decode('utf-8')), rep, schema=schema, parent_schema=parent_schema)),
                'Repeated projection differs')
        require(views['assembly']['shared'] == views['decompilation']['shared'] == views['combined']['shared'],
                'Shared context differs')
        require(all(views[kind][kind] == views['combined'][kind] for kind in KINDS), 'Combined subset differs')
        require(bundles.canonical(bundle).encode('utf-8') == raw, 'Projection mutated parent bundle')
        _, mapping = _code(bundle)
        map_path = f'private/line-maps/{obs}.json'
        line_map = {'parent_bundle_sha256': parent_hash, 'lines': mapping}
        content[map_path] = bundles.canonical(line_map).encode('utf-8')
        counts = {kind: sum(len(f['lines']) for f in views[kind][kind]) for kind in KINDS}
        audit_rows.append({'observation_id': obs, 'functions': len(bundle['functions']), **counts,
                           'shared_context_sha256': inventory.identity(views['combined']['shared']),
                           'repeat_projection_identical': True, 'shared_context_identical': True,
                           'combined_subsets_identical': True})
        for rep in CONDITIONS:
            condition = units[rep]
            require(condition['parent_bundle_sha256'] == parent_hash, 'Parent bundle identity differs')
            encoded = bundles.canonical(views[rep]).encode('utf-8')
            content[condition['view_path']] = encoded
            ledger.append({'observation_id': obs, 'representation': rep, 'condition_id': condition['condition_id'],
                           'parent_bundle_sha256': parent_hash, 'view_path': condition['view_path'],
                           'view_sha256': hashlib.sha256(encoded).hexdigest(), 'view_utf8_bytes': len(encoded),
                           'line_map_path': map_path, 'line_map_sha256': hashlib.sha256(content[map_path]).hexdigest(),
                           'visible_references': len(visible_references(views[rep]))})
    audit = {'schema_version': 1, 'status': 'passed', 'observations': len(grouped), 'views': len(ledger),
             'representation_counts': dict(Counter(row['representation'] for row in ledger)),
             'source_immutable': True, 'oracle_input': False, 'token_fit': 'pending_preflight', 'rows': audit_rows}
    content['coordinator/views.json'] = bundles.canonical(ledger).encode('utf-8')
    content['coordinator/audit.json'] = bundles.canonical(audit).encode('utf-8')
    return content


def prepare(inputs, directory, expected_input_manifest_sha256=None):
    inputs, directory = Path(inputs).resolve(), Path(directory).absolute()
    require(not directory.exists() and not directory.is_symlink(), 'Projection destination already exists')
    require(not directory.resolve().is_relative_to(inputs) and not inputs.is_relative_to(directory.resolve()),
            'Projection destination overlaps inputs')
    receipt = inventory.verify(inputs, expected_input_manifest_sha256)
    schema, parent_schema = read_json(SCHEMA), read_json(inputs/'private/parent/schemas/bundle-v2.json')
    conditions = read_json(inputs/'coordinator/conditions.json')
    sources = {p.stem: p.read_bytes() for p in (inputs/'public/bundles').glob('*.json')}
    content = render(conditions, sources, schema, parent_schema)
    require(digest(inputs/inventory.MANIFEST) == receipt['manifest_sha256'], 'Input manifest changed during projection')
    content['coordinator/input-manifest.json'] = plain_file(inputs, inventory.MANIFEST).read_bytes()
    content['coordinator/conditions.json'] = plain_file(inputs, 'coordinator/conditions.json').read_bytes()
    content['schemas/view.json'] = SCHEMA.read_bytes()
    content['schemas/bundle-v2.json'] = plain_file(inputs, 'private/parent/schemas/bundle-v2.json').read_bytes()
    content.update({f'source/bundles/{obs}.json': raw for obs, raw in sources.items()})
    manifest = {'schema_version': 1, 'status': 'views_projected_not_tokenized',
                'input_manifest_sha256': receipt['manifest_sha256'], 'counts': receipt['counts'],
                'files': {name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(content.items())}}
    directory.mkdir(parents=True, exist_ok=False)
    for name, raw in sorted(content.items()):
        path = local_path(directory, name)
        write_new(path, raw.decode('utf-8'))
        path.chmod(0o444)
    write_new(directory/MANIFEST, manifest)
    (directory/MANIFEST).chmod(0o444)
    return verify(directory)


def verify(directory, expected_manifest_sha256=None):
    """Validate/regenerate saved views without the Phase 1 workspace, oracle or network."""
    directory = Path(directory).resolve()
    manifest_path = plain_file(directory, MANIFEST)
    if expected_manifest_sha256 is not None:
        require(digest(manifest_path) == expected_manifest_sha256, 'Projection manifest changed')
    manifest = read_json(manifest_path)
    require(manifest['schema_version'] == 1 and manifest['status'] == 'views_projected_not_tokenized',
            'Unknown projection manifest')
    nodes = list(directory.rglob('*'))
    require(not any(p.is_symlink() for p in nodes), 'Projection symlinks are not allowed')
    require({p.relative_to(directory).as_posix() for p in nodes if p.is_file()} == set(manifest['files']) | {MANIFEST},
            'Projection file inventory differs')
    for name, expected in manifest['files'].items():
        require(digest(plain_file(directory, name)) == expected, f'Changed projection file: {name}')
    source_manifest = plain_file(directory, 'coordinator/input-manifest.json')
    require(digest(source_manifest) == manifest['input_manifest_sha256'], 'Phase 1 input identity differs')
    inputs = read_json(source_manifest)
    require(inputs['counts'] == manifest['counts'], 'Projection counts differ')
    for target, original in [('coordinator/conditions.json', 'coordinator/conditions.json'),
                             ('schemas/bundle-v2.json', 'private/parent/schemas/bundle-v2.json')]:
        require(digest(plain_file(directory, target)) == inputs['files'][original], 'Source metadata differs')
    sources = {p.stem: p.read_bytes() for p in (directory/'source/bundles').glob('*.json')}
    for obs, raw in sources.items():
        require(hashlib.sha256(raw).hexdigest() == inputs['files'][f'public/bundles/{obs}.json'],
                'Source bundle differs from Phase 1')
    conditions = read_json(directory/'coordinator/conditions.json')
    require(len(sources) == inputs['counts']['observations']
            and len(conditions) == inputs['counts']['observation_condition_units'], 'Incomplete view inventory')
    regenerated = render(conditions, sources, read_json(directory/'schemas/view.json'),
                          read_json(directory/'schemas/bundle-v2.json'))
    for name, raw in regenerated.items():
        require(plain_file(directory, name).read_bytes() == raw, f'Projection audit differs: {name}')
    return {'status': manifest['status'], 'observations': len(sources), 'views': len(conditions),
            'input_manifest_sha256': manifest['input_manifest_sha256'], 'manifest_sha256': digest(manifest_path)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'verify'))
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--inputs', type=Path)
    parser.add_argument('--input-manifest-sha256')
    parser.add_argument('--manifest-sha256')
    args = parser.parse_args()
    if args.action == 'prepare':
        require(args.inputs is not None, 'prepare requires --inputs')
        result = prepare(args.inputs, args.directory, args.input_manifest_sha256)
    else:
        result = verify(args.directory, args.manifest_sha256)
    print(bundles.canonical(result), end='')


if __name__ == '__main__':
    main()
