"""Exact projection, field-origin boundaries, line references and immutable view audits."""
from copy import deepcopy

import pytest
from jsonschema import ValidationError

from optimization_vuln_analysis.studies.representation import inventory, views
from optimization_vuln_analysis.inputs import bundles
from optimization_vuln_analysis.inputs.corpus import ROOT, read_json
from tests.support.parent import put


def test_exact_views_use_shared_data_and_union_of_code_only(small):
    original = deepcopy(small)
    a, d, both = (views.project(small, kind) for kind in views.CONDITIONS)
    assert small == original
    assert set(a) == {'schema_version', 'representation', 'shared', 'assembly'}
    assert set(d) == {'schema_version', 'representation', 'shared', 'decompilation'}
    assert set(both) == {'schema_version', 'representation', 'shared', 'assembly', 'decompilation'}
    assert a['shared'] == d['shared'] == both['shared']
    assert both['assembly'] == a['assembly'] and both['decompilation'] == d['decompilation']
    assert a['shared']['functions'] == [
        {'id': 'F0001', 'entry': '0x1000', 'name': 'entry'},
        {'id': 'F0002', 'entry': '0x2000', 'name': 'process'}]
    assert a['assembly'][0] == {'function_id': 'F0001', 'lines': [
        {'reference': 'A:F0001:L00001', 'address': '0x1000', 'mnemonic': 'NOP', 'operands': ''},
        {'reference': 'A:F0001:L00002', 'address': '0x1001', 'mnemonic': 'RET', 'operands': ''}]}
    assert d['decompilation'][1] == {'function_id': 'F0002', 'lines': [
        {'reference': 'D:F0002:L00001', 'text': 'void process(void) { return; }'}]}
    assert a['shared']['calls'] == small['calls']
    assert a['shared']['data'] == [{
        'address': '0x3000', 'bytes': '41424300', 'writable': False, 'storage': 'initialized',
        'references': ['0x2000'], 'truncated': False, 'window_size_bytes': 4,
        'window_origin': 'recovered_window', 'window_semantics': 'available_bytes_not_object_capacity'}]
    assert views.visible_references(both) == views.visible_references(a) | views.visible_references(d)
    # Nothing in a returned view may alias a mutable parent field or another view.
    a['shared']['assumptions'].append('changed')
    a['shared']['data'][0]['references'].append('0x1111')
    a['shared']['calls'][0]['target_name'] = 'changed'
    assert small == original and both['shared'] == d['shared']


def test_decompilation_preserves_lf_blank_lines_indentation_literals_and_unicode(small):
    text = '\nvoid entry(void)\r\n{\n\n  print("λ 0x401000 MOV RAX,RSP");\n}\n'
    small['functions'][0]['decompilation']['text'] = text
    small['functions'][0]['instructions'][0]['operands'] = '0x00401000'
    d = views.project(small, 'decompilation')
    a = views.project(small, 'assembly')
    lines = d['decompilation'][0]['lines']
    assert [line['text'] for line in lines] == ['', 'void entry(void)\r', '{', '',
                                             '  print("λ 0x401000 MOV RAX,RSP");', '}', '']
    assert '\n'.join(line['text'] for line in lines) == text
    assert [line['reference'] for line in lines] == [f'D:F0001:L{n:05d}' for n in range(1, 8)]
    assert a['assembly'][0]['lines'][0]['operands'] == '0x00401000'
    assert 'λ' in bundles.canonical(d) and '\\u03bb' not in bundles.canonical(d)
    # Address/instruction-shaped text is allowed when its origin is pseudocode.
    views.validate(d)


def test_metadata_type_descriptions_omitted_while_pseudocode_types_remain(small):
    small['data'][0]['recovered_type'] = 'char[123456]'
    small['functions'][0]['decompilation']['text'] = 'char values[17];\n'
    for kind in views.CONDITIONS:
        view = views.project(small, kind)
        assert '123456' not in bundles.canonical(view)
        assert ('char values[17]' in bundles.canonical(view)) == (kind != 'assembly')
    small['data'][0]['extent_status'] = 'unknown_window'
    small['data'][0]['writable'] = True
    small['completeness']['data'] = 'uncertain'
    view = views.project(small, 'assembly')
    assert view['shared']['data'][0]['window_origin'] == 'unknown_window'
    assert view['shared']['data'][0]['writable'] is True
    assert view['shared']['data'][0]['bytes'] == small['data'][0]['bytes']


@pytest.mark.parametrize('location', ['root', 'function', 'instruction', 'decompilation', 'call',
                                     'data', 'recovery', 'omission', 'transfer'])
def test_private_parent_metadata_rejected_even_when_nested(small, location):
    targets = {'root': small, 'function': small['functions'][0],
               'instruction': small['functions'][0]['instructions'][0],
               'decompilation': small['functions'][0]['decompilation'], 'call': small['calls'][0],
               'data': small['data'][0], 'recovery': small['completeness']}
    if location == 'omission':
        small['completeness']['omissions'] = [{'reason': 'function_limit', 'address': None, 'private_capacity': 20}]
    elif location == 'transfer':
        small['unresolved_transfers'] = [{'caller': '0x1000', 'site': '0x1000', 'kind': 'call',
                                        'reason': 'indirect_transfer', 'oracle_label': 'safe'}]
    else:
        targets[location]['private_capacity'] = 20
    for kind in views.CONDITIONS:
        with pytest.raises((ValueError, ValidationError)): views.project(small, kind)


@pytest.mark.parametrize('location', ['root', 'shared', 'function', 'call', 'window', 'recovery',
                                     'assembly_function', 'assembly_line', 'decompilation_function', 'decompilation_line'])
def test_view_schema_rejects_additional_properties_at_every_object_boundary(small, location):
    view = views.project(small, 'combined')
    targets = {'root': view, 'shared': view['shared'], 'function': view['shared']['functions'][0],
               'call': view['shared']['calls'][0], 'window': view['shared']['data'][0],
               'recovery': view['shared']['recovery'], 'assembly_function': view['assembly'][0],
               'assembly_line': view['assembly'][0]['lines'][0],
               'decompilation_function': view['decompilation'][0],
               'decompilation_line': view['decompilation'][0]['lines'][0]}
    targets[location]['private_capacity'] = 20
    with pytest.raises(ValidationError): views.validate(view)


@pytest.mark.parametrize('mutation', ['assembly_has_pseudocode', 'decompilation_has_instructions',
                                     'decompilation_has_assembly_array', 'assembly_has_decompilation_array',
                                     'instruction_bytes', 'instruction_size', 'pcode', 'data_type',
                                     'string_interpretation', 'body_ranges', 'missing_combined_code'])
def test_representation_field_boundaries(small, mutation):
    kind = 'decompilation' if mutation.startswith('decompilation') else 'assembly'
    if mutation == 'missing_combined_code': kind = 'combined'
    view = views.project(small, kind)
    if mutation == 'assembly_has_pseudocode': view['assembly'][0]['lines'][0]['text'] = 'void f(void) {}'
    if mutation == 'decompilation_has_instructions': view['decompilation'][0]['lines'][0]['address'] = '0x1000'
    if mutation == 'decompilation_has_assembly_array': view['assembly'] = []
    if mutation == 'assembly_has_decompilation_array': view['decompilation'] = []
    if mutation == 'instruction_bytes': view['assembly'][0]['lines'][0]['bytes'] = '90'
    if mutation == 'instruction_size': view['assembly'][0]['lines'][0]['size'] = 1
    if mutation == 'pcode': view['shared']['pcode'] = []
    if mutation == 'data_type': view['shared']['data'][0]['recovered_type'] = 'char[4]'
    if mutation == 'string_interpretation': view['shared']['data'][0]['string_prefix'] = 'ABC'
    if mutation == 'body_ranges': view['shared']['functions'][0]['ranges'] = []
    if mutation == 'missing_combined_code': del view['decompilation']
    with pytest.raises(ValidationError): views.validate(view)


@pytest.mark.parametrize('mutation', ['function_order', 'function_identity', 'line_reference', 'duplicate_reference',
                                     'wrong_prefix', 'code_function_omission', 'instruction_order', 'window_size'])
def test_noncanonical_view_structure_rejected(small, mutation):
    view = views.project(small, 'combined')
    if mutation == 'function_order': view['shared']['functions'].reverse()
    if mutation == 'function_identity': view['shared']['functions'][0]['id'] = 'F0000'
    if mutation == 'line_reference': view['assembly'][0]['lines'][0]['reference'] = 'A:F0001:L99999'
    if mutation == 'duplicate_reference': view['assembly'][0]['lines'][1]['reference'] = 'A:F0001:L00001'
    if mutation == 'wrong_prefix': view['decompilation'][0]['lines'][0]['reference'] = 'A:F0001:L00001'
    if mutation == 'code_function_omission': view['assembly'].pop()
    if mutation == 'instruction_order': view['assembly'][0]['lines'].reverse()
    if mutation == 'window_size': view['shared']['data'][0]['window_size_bytes'] = 5
    with pytest.raises((ValueError, ValidationError)): views.validate(view)


def test_unavailable_or_noncanonical_parent_cannot_be_silently_projected(small):
    small['functions'].reverse()
    with pytest.raises(ValueError, match='ordering'): views.project(small, 'combined')
    small['functions'].reverse()
    small['status'] = 'context_unavailable'
    small['completeness']['omissions'] = [{'reason': 'function_limit', 'address': None}]
    with pytest.raises(ValueError, match='unavailable'): views.project(small, 'combined')


def test_accepted_pilot_views_repeat_without_oracle_or_input_mutation():
    for path in sorted((ROOT/'data/pilot/records').glob('*.json')):
        raw = path.read_bytes()
        views_by_kind = {kind: views.project(read_json(path), kind) for kind in views.CONDITIONS}
        for kind, view in views_by_kind.items():
            assert bundles.canonical(view) == bundles.canonical(views.project(read_json(path), kind))
        assert views_by_kind['assembly']['shared'] == views_by_kind['decompilation']['shared']
        assert views_by_kind['combined']['assembly'] == views_by_kind['assembly']['assembly']
        assert views_by_kind['combined']['decompilation'] == views_by_kind['decompilation']['decompilation']
        assert path.read_bytes() == raw


def test_bound_batch_is_repeatable_offline_and_has_auditable_lineage(parent_fixture, tmp_path, monkeypatch):
    parent, _, policy_path = parent_fixture
    inputs = tmp_path/'inputs'
    receipt = inventory.prepare(parent, inputs, policy_path)
    import requests
    monkeypatch.setattr(requests, 'Session', lambda: pytest.fail('Projection attempted network access'))
    first, second = tmp_path/'views-one', tmp_path/'views-two'
    result = views.prepare(inputs, first, receipt['manifest_sha256'])
    views.prepare(inputs, second, receipt['manifest_sha256'])
    assert result['observations'] == 32 and result['views'] == 96
    assert result['manifest_sha256'] == inventory.digest(second/views.MANIFEST)
    assert {p.relative_to(first): p.read_bytes() for p in first.rglob('*') if p.is_file()} == {
        p.relative_to(second): p.read_bytes() for p in second.rglob('*') if p.is_file()}
    row = read_json(first/'coordinator/views.json')[0]
    mapping = read_json(first/row['line_map_path'])
    assert mapping['parent_bundle_sha256'] == row['parent_bundle_sha256']
    assert mapping['lines'][0] == {'reference': 'A:F0001:L00001', 'representation': 'assembly',
        'function_id': 'F0001', 'source_function_index': 1, 'function_entry': '0x1000',
        'source_instruction_index': 1, 'address': '0x1000'}
    assert mapping['lines'][1]['reference'] == 'D:F0001:L00001'
    assert not list(first.rglob('*oracle*')) and not (first/'private/evaluation.json').exists()
    inputs.rename(tmp_path/'inputs-unavailable'); parent.rename(tmp_path/'parent-unavailable')
    monkeypatch.setattr(inventory, 'verify', lambda *a: pytest.fail('View verification used private input verifier'))
    assert views.verify(first, result['manifest_sha256']) == result
    with pytest.raises(ValueError, match='destination already exists'): views.prepare(inputs, first)


@pytest.mark.parametrize('mutation', ['view', 'extra', 'missing', 'schema', 'lineage', 'rehashed_view'])
def test_saved_projection_corruption_is_rejected_without_rewriting(parent_fixture, tmp_path, mutation):
    parent, _, policy_path = parent_fixture
    inputs, output = tmp_path/'inputs', tmp_path/'views'
    inventory.prepare(parent, inputs, policy_path)
    views.prepare(inputs, output)
    ledger = read_json(output/'coordinator/views.json')
    name = ledger[0]['view_path']
    if mutation == 'missing': (output/name).unlink()
    if mutation == 'extra': put(output, 'public/views/extra.json', {})
    if mutation == 'schema': put(output, 'schemas/view.json', {})
    if mutation == 'lineage': put(output, ledger[0]['line_map_path'], {})
    if mutation in ('view', 'rehashed_view'):
        view = read_json(output/name); view['assembly'][0]['lines'][0]['mnemonic'] = 'CHANGED'
        path = put(output, name, bundles.canonical(view).encode())
        if mutation == 'rehashed_view':
            manifest = read_json(output/views.MANIFEST); manifest['files'][name] = inventory.digest(path)
            put(output, views.MANIFEST, manifest)
    before = {p.relative_to(output): p.read_bytes() for p in output.rglob('*') if p.is_file()}
    with pytest.raises(ValueError): views.verify(output)
    assert {p.relative_to(output): p.read_bytes() for p in output.rglob('*') if p.is_file()} == before
