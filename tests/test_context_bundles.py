"""Public bundle validation, leakage, ordering and availability contracts."""
from copy import deepcopy

import pytest
from jsonschema import ValidationError

from optimization_vuln_analysis.inputs import bundles
from optimization_vuln_analysis.inputs.corpus import ROOT, generate, read_json


@pytest.fixture
def policy():
    return read_json(ROOT / 'context_policy.json')


def test_multifunction_evidence_disjoint_bodies_and_order(small):
    bundles.validate(small)
    bundles.evidence_addresses(small, ['0x1000', '0x2001'])
    with pytest.raises(ValueError, match='outside'):
        bundles.evidence_addresses(small, ['0x3000'])
    with pytest.raises(ValueError):
        bundles.evidence_addresses(small, ['0x1002'])
    # Multiple emitted ranges in one function do not require an enclosing flat interval.
    second = small['functions'][1]
    second['ranges'] = [{'start': '0x2000', 'end': '0x2001'}, {'start': '0x2200', 'end': '0x2201'}]
    second['instructions'][1]['address'] = '0x2200'
    bundles.validate(small)
    second['instructions'][1]['address'] = '0x2100'
    with pytest.raises(ValueError, match='outside function'):
        bundles.validate(small)
    small['functions'].reverse()
    with pytest.raises(ValueError, match='ordering'):
        bundles.validate(small)


@pytest.mark.parametrize('mutation', ['source_bound', 'label', 'restored_name', 'path', 'treatment',
                                     'missing_callee', 'unreachable', 'call_site', 'data_site', 'duplicate',
                                     'empty_decompilation', 'unresolved', 'overlap', 'invented_literal', 'encoded_label'])
def test_reject_private_fields_and_inconsistent_available_bundles(small, mutation):
    if mutation == 'source_bound': small['functions'][0]['source_capacity'] = 10
    if mutation == 'label': small['binary_label'] = 'not_vulnerable'
    if mutation == 'restored_name': small['functions'][1]['name'] = 'CWE121_goodG2B'
    if mutation == 'path': small['functions'][0]['decompilation']['text'] += '/experiment/corpus/unit.c'
    if mutation == 'treatment': small['functions'][0]['decompilation']['text'] += ' O3'
    if mutation == 'missing_callee': small['functions'].pop()
    if mutation == 'unreachable': small['calls'] = []
    if mutation == 'call_site': small['calls'][0]['site'] = '0x9999'
    if mutation == 'data_site': small['data'][0]['references'] = ['0x9999']
    if mutation == 'duplicate': small['functions'].append(deepcopy(small['functions'][0]))
    if mutation == 'empty_decompilation': small['functions'][1]['decompilation']['text'] = ''
    if mutation == 'unresolved':
        small['unresolved_transfers'] = [{'caller': '0x1000', 'site': '0x1000', 'kind': 'call', 'reason': 'indirect_transfer'}]
    if mutation == 'overlap': small['functions'][0]['instructions'][1]['address'] = '0x1000'
    if mutation == 'invented_literal': small['data'][0]['string_prefix'] = 'arbitrary source text'
    if mutation == 'encoded_label':
        small['data'][0].update(size=7, bytes=b'CWE121\0'.hex(), string_prefix=None)
    with pytest.raises((ValueError, ValidationError)):
        bundles.validate(small)


@pytest.mark.parametrize('limit', ['max_functions', 'max_instructions', 'max_data_bytes',
                                 'max_data_bytes_per_reference', 'max_bundle_utf8_bytes', 'max_token_upper_bound'])
def test_no_available_silent_budget_truncation(small, policy, limit):
    policy[limit] = 1
    result = bundles.apply_budget(small, policy)
    assert result['status'] == 'context_unavailable'
    assert result['functions'] == small['functions']
    assert result['data'] == small['data']
    assert result['completeness']['omissions']
    bundles.validate(result)


def test_unknown_data_and_failed_decompilation_are_explicit(small):
    small['data'][0]['extent_status'] = 'unknown_window'
    small['completeness']['data'] = 'uncertain'
    bundles.validate(small)
    small['functions'][0]['decompilation'] = {'status': 'timeout', 'text': ''}
    with pytest.raises(ValueError, match='incomplete'):
        bundles.validate(small)
    small['status'] = 'extraction_unavailable'
    small['completeness'].update(decompilation='incomplete', omissions=[{'reason': 'decompilation_failed', 'address': '0x1000'}])
    bundles.validate(small)


def test_policy_rejects_unimplemented_rules(policy):
    bundles.policy_check(policy)
    for field, value in (('max_functions', 0), ('max_instructions', True), ('allow_assembly_only', True),
                         ('unresolved_transfers', 'ignore'), ('compiler_spec', 'windows')):
        changed = deepcopy(policy); changed[field] = value
        with pytest.raises(ValueError): bundles.policy_check(changed)


def test_all_accepted_pilot_bundles_remain_valid_and_canonical():
    plan = generate(read_json(ROOT/'config.json'), read_json(ROOT/'corpus/manifest.json'),
                    ROOT, 'pilot', require_assigned=True)
    expected = {row['observation_id']+'.json' for row in plan['observations']}
    directory = ROOT/'data/pilot/records'
    assert len(expected) == 32 and {p.name for p in directory.iterdir()} == expected
    for name in sorted(expected):
        path = directory/name
        bundle = read_json(path)
        assert bundle['status'] == 'available'
        bundles.validate(bundle)
        assert path.read_bytes() == bundles.canonical(bundle).encode('utf-8')
