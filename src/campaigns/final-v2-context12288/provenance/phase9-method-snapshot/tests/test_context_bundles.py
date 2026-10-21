"""Public v2 context contracts and independent binary extraction fixtures."""
from copy import deepcopy
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest
from jsonschema import ValidationError

from redesign.pipeline import bundles, context_worker
from redesign.pipeline.inventory import ROOT, digest, read_json


@pytest.fixture
def policy():
    return read_json(ROOT / 'context_policy.json')


@pytest.fixture
def small():
    def ins(pc, opcode='90', mnemonic='NOP'):
        return {'address': hex(pc), 'size': len(bytes.fromhex(opcode)), 'bytes': opcode,
                'mnemonic': mnemonic, 'operands': ''}
    def function(entry, name, instructions):
        return {'entry': hex(entry), 'name': name, 'name_origin': 'analysis',
                'ranges': [{'start': hex(entry), 'end': hex(entry + 2)}], 'instructions': instructions,
                'decompilation': {'status': 'ok', 'text': f'void {name}(void) {{ return; }}'}}
    value = bundles.empty_bundle('0x1000', 'entry_unavailable')
    value['status'] = 'available'
    value['completeness'].update(traversal='complete', data='complete', decompilation='complete', omissions=[])
    value['functions'] = [function(0x1000, 'entry', [ins(0x1000), ins(0x1001, 'c3', 'RET')]),
                          function(0x2000, 'process', [ins(0x2000), ins(0x2001, 'c3', 'RET')])]
    value['calls'] = [{'caller': '0x1000', 'site': '0x1000', 'target_address': '0x2000',
                       'target_entry': '0x2000', 'target_name': 'process', 'kind': 'tail', 'resolution': 'application'}]
    value['data'] = [{'address': '0x3000', 'size': 4, 'bytes': '41424300', 'string_prefix': 'ABC', 'writable': False,
                      'storage': 'initialized', 'extent_status': 'recovered_type_extent',
                      'recovered_type': 'char[4]', 'interpretation': 'uncertain_binary_recovery_not_an_object_bound',
                      'references': ['0x2000'], 'truncated': False}]
    return value


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


def test_engine_unavailable_is_an_inventory_record(tmp_path, policy, monkeypatch):
    binary = tmp_path / 'input.elf'; binary.write_bytes(b'fixture')
    monkeypatch.delenv('GHIDRA_HOME', raising=False)
    record, trace = context_worker.extract(binary, '0x1000', policy, tmp_path / 'job')
    assert record['status'] == 'extraction_unavailable'
    assert record['completeness']['omissions'][0]['reason'] == 'engine_unavailable'
    assert trace['input_sha256'] == digest(binary)
    bundles.validate(record)


def test_policy_rejects_unimplemented_rules(policy):
    bundles.policy_check(policy)
    for field, value in (('max_functions', 0), ('max_instructions', True), ('allow_assembly_only', True),
                         ('unresolved_transfers', 'ignore'), ('compiler_spec', 'windows')):
        changed = deepcopy(policy); changed[field] = value
        with pytest.raises(ValueError): bundles.policy_check(changed)


GHIDRA = os.environ.get('GHIDRA_HOME')


@pytest.mark.skipif(not GHIDRA, reason='Set GHIDRA_HOME for real v2 context extraction')
def test_real_caller_allocation_helper_write_tail_call_and_literals(tmp_path, policy):
    (tmp_path / 'entry.c').write_text('''#include <stdlib.h>
extern void fill(char *);
extern void report(const char *);
extern void echo(const char *);
static void initial(char *p) { p[1]='I'; }
int main(void) { char *p=malloc(16); if(!p) return 1; fill(p); initial(p); report(p); echo(p); free(p); return 0; }
''')
    (tmp_path / 'helper.c').write_text('''#include <stdio.h>
#include <string.h>
void fill(char *p) { memcpy(p,"sample",7); }
void report(const char *p) { puts(p); puts("complete"); }
void echo(const char *p) { puts(p); }
''')
    objects = []
    for name in ('entry', 'helper'):
        obj = tmp_path / (name + '.o')
        subprocess.run(['gcc-15', '-O2', '-g', '-fno-pie', '-c', str(tmp_path / (name + '.c')), '-o', str(obj)],
                       check=True, capture_output=True)
        objects.append(str(obj))
    reference = tmp_path / 'reference'
    subprocess.run(['gcc-15', '-no-pie', *objects, '-o', str(reference)], check=True, capture_output=True)
    symbols = subprocess.check_output(['nm', '-S', str(reference)], text=True)
    entry = hex(int(re.search(r'^(\w+) \w+ T main$', symbols, re.M)[1], 16))
    retained, stripped = tmp_path / 'retained', tmp_path / 'stripped'
    subprocess.run(['objcopy', '--strip-debug', str(reference), str(retained)], check=True)
    subprocess.run(['strip', '--strip-all', '-o', str(stripped), str(retained)], check=True)
    outputs = []
    for index, binary in enumerate((retained, stripped)):
        bundle, trace = context_worker.extract(binary, entry, policy, tmp_path / f'job-{index}')
        assert bundle['status'] == 'available', (bundle, trace)
        bundles.validate(bundle, binary)
        assert len(bundle['functions']) == 4
        assert {'malloc', 'puts', 'free'} <= {c['target_name'] for c in bundle['calls'] if c['resolution'] == 'external'}
        assert any(c['kind'] == 'tail' and c['target_name'] == 'puts' for c in bundle['calls'])
        assert any(bytes.fromhex(d['bytes']).startswith(b'complete\0') for d in bundle['data'])
        assert all('source_capacity' not in bundles.canonical(f) for f in bundle['functions'])
        outputs.append(bundle)
    assert {'main', 'fill', 'report', 'echo'} == {f['name'] for f in outputs[0]['functions']}
    assert not {'fill', 'report', 'echo'} & {f['name'] for f in outputs[1]['functions']}
    assert not re.search(r'\binitial$', symbols, re.M)  # Ordinary inlining has removed this entry.
    assert {i['address'] for f in outputs[0]['functions'] for i in f['instructions']} == {
        i['address'] for f in outputs[1]['functions'] for i in f['instructions']}
    # A tiny generic cap exposes a partial diagnostic scope as unavailable, never as a usable crop.
    capped = deepcopy(policy); capped['max_functions'] = 1
    bundle, _ = context_worker.extract(stripped, entry, capped, tmp_path / 'job-capped')
    assert bundle['status'] == 'context_unavailable'
    assert any(o['reason'] == 'function_limit' for o in bundle['completeness']['omissions'])
    missing, _ = context_worker.extract(stripped, '0x1', policy, tmp_path / 'job-missing')
    assert missing['status'] == 'extraction_unavailable'
    assert missing['completeness']['omissions'][0]['reason'] == 'entry_function_not_recovered'


@pytest.mark.skipif(not GHIDRA, reason='Set GHIDRA_HOME for real unresolved transfer extraction')
def test_real_indirect_transfer_is_not_silently_dropped(tmp_path, policy):
    source = tmp_path / 'indirect.c'
    source.write_text('int invoke(int (*f)(int), int x) { return f(x); } int main(void) { return 0; }\n')
    reference = tmp_path / 'reference'
    subprocess.run(['gcc-15', '-O0', '-fno-pie', '-no-pie', str(source), '-o', str(reference)], check=True)
    symbols = subprocess.check_output(['nm', '-S', str(reference)], text=True)
    entry = hex(int(re.search(r'^(\w+) \w+ T invoke$', symbols, re.M)[1], 16))
    record, trace = context_worker.extract(reference, entry, policy, tmp_path / 'job')
    assert record['status'] == 'extraction_unavailable', trace
    assert record['unresolved_transfers']
    assert any(r['reason'] == 'indirect_transfer' for r in record['completeness']['omissions'])
