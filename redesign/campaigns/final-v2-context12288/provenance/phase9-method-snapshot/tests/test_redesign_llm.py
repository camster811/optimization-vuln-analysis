"""Phase 6 boundary, response, identity and no-retry regression tests."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from redesign.pipeline import llm, llm_runtime as runtime, run_llm as runner
from redesign.pipeline.inventory import ROOT, read_json


@pytest.fixture
def bundle():
    return read_json(next((ROOT/'data/pilot/records').glob('*.json')))


@pytest.fixture
def settings():
    return llm.settings()


def answer(bundle, label='uncertain', confidence=.5):
    return {'decision': label, 'confidence': confidence,
            'evidence': [bundle['functions'][-1]['instructions'][0]['address']], 'summary': 'Insufficient bounds.'}


def envelope(value, finish='stop'):
    return json.dumps({'choices': [{'message': {'content': json.dumps(value), 'reasoning_content': 'analysis'},
                                   'finish_reason': finish}], 'usage': {'prompt_tokens': 20, 'completion_tokens': 30}})


def test_cross_function_evidence(bundle, settings):
    schema = settings[2]
    assert llm.decode(envelope(answer(bundle)), 200, bundle, schema)['status'] == 'valid'
    invalid = answer(bundle); invalid['evidence'] = ['0xffffffffffff']
    assert llm.decode(envelope(invalid), 200, bundle, schema)['status'] == 'schema_invalid'
    invalid['evidence'] = [bundle['data'][0]['address']]
    assert llm.decode(envelope(invalid), 200, bundle, schema)['status'] == 'schema_invalid'


@pytest.mark.parametrize('finish,status', [('length', 'length_limit'), ('stop', 'valid'), ('tool_calls', 'schema_invalid')])
def test_finish_reason(bundle, settings, finish, status):
    result = llm.decode(envelope(answer(bundle), finish), 200, bundle, settings[2])
    assert result['status'] == status
    assert result['raw_reasoning'] == 'analysis'


@pytest.mark.parametrize('change', [{'confidence': float('nan')}, {'confidence': True}, {'confidence': 1.1},
                                     {'summary': '  '}, {'extra': 1}, {'decision': 'safe'}])
def test_invalid_answers(bundle, settings, change):
    value = answer(bundle); value.update(change)
    assert llm.decode(envelope(value), 200, bundle, settings[2])['status'] != 'valid'


@pytest.mark.parametrize('body', ['{}', 'null', '[]', '{', '{"choices":[{"message":null,"finish_reason":"stop"}]}'])
def test_bad_envelopes(bundle, settings, body):
    assert llm.decode(body, 200, bundle, settings[2])['status'] != 'valid'


def test_stateless_payload(bundle, settings):
    policy, prompt, schema = settings
    first = llm.payload(bundle, prompt, schema, policy, 1)
    second = llm.payload(bundle, prompt, schema, policy, 2)
    assert first.pop('seed') == 4101 and second.pop('seed') == 4102
    assert first == second and first['cache_prompt'] is False
    assert first['max_tokens'] == 4096 and len(first['messages']) == 1


@pytest.mark.parametrize('count,status', [(4096, 'available'), (4097, 'context_unavailable')])
def test_exact_budget(monkeypatch, settings, count, status):
    calls = []
    def query(policy, method, path, payload):
        calls.append((path, payload))
        return {'prompt': 'rendered'} if path == '/apply-template' else {'tokens': [1] * count}
    monkeypatch.setattr(runtime, 'query', query)
    result = runtime.budget({'messages': []}, settings[0])
    assert result['status'] == status
    assert calls[-1][1] == {'content': 'rendered', 'add_special': True, 'parse_special': True}


def test_aggregation():
    rows = [{'status': 'valid', 'parsed': {'decision': label, 'confidence': c}}
            for label, c in [('CWE-121', .2), ('CWE-121', .9), ('uncertain', .8)]]
    result = llm.aggregate(rows)
    assert result['decision'] == 'CWE-121' and result['confidence'] == .8
    rows[1]['parsed']['decision'] = 'CWE-122'
    assert llm.aggregate(rows)['decision'] == 'uncertain'
    assert llm.aggregate([{'status': 'timeout'}]*3)['status'] == 'unavailable'


@pytest.fixture
def prepared(tmp_path, monkeypatch, bundle, settings):
    root = tmp_path/'root'; root.mkdir()
    for name, value in [('llm_policy.json', settings[0]), ('llm/response.schema.json', settings[2]),
                        ('config.json', {}), ('corpus/manifest.json', {}), ('data/pilot/records/r1.json', bundle)]:
        runtime.write_new(root/name, value)
    runtime.write_new(root/'llm/prompt.md', settings[1])
    slots = [{'observation_id': 'r1', 'repetition': n, 'seed': 4100+n,
              'order_sha256': hashlib.sha256(f'20261019\nr1\n{n}'.encode()).hexdigest()} for n in range(1,4)]
    plan = {'observations': [{'observation_id': 'r1', 'record_path': 'data/pilot/records/r1.json'}],
            'inference_slots': sorted(slots, key=lambda s: s['order_sha256'])}
    monkeypatch.setattr(runner, 'generate', lambda *a: plan)
    monkeypatch.setattr(runner, 'check_record_inventory', lambda *a: {})
    monkeypatch.setattr(runtime, 'verify_live', lambda *a: None)
    monkeypatch.setattr(runtime, 'budget', lambda *a: {'status': 'available', 'prompt_tokens': 1,
        'reserved_completion_tokens': 4096, 'total_budget': 4097, 'rendered_prompt': 'x', 'token_ids': [1]})
    server = tmp_path/'server.json'; runtime.write_new(server, {})
    directory = tmp_path/'run'; runner.prepare(directory, server, root)
    return directory, root


def test_dispatch_crash_never_retried(prepared, monkeypatch):
    directory, root = prepared
    calls = []
    def crash(*args): calls.append(1); raise RuntimeError('crash after dispatch')
    monkeypatch.setattr(llm, 'attempt', crash)
    with pytest.raises(RuntimeError): runner.run(directory, root, max_slots=1)
    assert len(calls) == 1
    monkeypatch.setattr(llm, 'attempt', lambda *a: {'status': 'timeout', 'parsed': None, 'response_body': None})
    result = runner.run(directory, root)
    assert result['attempt_statuses'] == {'interrupted': 1, 'timeout': 2}
    monkeypatch.setattr(llm, 'attempt', crash)
    runner.run(directory, root)
    assert len(calls) == 1


def test_prompt_mutation_blocks(prepared):
    directory, root = prepared
    (root/'llm/prompt.md').write_text('changed {{BUNDLE_JSON}}')
    with pytest.raises(ValueError, match='prompt'): runner.run(directory, root)
    assert not list(directory.glob('slots/*/dispatch.json'))


def test_corrupt_terminal_blocks(prepared, monkeypatch):
    directory, root = prepared
    monkeypatch.setattr(llm, 'attempt', lambda *a: {'status': 'timeout', 'parsed': None, 'response_body': None})
    runner.run(directory, root, max_slots=1)
    next(directory.glob('slots/*/result.json')).write_text('{')
    with pytest.raises(ValueError): runner.run(directory, root)
    assert len(list(directory.glob('slots/*/dispatch.json'))) == 1


def test_runtime_change_blocks(prepared, monkeypatch):
    directory, root = prepared
    def changed(*args): raise ValueError('Server identity changed')
    monkeypatch.setattr(runtime, 'verify_live', changed)
    with pytest.raises(ValueError, match='identity'): runner.run(directory, root)
    assert not list(directory.glob('slots/*/dispatch.json'))


def test_exclusive_publication(tmp_path):
    path = tmp_path/'value.json'
    runtime.write_new(path, {'a': 1})
    with pytest.raises(FileExistsError): runtime.write_new(path, {'a': 2})
    assert read_json(path) == {'a': 1}


def test_unavailable_slots_never_dispatch(prepared, monkeypatch):
    directory, root = prepared
    manifest = read_json(directory/'manifest.json')
    for slot in manifest['slots']:
        path = directory/'slots'/runner.slot_name(slot)/'budget.json'
        accounting = read_json(path)
        accounting.update(status='context_unavailable', prompt_tokens=4097, total_budget=8193, token_ids=[1]*4097)
        path.write_text(json.dumps(accounting))
        slot['budget_sha256'] = llm.sha(accounting)
    (directory/'manifest.json').write_text(json.dumps(manifest))
    def forbidden(*a): pytest.fail('Unavailable context dispatched')
    monkeypatch.setattr(llm, 'attempt', forbidden)
    result = runner.run(directory, root)
    assert result['attempt_statuses'] == {'context_unavailable': 3}
    assert result['aggregates']['r1']['status'] == 'unavailable'
    assert not list(directory.glob('slots/*/dispatch.json'))


@pytest.mark.parametrize('field', ['process', 'model_stat', 'libraries', 'props'])
def test_live_identity_mutations(monkeypatch, settings, field):
    policy = settings[0]
    evidence = {'policy_sha256': llm.sha(policy), 'process': {'pid': 1}, 'model_stat': {}, 'libraries': {}, 'props': {}}
    monkeypatch.setattr(runtime, 'process_identity', lambda *a: evidence['process'])
    monkeypatch.setattr(runtime, 'model_stat', lambda *a: {})
    monkeypatch.setattr(runtime, 'libraries', lambda *a: {})
    monkeypatch.setattr(runtime, 'owns_listener', lambda *a: True)
    monkeypatch.setattr(runtime, 'query', lambda *a: {})
    monkeypatch.setattr(runtime, 'props_identity', lambda p: p)
    runtime.verify_live(evidence, policy)
    function = {'process': 'process_identity', 'model_stat': 'model_stat', 'libraries': 'libraries', 'props': 'query'}[field]
    monkeypatch.setattr(runtime, function, lambda *a: {'changed': True})
    with pytest.raises(ValueError): runtime.verify_live(evidence, policy)


def test_timeout_is_terminal(bundle, settings, monkeypatch):
    import requests
    calls = []
    def timeout(*a): calls.append(1); raise requests.Timeout('timeout')
    monkeypatch.setattr(llm, 'send_request', timeout)
    result = llm.attempt({}, bundle, settings[0], settings[2])
    assert result['status'] == 'timeout' and len(calls) == 1
