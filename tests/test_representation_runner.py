"""No-retry execution, durable evidence, verified restarts and offline-only replay."""
import fcntl
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from optimization_vuln_analysis.studies.representation import adapter, inventory, replay, runner
from optimization_vuln_analysis.inference import attempts as llm, runtime
from optimization_vuln_analysis.inputs.corpus import read_json
from tests.support.parent import put
from tests.support.execution import accounting, fake_runtime, bind


def test_offline_preparation_uses_existing_schedule_and_needs_preflight(packet):
    directory, control = packet
    before = {p.relative_to(directory): p.read_bytes() for p in directory.rglob('*') if p.is_file()}
    inspection = replay.inspect(directory)
    report = runner.verify(directory)
    assert inspection['state'] == report and inspection['eligibility'] is None
    assert inspection['projection_manifest_sha256'] == read_json(directory/replay.MANIFEST)['projection_manifest_sha256']
    assert not (directory/'runner.lock').exists()
    assert before == {p.relative_to(directory): p.read_bytes() for p in directory.rglob('*') if p.is_file()}
    assert report['slots'] == 288 and report['attempt_statuses'] == {'pending': 288}
    assert report['preflight_bound'] is False and report['purpose'] == 'engineering'
    conditions = read_json(directory/'coordinator/conditions.json')
    observations = {c['observation_id']: {k: c[k] for k in ('observation_id','parent_bundle_sha256','bundle_path')}
                    for c in conditions}
    _, expected = inventory.conditions_and_slots(list(observations.values()), control['policy'])
    actual = read_json(directory/'coordinator/schedule.json')
    assert [{k: s[k] for k in expected[0]} for s in actual] == expected
    assert len({s['slot_path'] for s in actual}) == len({s['slot_id'] for s in actual}) == 288
    first_observation = actual[0]['observation_id']
    for slot in (s for s in actual if s['observation_id'] == first_observation):
        expected_request = adapter.payload(read_json(directory/slot['view_path']),
            (directory/'protocol/prompt.md').read_text(), read_json(directory/'protocol/response.json'),
            control['policy'], slot['repetition'])
        assert (directory/slot['request_path']).read_text() == adapter.wire(expected_request)
    with pytest.raises(ValueError, match='Preflight is not bound'): runner.run(directory)
    assert not control['calls']


def test_full_fake_execution_replays_and_never_reexecutes(packet, monkeypatch):
    directory, control = bind(packet)
    report = runner.run(directory)
    assert report['status'] == 'complete' and report['terminal_slots'] == 288
    assert report['attempt_statuses'] == {'valid': 288} and len(report['aggregates']) == 96
    assert len(set(control['calls'])) == len(control['calls']) == 288
    assert all(a['status'] == 'abstained' for a in report['aggregates'].values())
    before = {p.relative_to(directory): p.read_bytes() for p in directory.rglob('*') if p.is_file()}
    monkeypatch.setattr(runtime, 'verify_live', lambda *a: pytest.fail('Offline replay queried runtime'))
    monkeypatch.setattr(runtime, 'budget', lambda *a: pytest.fail('Offline replay tokenized'))
    monkeypatch.setattr(llm, 'send_request', lambda *a: pytest.fail('Terminal slot retried'))
    assert runner.verify(directory) == report
    assert runner.run(directory) == report
    assert before == {p.relative_to(directory): p.read_bytes() for p in directory.rglob('*') if p.is_file()}


@pytest.mark.parametrize('where', ['before_dispatch', 'after_dispatch', 'after_response'])
def test_interruption_recovers_conservatively_without_retry(packet, monkeypatch, where):
    directory, control = bind(packet)
    slot = read_json(directory/'coordinator/schedule.json')[0]
    original = runner._publish
    def interrupted(path, value, **kwargs):
        if Path(path).name == ('dispatch.json' if where == 'before_dispatch' else
                                'response.json' if where == 'after_dispatch' else 'result.json'):
            raise KeyboardInterrupt('fixture process interruption')
        return original(path, value, **kwargs)
    monkeypatch.setattr(runner, '_publish', interrupted)
    with pytest.raises(KeyboardInterrupt): runner.run(directory, max_slots=1)
    monkeypatch.setattr(runner, '_publish', original)
    before = {p.relative_to(directory): p.read_bytes() for p in directory.rglob('*') if p.is_file()}
    report = runner.verify(directory)
    assert before == {p.relative_to(directory): p.read_bytes() for p in directory.rglob('*') if p.is_file()}
    if where == 'before_dispatch':
        assert report['attempt_statuses'] == {'pending': 288}
        assert not control['calls']
        runner.run(directory, max_slots=1)
        assert control['calls'] == [slot['slot_id']]
    else:
        assert report['attempt_statuses'] == {'interrupted': 1, 'pending': 287}
        assert control['calls'] == [slot['slot_id']]
        runner.run(directory, max_slots=0)
        assert read_json(directory/slot['slot_path']/'result.json')['status'] == 'interrupted'
        runner.run(directory, max_slots=1)
        assert len(control['calls']) == 2 and control['calls'].count(slot['slot_id']) == 1
        assert (directory/slot['slot_path']/'response.json').exists() == (where == 'after_response')


def test_real_os_style_uncommitted_files_are_preserved(packet):
    directory, control = bind(packet)
    slot = read_json(directory/'coordinator/schedule.json')[0]
    put(directory, slot['slot_path']+'/.pending-orphan', b'partial response bytes')
    report = runner.run(directory, max_slots=1)
    assert report['uncommitted_files'] == [slot['slot_path']+'/.pending-orphan']
    assert (directory/slot['slot_path']/'.pending-orphan').read_bytes() == b'partial response bytes'


def test_input_blocking_is_shared_by_all_nine_slots_without_runtime_contact(packet, monkeypatch):
    directory, control = packet
    calls = []
    def budget(request, policy):
        calls.append(1)
        return accounting(policy, 9000 if len(calls) == 1 else 5)
    monkeypatch.setattr(runtime, 'budget', budget)
    runner.preflight(directory, control['evidence'])
    monkeypatch.setattr(runtime, 'verify_live', lambda *a: pytest.fail('Blocked slot checked server'))
    report = runner.run(directory, max_slots=0)
    assert report['blocked_observations'] == 1 and report['attempt_statuses'] == {'input_blocked': 9, 'pending': 279}
    assert len(report['aggregates']) == 3 and all(a['status'] == 'unavailable' for a in report['aggregates'].values())
    assert not list(directory.glob('slots/*/*/*/dispatch.json')) and not control['calls']


def test_restart_requires_registered_matching_evidence_and_keeps_old_slots(packet):
    directory, control = bind(packet)
    runner.run(directory, max_slots=1)
    first_call = control['calls'][0]
    control['evidence'] = fake_runtime(control['policy'], pid=22)
    with pytest.raises(ValueError, match='Live server identity changed'): runner.run(directory, max_slots=1)
    assert len(control['calls']) == 1
    report = runner.register_runtime(directory, control['evidence'])
    assert report['runtime_events'] == 2
    assert runner.register_runtime(directory, control['evidence'])['runtime_events'] == 2
    runner.run(directory, max_slots=1)
    assert len(control['calls']) == 2 and control['calls'].count(first_call) == 1
    events = sorted((directory/'runtime').glob('*.json'))
    assert read_json(events[1])['previous_sha256'] == runner.digest(events[0])


@pytest.mark.parametrize('field', ['model', 'binary', 'libraries', 'template', 'context', 'source'])
def test_incompatible_restart_never_appends_or_dispatches(packet, field):
    directory, control = bind(packet)
    evidence = fake_runtime(control['policy'], pid=22)
    if field == 'model': evidence['model_sha256'] = 'd'*64
    if field == 'binary': evidence['process']['binary_sha256'] = 'd'*64
    if field == 'libraries': evidence['libraries']['/fake/lib.so'] = 'd'*64
    if field == 'template': evidence['props']['chat_template'] = 'different'
    if field == 'context': evidence['props']['default_generation_settings']['n_ctx'] = 8192
    if field == 'source': evidence['source']['source_tree_sha256'] = 'd'*64
    control['evidence'] = evidence
    with pytest.raises(ValueError): runner.register_runtime(directory, evidence)
    assert len(list((directory/'runtime').glob('*.json'))) == 1 and not control['calls']


def test_runtime_change_after_response_preserves_raw_attempt_and_excludes_vote(packet, monkeypatch):
    directory, control = bind(packet)
    original = llm.send_request
    def changed(*args):
        response = original(*args)
        control['evidence'] = fake_runtime(control['policy'], pid=22)
        return response
    monkeypatch.setattr(llm, 'send_request', changed)
    with pytest.raises(ValueError, match='Live server identity changed'): runner.run(directory, max_slots=1)
    slot = read_json(directory/'coordinator/schedule.json')[0]
    response = read_json(directory/slot['slot_path']/'response.json')
    assert response['attempt']['status'] == 'valid' and response['attempt']['response_body']
    assert read_json(directory/slot['slot_path']/'result.json')['status'] == 'runtime_changed'
    assert runner.verify(directory)['attempt_statuses'] == {'runtime_changed': 1, 'pending': 287}
    runner.register_runtime(directory, control['evidence'])
    runner.run(directory, max_slots=0)
    assert len(control['calls']) == 1


@pytest.mark.parametrize('target', ['view', 'prompt', 'request', 'schema', 'schedule', 'result', 'runtime_event', 'preflight'])
def test_corrupt_or_changed_artifacts_block_before_any_new_request(packet, target):
    directory, control = bind(packet)
    slot = read_json(directory/'coordinator/schedule.json')[0]
    paths = {'view': slot['view_path'], 'prompt': 'protocol/prompt.md', 'request': slot['request_path'],
             'schema': 'protocol/response.json', 'schedule': 'coordinator/schedule.json',
             'result': slot['slot_path']+'/result.json', 'runtime_event': 'runtime/000001.json',
             'preflight': replay.PREFLIGHT}
    if target == 'result': runner.run(directory, max_slots=1)
    count = len(control['calls'])
    put(directory, paths[target], b'{')
    with pytest.raises(ValueError): runner.run(directory, max_slots=1)
    assert len(control['calls']) == count


def test_offline_inspection_needs_no_source_snapshots_or_runtime(packet, monkeypatch):
    directory, control = bind(packet)
    def forbidden(*args, **kwargs): pytest.fail('Saved inspection contacted transport/runtime')
    monkeypatch.setattr(llm, 'send_request', forbidden)
    monkeypatch.setattr(runtime, 'query', forbidden)
    monkeypatch.setattr(runtime, 'budget', forbidden)
    monkeypatch.setattr(runtime, 'verify_live', forbidden)
    before = {p.relative_to(directory): p.read_bytes() for p in directory.rglob('*') if p.is_file()}
    inspection = replay.inspect(directory)
    assert inspection['state'] == runner.verify(directory)
    assert inspection['state']['slots'] == 288
    assert inspection['eligibility'] == read_json(directory/replay.PREFLIGHT)['eligibility']
    assert before == {p.relative_to(directory): p.read_bytes() for p in directory.rglob('*') if p.is_file()}
    assert not (directory/'coordinator/dependency-snapshot').exists()
    assert not control['calls']


def test_concurrent_runner_and_registration_cannot_acquire_ownership(packet):
    directory, control = bind(packet)
    with (directory/'runner.lock').open('r') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError): runner.run(directory, max_slots=1)
        with pytest.raises(BlockingIOError): runner.register_runtime(directory, control['evidence'])
        with pytest.raises(BlockingIOError): runner.verify(directory)
    assert not control['calls']


@pytest.mark.parametrize('failure', ['timeout', 'http', 'schema', 'unicode'])
def test_failures_and_unusual_response_text_are_saved_without_retry(packet, monkeypatch, failure):
    directory, control = bind(packet)
    calls = []
    def transport(*args):
        calls.append(1)
        if failure == 'timeout':
            import requests
            raise requests.Timeout('synthetic timeout')
        content = {'decision': 'uncertain', 'confidence': .5, 'evidence': [],
                   'summary': '\ud800' if failure == 'unicode' else 'synthetic'}
        if failure == 'schema': content['extra'] = 1
        body = json.dumps({'choices': [{'message': {'content': json.dumps(content)}, 'finish_reason': 'stop'}]})
        return SimpleNamespace(text=body, status_code=500 if failure == 'http' else 200)
    monkeypatch.setattr(llm, 'send_request', transport)
    report = runner.run(directory, max_slots=1)
    expected = {'timeout': 'timeout', 'http': 'transport_error', 'schema': 'schema_invalid', 'unicode': 'valid'}[failure]
    assert report['attempt_statuses'] == {expected: 1, 'pending': 287}
    runner.run(directory, max_slots=0)
    assert calls == [1]
    slot = read_json(directory/'coordinator/schedule.json')[0]
    assert (directory/slot['slot_path']/'response.json').exists()


def test_runtime_cli_delegates_explicit_new_policy(projection_setup, tmp_path, monkeypatch):
    _, protocol = projection_setup
    import sys
    calls = []
    monkeypatch.setattr(runtime, 'serve', lambda directory, policy: calls.append((directory, policy)))
    monkeypatch.setattr(sys, 'argv', ['runner', 'serve', '--directory', str(tmp_path/'server'), '--protocol-root', str(protocol)])
    runner.main()
    assert calls[0][1]['method_id'] == 'public-representation-llm-v1' and calls[0][1]['llm']['context_limit'] == 12288
