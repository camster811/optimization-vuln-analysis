"""Pilot selection, accepted-input binding and reuse of projections/execution."""
import json
import shutil
from types import SimpleNamespace

import pytest

from optimization_vuln_analysis.studies.representation import adapter, pilot, runner, views
from optimization_vuln_analysis.inference import attempts as llm, runtime
from optimization_vuln_analysis.inputs.corpus import read_json
from tests.support.parent import put
from tests.support.execution import accounting, fake_runtime


def test_offline_predeclaration_projects_all_pilot_views_and_uses_metadata_only(accepted, tmp_path, monkeypatch):
    monkeypatch.setattr(llm, 'send_request', lambda *a, **k: pytest.fail('Preparation contacted model'))
    # Neither labels nor historical prediction files are required for selection.
    put(accepted, 'corpus/private/pilot-oracle.json', {'unreadable_truth': 'unused'})
    first, second = tmp_path/'first', tmp_path/'second'
    receipt = pilot.prepare(first, accepted)
    pilot.prepare(second, accepted)
    assert {p.relative_to(first): p.read_bytes() for p in first.rglob('*') if p.is_file()} == {
        p.relative_to(second): p.read_bytes() for p in second.rglob('*') if p.is_file()}
    assert receipt['projected_views'] == 96 and receipt['slots'] == 18
    chosen = read_json(first/'selection.json')['selected']
    assert len(chosen) == 2 and len({r['family_id'] for r in chosen}) == 2
    assert all((r['variant'], r['optimization'], r['symbols']) == ('vulnerable', 'O0', 'retained') for r in chosen)
    policy, prompt, schema = adapter.settings(first/'protocol')
    original, original_prompt, original_schema = adapter.settings()
    assert policy['llm'] == original['llm'] and policy['llama_cpp'] == original['llama_cpp']
    assert prompt == original_prompt and schema == original_schema
    assert policy['engineering']['included_in_final_scores'] is False
    assert policy['matrix']['final_slots'] == 18 and policy['configuration_id'] != original['configuration_id']
    assert 'private/evaluation.json' not in read_json(first/'manifest.json')['files']
    runner.prepare(first/'smoke', tmp_path/'execution', protocol_root=first/'protocol')
    assert runner.verify(tmp_path/'execution')['attempt_statuses'] == {'pending': 18}
    # Original workspace can disappear; verification reads the saved packet only.
    monkeypatch.setattr(pilot, 'ROOT', tmp_path/'missing')
    assert pilot.verify(first) == receipt


@pytest.mark.parametrize('failure', ['accepted_hash', 'extraction_hash', 'bundle', 'missing', 'unavailable', 'build_binding'])
def test_changed_or_missing_accepted_inputs_fail_before_preparation(accepted, tmp_path, failure):
    plan = read_json(accepted/pilot.SOURCES[2])['plan']
    row = plan['observations'][0]
    if failure == 'accepted_hash':
        doc = read_json(accepted/pilot.SOURCES[4]); doc['inputs'][row['observation_id']] = '0'*64
        put(accepted, pilot.SOURCES[4], doc)
    elif failure in ('extraction_hash', 'unavailable', 'build_binding'):
        doc = read_json(accepted/pilot.SOURCES[3])
        if failure == 'extraction_hash': doc['observations'][0]['record_sha256'] = '0'*64
        elif failure == 'unavailable': doc['observations'][0]['status'] = 'entry_unavailable'
        else: doc['build_manifest_sha256'] = '0'*64
        put(accepted, pilot.SOURCES[3], doc)
    elif failure == 'bundle': put(accepted, row['record_path'], b'{}\n')
    elif failure == 'missing': (accepted/row['record_path']).unlink()
    with pytest.raises(ValueError): pilot.prepare(tmp_path/'out', accepted)
    assert not (tmp_path/'out').exists()


def test_projection_content_matches_existing_projector_and_tampering_fails(accepted, tmp_path):
    directory = tmp_path/'pilot'
    receipt = pilot.prepare(directory, accepted)
    row = read_json(directory/'selection.json')['selected'][0]
    for rep in views.CONDITIONS:
        projected = read_json(directory/f"smoke/public/views/{rep}/{row['observation_id']}.json")
        expected = views.project(read_json(accepted/row['record_path']), rep)
        assert projected == expected
    with pytest.raises(ValueError, match='identity'):
        pilot.verify(directory, '0'*64)
    put(directory, 'selection.json', {})
    with pytest.raises(ValueError, match='changed'): pilot.verify(directory)


def test_copied_accepted_packet_prepares_without_original_build_paths(accepted, tmp_path, monkeypatch):
    original, copied, output = tmp_path/'original-packet', tmp_path/'copied-packet', tmp_path/'reprepared'
    receipt = pilot.prepare(original, accepted)
    shutil.copytree(original, copied)
    accepted.rename(tmp_path/'old-workspace-unavailable')
    def forbidden(*args, **kwargs): pytest.fail('Accepted packet fell back to old source/build inventory')
    monkeypatch.setattr(pilot, 'generate', forbidden)
    result = pilot.prepare(output, root=tmp_path/'missing', accepted=copied,
                           accepted_manifest_sha256=receipt['manifest_sha256'])
    assert result['slots'] == 18 and result['projected_views'] == 96
    for name in ('selection.json', 'source-bindings.json'):
        assert (output/name).read_bytes() == (copied/name).read_bytes()
    for path in (copied/'projection/public/views').rglob('*.json'):
        assert (output/path.relative_to(copied)).read_bytes() == path.read_bytes()
    with pytest.raises(ValueError, match='identity'):
        pilot.prepare(tmp_path/'bad', accepted=copied, accepted_manifest_sha256='0'*64)
    assert not (tmp_path/'bad').exists()


@pytest.mark.parametrize('failure', [None, 'length_limit', 'schema_invalid'])
def test_complete_fake_execution_replays_and_accepts_uncertain_without_accuracy_target(accepted, tmp_path, monkeypatch, failure):
    directory, execution = tmp_path/'pilot', tmp_path/'execution'
    pilot.prepare(directory, accepted)
    runner.prepare(directory/'smoke', execution, protocol_root=directory/'protocol')
    policy = read_json(execution/'protocol/policy.json')
    evidence = fake_runtime(policy)
    monkeypatch.setattr(runtime, 'verify_live', lambda *a: None)
    monkeypatch.setattr(runtime, 'budget', lambda *a: accounting(policy))
    calls = []
    def transport(*a):
        answer = {'decision': 'uncertain', 'confidence': .1, 'summary': 'Fixture only.', 'evidence': []}
        finish = 'length' if not calls and failure == 'length_limit' else 'stop'
        if not calls and failure == 'schema_invalid': answer['evidence'] = ['A:F9999:L99999']
        calls.append(True)
        return SimpleNamespace(status_code=200, text=json.dumps({'choices': [{'message': {'content': json.dumps(answer)},
                                                                               'finish_reason': finish}]}))
    monkeypatch.setattr(llm, 'send_request', transport)
    runner.preflight(execution, evidence)
    assert pilot.check(directory, execution)['status'] == 'not_passed'
    runner.run(execution, max_slots=1)
    assert pilot.check(directory, execution)['terminal_slots'] == 1
    runner.run(execution)
    before = {p.relative_to(execution): p.read_bytes() for p in execution.rglob('*') if p.is_file()}
    monkeypatch.setattr(llm, 'send_request', lambda *a: pytest.fail('Offline pilot check sent request'))
    report = pilot.check(directory, execution)
    assert report['status'] == ('not_passed' if failure == 'schema_invalid' else 'passed')
    assert report['correctness_used_for_acceptance'] is False
    assert all(n >= 5 for n in report['valid_by_representation'].values())
    assert sum(report['valid_by_representation'].values()) == (17 if failure else 18)
    assert all(a['status'] == 'abstained' for a in report['aggregates'].values())
    assert before == {p.relative_to(execution): p.read_bytes() for p in execution.rglob('*') if p.is_file()}
