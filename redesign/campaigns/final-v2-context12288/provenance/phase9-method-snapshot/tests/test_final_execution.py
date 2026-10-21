"""Final execution tests never dispatch to a model or invoke Ghidra."""
from pathlib import Path

import pytest

from redesign.pipeline import final_analysis, final_run as final, llm_runtime
from redesign.pipeline.inventory import read_json
from redesign.pipeline.bundles import canonical
from test_pilot_evaluation import row


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    monkeypatch.setattr(final.final_freeze, 'verify', lambda root: {'status':'verified'})
    monkeypatch.setattr(final,'claim_path',lambda root:tmp_path/'execution.json')
    directory = tmp_path/'run'
    final.prepare(directory)
    return directory


def test_prepare_is_offline_and_exact(prepared):
    manifest, _ = final.validate_manifest(prepared)
    report = final.verify(prepared)
    assert len(manifest['inputs']) == 160
    assert report['attempt_statuses'] == {'pending':480}
    assert report['baseline_statuses'] == {'pending':160}
    assert list(report['shared_availability'].values()).count('context_unavailable') == 48
    with pytest.raises(FileExistsError): final.prepare(prepared)
    assert not list(prepared.rglob('dispatch.json'))


@pytest.mark.parametrize('kind', ['input','request','budget','schedule','implementation','runtime'])
def test_tampering_fails_before_dispatch(prepared, monkeypatch, kind):
    manifest = read_json(prepared/'manifest.json')
    slot = manifest['slots'][0]
    if kind == 'input':
        path = prepared/'inputs'/f"{slot['observation_id']}.json"
    elif kind in ('request','budget'):
        path = prepared/'slots'/final.run_llm.slot_name(slot)/f'{kind}.json'
    else: path = prepared/'manifest.json'
    data = read_json(path)
    if kind == 'schedule': data['slots'] = data['slots'][:-1]
    elif kind == 'implementation': data['methods'] = {}
    elif kind == 'runtime': data['server_sha256'] = 'changed'
    else: data['tampered'] = True
    path.write_text(canonical(data))
    monkeypatch.setattr(final.llm,'attempt',lambda *args:pytest.fail('must fail before dispatch'))
    with pytest.raises(ValueError): final.run(prepared, max_slots=1)
    assert not list(prepared.rglob('dispatch.json'))


def test_interrupted_failed_and_blocked_slots_never_retry(prepared, monkeypatch):
    monkeypatch.setattr(llm_runtime,'verify_live',lambda *args:None)
    manifest = read_json(prepared/'manifest.json')
    live = [s for s in manifest['slots'] if read_json(prepared/'slots'/final.run_llm.slot_name(s)/'budget.json')['status']=='available']
    first = live[0]; path = prepared/'slots'/final.run_llm.slot_name(first)
    llm_runtime.write_new(path/'dispatch.json', {'request_sha256':first['request_sha256'],
        'server_sha256':manifest['server_sha256']})
    calls = []
    def attempt(*args):
        calls.append(args)
        return {'status':'timeout','parsed':None,'response_body':None}
    monkeypatch.setattr(final.llm,'attempt',attempt)
    report = final.run(prepared,max_slots=1)
    assert report['attempt_statuses'] == {'interrupted':1,'timeout':1,'context_unavailable':144,'pending':334}
    before = (path/'result.json').read_bytes()
    report = final.run(prepared,max_slots=1)
    assert len(calls) == 2 and report['attempt_statuses']['timeout'] == 2
    assert (path/'result.json').read_bytes() == before
    assert calls[0][0] != calls[1][0]  # different frozen scheduled requests


def test_runtime_restart_requires_identical_configuration(prepared, tmp_path, monkeypatch):
    monkeypatch.setattr(llm_runtime,'verify_live',lambda *args:None)
    monkeypatch.setattr(final.llm,'attempt',lambda *args:{'status':'timeout','parsed':None,'response_body':None})
    server = read_json(prepared/'server.json')
    server['process']['pid'] += 1
    path = tmp_path/'new-server.json'; path.write_text(canonical(server))
    report = final.run(prepared,max_slots=1,server=path)
    assert report['attempt_statuses']['timeout'] == 1
    assert len(list((prepared/'runtime-sessions').glob('*.json'))) == 1
    server['model_sha256'] = 'different-model';path.write_text(canonical(server))
    with pytest.raises(ValueError,match='Locked runtime differs'):final.run(prepared,max_slots=1,server=path)


def test_campaign_cannot_start_another_execution(prepared, tmp_path):
    final.claim_execution(prepared,final.CAMPAIGN)
    final.claim_execution(prepared,final.CAMPAIGN)
    second = tmp_path/'another-run'
    final.prepare(second)
    with pytest.raises(ValueError,match='already has an execution'):
        final.claim_execution(second,final.CAMPAIGN)


def test_incomplete_final_cannot_be_analyzed(prepared):
    with pytest.raises(ValueError,match='incomplete'): final_analysis.analyze(prepared)


def test_final_diagnostics_denominators_and_artifacts():
    rows = [row('a',cwe='CWE-121',baseline='not_vulnerable',public_context_status='available'),
            row('b',cwe='CWE-121',public_context_status='available',shared_availability='context_unavailable'),
            row('c',cwe='CWE-121',public_context_status='extraction_unavailable',shared_availability='context_unavailable')]
    table = final_analysis.diagnostics(rows)[0]
    assert table['planned']==3 and table['context_failures']==1 and table['extraction_failures']==1
    assert table['methods']['baseline']=={'A':3,'C':1,'E':0,'U':0,'M':2}
    report = final_analysis.evaluate.evaluate(rows,repetitions=20)
    outputs = final_analysis.artifacts(report)
    assert set(outputs)=={'evaluation.json','observations.csv','report.md'}
    assert len(outputs['observations.csv'].splitlines())==4


def test_baseline_recovers_without_redispatch(prepared, monkeypatch):
    _, preflight, _ = final.frozen_inputs(final.CAMPAIGN)
    engine = read_json(preflight/'context-audit.json')['engine']
    monkeypatch.setattr(final,'engine_identity',lambda policy:engine)
    calls = []
    def worker(argv, **kwargs):
        calls.append(argv)
        # Workers receive public inputs, policy, output/work paths only.
        assert not any('oracle' in arg or 'private' in arg for arg in argv)
        source = Path(argv[argv.index('--input')+1])
        output = Path(argv[argv.index('--output')+1])
        policy = read_json(Path(argv[argv.index('--policy')+1]))
        output.write_text(canonical(final.failure(policy,final.digest(source))))
        return type('Process',(),{'returncode':0,'stdout':'','stderr':''})()
    monkeypatch.setattr(final.subprocess,'run',worker)
    manifest = read_json(prepared/'manifest.json')
    identifier = next(iter(manifest['inputs']))
    llm_runtime.write_new(prepared/'baseline'/identifier/'dispatch.json',
                         {'bundle_sha256':manifest['inputs'][identifier]})
    report = final.baseline(prepared)
    assert report['baseline_statuses']=={'runtime_failed':112,'context_unavailable':48}
    assert len(calls)==111
    final.baseline(prepared)
    assert len(calls)==111


def test_complete_saved_run_regenerates_analysis(prepared, monkeypatch):
    manifest = read_json(prepared/'manifest.json')
    policy = read_json(final.CAMPAIGN/'baseline_policy.json')
    availability = final.verify(prepared)['shared_availability']
    for slot in manifest['slots']:
        path = prepared/'slots'/final.run_llm.slot_name(slot)
        status = availability[slot['observation_id']]
        if status == 'available':
            llm_runtime.write_new(path/'dispatch.json', {'request_sha256':slot['request_sha256'],
                'server_sha256':manifest['server_sha256']})
            result = {'status':'timeout','parsed':None,'response_body':None}
        else: result = {'status':status,'parsed':None}
        llm_runtime.write_new(path/'result.json', {**result,'slot':slot})
    for identifier, sha in manifest['inputs'].items():
        path = prepared/'baseline'/identifier
        llm_runtime.write_new(path/'dispatch.json', {'bundle_sha256':sha})
        result = final.failure(policy,sha) if availability[identifier]=='available' else {
            'status':availability[identifier],'prediction':None}
        llm_runtime.write_new(path/'result.json',result)
    # Keep this integration fixture fast; separate locked-evaluator tests verify
    # arithmetic and the bootstrap. Production reads the frozen 10,000 draws.
    original_read = final_analysis.read_json
    def read(path):
        value = original_read(path)
        if path == final.CAMPAIGN/'config.json':
            value['evaluation']['bootstrap_repetitions'] = 20
        return value
    monkeypatch.setattr(final_analysis,'read_json',read)
    report = final_analysis.analyze(prepared)
    assert report['primary']['llm']['A']['estimate'] == 160
    assert report['primary']['llm']['M']['estimate'] == 160
    assert report['compute']['actual_dispatches'] == 336
    assert report['symbol_contrasts_by_level']['O0']['matched_cells'] == 20
    assert len(report['disposition_by_optimization_cwe']) == 8
    assert final_analysis.artifacts(report) == final_analysis.artifacts(final_analysis.analyze(prepared))
