"""Saved-result reporting checks study scoring, failed-slot costs and bytes."""
from copy import deepcopy
import csv
import io
import json
import shutil
from types import SimpleNamespace

import pytest

from optimization_vuln_analysis.common.artifacts import file_inventory
from optimization_vuln_analysis.studies.representation import reporting, runner, scoring
from optimization_vuln_analysis.studies.representation import replay as execution_replay
from optimization_vuln_analysis.inference import attempts as llm, runtime
from optimization_vuln_analysis.inputs.corpus import read_json


@pytest.fixture(scope='module')
def completed(reporting_study, tmp_path_factory):
    root = tmp_path_factory.mktemp('reporting')
    execution = reporting_study.execution
    policy = read_json(execution/'protocol/policy.json')
    calls = []
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(runtime, 'verify_live', lambda *a: None)
        def transport(*a):
            calls.append(True)
            answer = {'decision': 'uncertain', 'confidence': .5, 'summary': 'Fixture, with comma\nand newline.', 'evidence': []}
            if len(calls) == 2: answer['evidence'] = ['A:F9999:L99999']
            body = {'choices': [{'message': {'content': json.dumps(answer), 'reasoning_content': 'Fixture reasoning.'},
                                 'finish_reason': 'length' if len(calls) == 1 else 'stop'}],
                    'usage': {'prompt_tokens': 5, 'completion_tokens': 7}}
            return SimpleNamespace(text=json.dumps(body), status_code=200)
        patch.setattr(llm, 'send_request', transport)
        state = runner.run(execution)
    assert state['status'] == 'complete' and len(calls) == 279
    output = root/'analysis'
    receipt = reporting.prepare(reporting_study.inputs, reporting_study.projection, execution, output)
    return SimpleNamespace(execution=execution, output=output, receipt=receipt)


def csv_rows(path):
    return list(csv.DictReader(io.StringIO(path.read_bytes().decode('utf-8'), newline='')))


def test_complete_analysis_keeps_failed_slots_and_costs_and_control_available(completed):
    e = read_json(completed.output/'evaluation.json')
    for method in scoring.REPRESENTATIONS:
        assert {k:e['primary']['methods'][method]['counts'][k] for k in ['A','U','M']} == {'A':32,'U':31,'M':1}
    assert e['primary']['methods'][scoring.CONTROL]['counts']['C'] == 16
    conditions = csv_rows(completed.output/'observation-condition.csv')
    assert len(conditions) == 96
    assert len(csv_rows(completed.output/'control.csv')) == 32
    assert all('confidence' not in row and row['status'] == 'classified' for row in csv_rows(completed.output/'control.csv'))
    attempts = csv_rows(completed.output/'attempts.csv')
    assert len(attempts) == 288 and sum(row['dispatched'] == 'True' for row in attempts) == 279
    total = csv_rows(completed.output/'compute.csv')[-1]
    assert total['prompt_tokens'] == str(279*5) and total['completion_tokens'] == str(279*7)
    assert total['prompt_tokens_missing_dispatched_slots'] == total['completion_tokens_missing_dispatched_slots'] == '0'
    failures = csv_rows(completed.output/'failed-slots.csv')
    assert {r['status'] for r in failures} == {'length_limit', 'schema_invalid'} and len(failures) == 2
    assert all(r['response_sha256'] for r in failures)
    assert csv_rows(completed.output/'disagreements.csv') == []
    assert len(read_json(completed.output/'qualitative.json')['cases']) == 0
    assert b'Fixture, with comma\nand newline.' in (completed.output/'attempts.csv').read_bytes()
    assert read_json(completed.output/'audit.json')['all_partitions_verified']


def test_report_verification_needs_no_runtime_or_input_data(completed, monkeypatch):
    before = file_inventory(completed.execution)
    def forbidden(*a, **k): pytest.fail('Analysis contacted model/runtime')
    monkeypatch.setattr(llm, 'send_request', forbidden)
    monkeypatch.setattr(runtime, 'verify_live', forbidden)
    monkeypatch.setattr(runtime, 'query', forbidden)
    result = reporting.verify(completed.output, completed.receipt['manifest_sha256'])
    assert result['status'] == 'verified'
    assert file_inventory(completed.execution) == before


def test_independent_recount_rejects_changed_votes_or_integer_scores(completed):
    e = read_json(completed.output/'evaluation.json')
    replay = read_json(completed.output/'phase8-check.json')
    records = execution_replay.records(completed.execution)
    changed = deepcopy(e); changed['primary']['methods']['assembly']['counts']['C'] += 1
    with pytest.raises(ValueError, match='integer recount'): reporting.audit(changed, records, replay)
    changed = deepcopy(replay); next(iter(changed['aggregates'].values()))['votes'] = {'not_vulnerable': 3}
    with pytest.raises(ValueError, match='vote recount'): reporting.audit(e, records, changed)
    changed = deepcopy(e)
    changed['rows'][0]['predictions']['assembly'] = {'status':'classified','decision':'not_vulnerable'}
    with pytest.raises(ValueError,match='rows differ'): reporting.audit(changed,records,replay)


def test_compute_exposes_dispatched_usage_gaps_and_does_not_count_blocking_as_unknown_consumption():
    valid = {'representation':'assembly','status':'valid','dispatch':{'runtime_event_sha256':'one'},
             'response':{'usage':{'prompt_tokens':10,'completion_tokens':20},'elapsed_seconds':2}}
    timeout = {**valid,'status':'timeout','response':{'usage':{'prompt_tokens':None,'completion_tokens':None},'elapsed_seconds':5}}
    interrupted = {**valid,'status':'interrupted','response':None}
    blocked = {**valid,'status':'input_blocked','dispatch':None,'response':None}
    changed = {**valid,'status':'runtime_changed'}  # preserved raw usage still counts
    total = reporting.compute([valid,timeout,interrupted,blocked,changed])[-1]
    assert total['scheduled_slots'] == 5 and total['dispatched_slots'] == 4
    assert total['prompt_tokens'] == 20 and total['completion_tokens'] == 40
    assert total['prompt_tokens_missing_dispatched_slots'] == total['completion_tokens_missing_dispatched_slots'] == 2
    assert total['recorded_response_seconds'] == 9 and total['elapsed_missing_dispatched_slots'] == 1


@pytest.mark.parametrize('name', ['metrics.csv','evaluation.json','figures/outcomes.png'])
def test_changed_analysis_files_fail_hash_checks(completed,tmp_path,name):
    directory = tmp_path/'bad'; shutil.copytree(completed.output,directory)
    path = directory/name;path.chmod(0o644);path.write_bytes(b'changed\n')
    with pytest.raises(ValueError,match='inventory/hashes'): reporting.verify(directory)


def test_unselected_qualitative_cases_are_rejected(completed):
    e = read_json(completed.output/'evaluation.json')
    replay = read_json(completed.output/'phase8-check.json')
    with pytest.raises(ValueError,match='predeclared selection'):
        reporting._qualitative(e,execution_replay.records(completed.execution),replay,completed.execution,
                               {'cases':{'invented':{'error_codes':[],'explanation':'Wrong selection'}}})


def test_primary_contrast_role_does_not_extend_to_secondary_source_or_subgroup_endpoints(completed):
    rows = csv_rows(completed.output/'contrasts.csv')
    assert sum(r['analysis_role'] == 'primary' for r in rows) == 1
    primary = next(r for r in rows if r['analysis_role'] == 'primary')
    assert primary['scope'] == 'primary' and primary['id'] == 'combined_minus_decompilation_correct_rate'
