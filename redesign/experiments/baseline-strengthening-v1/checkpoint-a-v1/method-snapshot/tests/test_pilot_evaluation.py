"""Independent arithmetic checks for prospective scoring and family pairing."""
from copy import deepcopy
import numpy as np
import pytest
from redesign.pipeline.evaluate import evaluate, outcomes, statistics, matched


def row(identifier, truth='not_vulnerable', baseline='uncertain', llm='not_vulnerable', **extra):
    def prediction(value):
        return {'decision': value, 'status': 'unavailable' if value is None else 'abstained' if value=='uncertain' else 'classified'}
    return {'observation_id': identifier, 'binary_label': truth, 'source_label': truth,
            'family_id': 'family-a', 'variant': 'safe', 'optimization': 'O0', 'symbols': 'retained',
            'cwe': 'CWE-121', 'operation_status': 'present', 'shared_availability': 'available',
            'bundle_sha256': identifier, 'predictions': {'baseline': prediction(baseline), 'llm': prediction(llm)}, **extra}


def score(rows, method='llm'):
    return {k: v[0] for k,v in statistics(outcomes(rows,method),np.ones((1,len(rows)))).items()}


def test_partition_and_wrong_cwe_alert():
    rows = [row('a',truth='vulnerable_CWE-121',llm='vulnerable_CWE-122'),
            row('b'),row('c',llm='uncertain'),row('d',llm=None),row('e',truth='unresolved')]
    s=score(rows)
    assert [s[k] for k in ('A','C','E','U','M')] == [4,1,1,1,1]
    assert s['TP']==1 and s['FN']==0 and s['TN']==3 and s['FP']==0
    assert s['correct_rate']==.25 and s['selective_accuracy']==.5
    assert s['coverage']==.5 and s['balanced_accuracy']==1


def test_shared_overlay_applies_to_both():
    rows=[row('a',baseline='not_vulnerable',shared_availability='context_unavailable'),row('b',baseline='not_vulnerable')]
    for method in ('baseline','llm'):
        s=score(rows,method)
        assert s['A']==2 and s['C']==1 and s['M']==1 and s['correct_rate']==.5
    report=evaluate(rows,repetitions=20)
    assert report['common_input']['planned_cells']==1
    assert report['primary']['llm_minus_baseline_correct_rate']['estimate']==0


def test_zero_denominators_are_na():
    s=score([row('a',truth='unresolved')])
    assert np.isnan(s['correct_rate']) and np.isnan(s['balanced_accuracy'])
    report=evaluate([row('a',truth='unresolved')],repetitions=20)
    value=report['primary']['llm']['correct_rate']
    assert value['estimate'] is None and value['interval']['defined_replicates']==0


def test_matched_contrast_keeps_missing_predictions():
    rows=[row('a'),row('b',optimization='O1',llm=None)]
    result=matched(rows,np.ones((3,2)),'optimization','O0','O1')
    assert result['matched_cells']==1
    assert result['methods']['llm']['second_minus_first_correct_rate']==-1
    rows[1]['binary_label']='unresolved'
    result=matched(rows,np.ones((3,2)),'optimization','O0','O1')
    assert result['matched_cells']==0 and result['omitted']=={'unresolved_truth':1}


def test_family_bootstrap_shared_and_deterministic():
    rows=[row('a',baseline='not_vulnerable'),row('b',family_id='family-b',llm='uncertain',baseline='uncertain')]
    first=evaluate(rows,repetitions=100)
    assert first==evaluate(rows,repetitions=100)
    assert first['bootstrap']['draws_per_replicate']==2
    contrast=first['primary']['llm_minus_baseline_correct_rate']
    assert contrast['estimate']==contrast['interval']['lower']==contrast['interval']['upper']==0
    assert first['primary']['llm']['correct_rate']['interval']['lower']==0
    assert first['primary']['llm']['correct_rate']['interval']['upper']==1


def test_conflicting_identical_inputs_and_source_recovery():
    rows=[row('a',bundle_sha256='same'),row('b',bundle_sha256='same',source_label='vulnerable_CWE-121'),row('c')]
    report=evaluate(rows,repetitions=20)
    assert report['primary']['llm']['C']['estimate']==3
    assert report['source_label_recovery']['llm']['C']['estimate']==2
    assert report['excluding_conflicting_identical_inputs']['excluded_cells']==2
    assert report['excluding_conflicting_identical_inputs']['binary']['planned_cells']==1


def test_inventory_duplicates_rejected():
    with pytest.raises(ValueError): evaluate([row('a'),row('a')],repetitions=2)


def test_lock_detects_artifact_mutation(tmp_path):
    from redesign.pipeline.method_lock import check_files
    from redesign.pipeline.inventory import digest
    path=tmp_path/'policy.json';path.write_text('{}')
    files={'policy.json':digest(path)}
    check_files(files,tmp_path)
    path.write_text('{"changed":true}')
    with pytest.raises(ValueError,match='changed'):check_files(files,tmp_path)


def test_runtime_lock_excludes_process_identity_only():
    from redesign.pipeline.method_lock import runtime_configuration
    keys=('policy_sha256','model_sha256','props','libraries','source','gpu_layers','flash_attention')
    server={k:k for k in keys};server['process']={'pid':1,'binary_sha256':'binary'}
    same=deepcopy(server);same['process']={'pid':2,'binary_sha256':'binary'}
    assert runtime_configuration(server)==runtime_configuration(same)
    same['model_sha256']='changed'
    assert runtime_configuration(server)!=runtime_configuration(same)


def test_archive_preserves_raw_attempts(tmp_path):
    import tarfile
    from redesign.pipeline.method_lock import archive_run
    run=tmp_path/'run';run.mkdir()
    (run/'result.json').write_text('{"raw":"kept"}\n')
    (run/'runner.lock').touch()
    archive=tmp_path/'run.tar.gz';archive_run(run,archive)
    with tarfile.open(archive) as saved:
        assert saved.getnames()==['result.json']
        assert saved.extractfile('result.json').read()==b'{"raw":"kept"}\n'
    with pytest.raises(FileExistsError):archive_run(run,archive)


def test_incomplete_pilot_cannot_be_scored(monkeypatch,tmp_path):
    from redesign.pipeline import evaluate as evaluator
    monkeypatch.setattr(evaluator.baseline_snapshot,'replay',lambda:None)
    monkeypatch.setattr(evaluator.run_llm,'verify',lambda p:{'attempt_statuses':{'pending':1}})
    with pytest.raises(ValueError,match='incomplete'):evaluator.pilot(tmp_path)
