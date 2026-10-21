"""Independent control, denominator, resampling and immutable-publication checks."""
from copy import deepcopy
from pathlib import Path

import numpy as np
import pytest

from redesign.extensions.baseline_study import controls, scoring, study
from redesign.pipeline import evaluate as frozen
from redesign.pipeline.bundles import canonical
from redesign.pipeline.inventory import read_json
from test_pilot_evaluation import row


@pytest.mark.parametrize('method,label', list(controls.CONTROL_LABELS.items()))
def test_each_constant_is_uninformative(method,label):
    prediction=controls.predict(method,'available')
    assert prediction['decision']==label
    assert prediction['status']==('abstained' if label=='uncertain' else 'classified')
    assert set(prediction)=={'method_id','kind','decision','status'}
    assert prediction['kind']=='uninformative_constant_control'
    unavailable=controls.predict(method,'context_unavailable')
    assert unavailable['decision'] is None and unavailable['status']=='unavailable'


def test_private_labels_names_treatments_and_neighbors_do_not_affect_controls():
    rows=[row('a'),row('b',truth='vulnerable_CWE-121')]
    def predictions(items):
        return {r['observation_id']:{m:r['predictions'][m] for m in controls.CONTROL_LABELS}
                for r in scoring.attach_controls(items)}
    before=predictions(rows)
    changed=deepcopy(rows)
    for r in changed:
        r.update(binary_label='vulnerable_CWE-122',source_label='unresolved',family_id='private-family',
                 optimization='O3',symbols='stripped',source_name='private_bad.c',oracle_capacity=12345)
        r['predictions']['llm']['decision']='uncertain'
    assert predictions(changed)==before
    assert predictions(list(reversed(changed)))==before
    with pytest.raises(ValueError,match='only opaque IDs'):
        controls.generate([{'observation_id':'a','status':'available','binary_label':'not_vulnerable'}])


def test_controls_reject_duplicate_inventory_and_unknown_availability():
    with pytest.raises(ValueError,match='Duplicate'):
        controls.generate([{'observation_id':'a','status':'available'}]*2)
    with pytest.raises(ValueError,match='availability'):controls.predict('control_cwe121','typo')
    with pytest.raises(ValueError,match='Unknown constant'):controls.predict('fitted_majority','available')


def test_wrong_cwe_is_exact_error_but_alert_true_positive():
    report=scoring.evaluate([row('a',truth='vulnerable_CWE-121'),row('b')],repetitions=16)
    value=report['binary']['primary']['methods']['control_cwe122']
    assert [value[k]['estimate'] for k in ('A','C','E','TP','FP','TN','FN')]==[2,0,2,1,1,0,0]
    assert value['recall']['estimate']==1
    assert value['false_positive_rate']['estimate']==1
    assert value['precision']['estimate']==.5
    assert value['balanced_accuracy']['estimate']==.5
    no_overflow=report['binary']['primary']['methods']['control_not_vulnerable']
    assert no_overflow['C']['estimate']==1 and no_overflow['recall']['estimate']==0


def test_unknown_binary_truth_source_truth_and_shared_missingness_are_separate():
    rows=[row('a',truth='unresolved',source_label='vulnerable_CWE-121'),
          row('b',truth='vulnerable_CWE-121',shared_availability='context_unavailable'),row('c')]
    report=scoring.evaluate(rows,repetitions=16)
    binary=report['binary']['primary']['methods']['control_not_vulnerable']
    source=report['source_label_recovery']['primary']['methods']['control_not_vulnerable']
    assert [binary[k]['estimate'] for k in ('P','A','C','E','U','M')]==[3,2,1,0,0,1]
    assert [source[k]['estimate'] for k in ('A','C','E','U','M')]==[3,1,1,0,1]
    assert report['binary']['common_input']['planned_cells']==2
    assert report['binary']['common_input']['methods']['control_not_vulnerable']['correct_rate']['estimate']==1


def test_always_uncertain_and_no_alert_precision_are_na():
    report=scoring.evaluate([row('a',truth='vulnerable_CWE-121'),row('b')],repetitions=16)
    value=report['binary']['primary']['methods']['control_uncertain']
    assert [value[k]['estimate'] for k in ('C','E','U','M','coverage')]==[0,0,2,0,0]
    for key in ('precision','selective_accuracy'):
        assert value[key]['estimate'] is None
        assert value[key]['interval']=={'lower':None,'upper':None,'defined_replicates':0}
    assert value['recall']['estimate']==0 and value['false_positive_rate']['estimate']==0
    assert value['abstention_no_alert']['estimate']==2
    assert report['binary']['primary']['methods']['control_not_vulnerable']['precision']['estimate'] is None


def test_no_adjudicated_truth_and_empty_common_input_do_not_invent_zero_rates():
    report=scoring.evaluate([row('a',truth='unresolved',source_label='not_vulnerable',
                                 shared_availability='context_unavailable')],repetitions=16)
    assert report['binary']['common_input']=={'planned_cells':0,'status':'empty_subset'}
    for value in report['binary']['primary']['methods'].values():
        assert value['A']['estimate']==0
        assert value['correct_rate']['estimate'] is None
        assert value['balanced_accuracy']['estimate'] is None
        assert value['correct_rate']['interval']['defined_replicates']==0
    with pytest.raises(ValueError,match='Empty or duplicate'):scoring.evaluate([],repetitions=16)


def test_family_bootstrap_uses_shared_weights_not_independent_cells():
    rows=[row('a',truth='vulnerable_CWE-121',llm='vulnerable_CWE-121',family_id='a')]
    rows += [row(str(i),llm='vulnerable_CWE-121',family_id='b') for i in range(3)]
    families,weights=scoring.family_weights(rows,repetitions=100,seed=20261019)
    assert families==['a','b']
    assert np.array_equal(weights[:,1],weights[:,2]) and np.array_equal(weights[:,2],weights[:,3])
    assert np.all(weights[1:,0]+weights[1:,1]==2)
    # A contributes +1 correct relative to safe, B contributes -3 across its
    # three cells. Family draws AA/AB/BB therefore yield +1/-0.5/-1.
    values=(weights[:,0]-3*weights[:,1])/(weights[:,0]+3*weights[:,1])
    report=scoring.evaluate(rows,repetitions=100)
    contrast=report['binary']['primary']['paired_llm_minus_comparator']['control_not_vulnerable']['correct_rate_difference']
    assert contrast['estimate']==-.5
    assert contrast['interval']==frozen.interval(values[1:])
    assert contrast['interval']['lower']==-1 and contrast['interval']['upper']==1


def test_adapter_reproduces_frozen_two_method_intervals_on_small_fixture():
    rows=[row('a',family_id='a',baseline='not_vulnerable'),
          row('b',family_id='b',truth='vulnerable_CWE-121',llm='vulnerable_CWE-121')]
    original=frozen.evaluate(rows,repetitions=40)
    new=scoring.evaluate(rows,repetitions=40)
    scoring.verify_historical(new,original)
    for method in scoring.METHODS:
        integer=scoring.recount(new['rows'],method)
        assert all(value==new['binary']['primary']['methods'][method][key]['estimate']
                   for key,value in integer.items())


def test_xml_test_gate_requires_passes_and_checkpoint_tests(tmp_path):
    path=tmp_path/'tests.xml'
    path.write_text('<testsuite><testcase classname="test_baseline_study" name="fixture"/></testsuite>')
    assert study.test_gate(path)['tests']==1
    path.write_text('<testsuite><testcase classname="test_baseline_study"><skipped/></testcase></testsuite>')
    with pytest.raises(ValueError,match='failed or skipped'):study.test_gate(path)
    path.write_text('<testsuite><testcase classname="test_pilot_evaluation"/></testsuite>')
    with pytest.raises(ValueError,match='Missing checkpoint A'):study.test_gate(path)


def test_existing_run_ids_and_publications_are_not_replaced(tmp_path,monkeypatch):
    monkeypatch.setattr(study,'BUILD',tmp_path/'build')
    monkeypatch.setattr(study,'EXPERIMENT',tmp_path/'publications')
    (study.BUILD/'existing').mkdir(parents=True)
    with pytest.raises(ValueError,match='already exists'):study.run('existing',tmp_path/'test.xml')
    (study.EXPERIMENT/'published').mkdir(parents=True)
    with pytest.raises(ValueError,match='publication already exists'):study.run('published',tmp_path/'test.xml')


def test_supplement_archive_members_content_and_overwrite_guard(tmp_path,monkeypatch):
    source=tmp_path/'build';source.mkdir()
    (source/'study-manifest.json').write_text(canonical({'run_id':'fixture','tests':{'tests':1}}))
    (source/'predictions.json').write_text(canonical({'a':'not_vulnerable'}))
    monkeypatch.setattr(study,'EXPERIMENT',tmp_path/'publications')
    result=study.publish(source)
    destination=Path(result['publication'])
    study.verify_release(destination)
    assert read_json(destination/'release.json')['files'].keys()=={'study-manifest.json','predictions.json'}
    with pytest.raises(ValueError,match='refusing replacement'):study.publish(source)
    path=destination/'predictions.json';path.chmod(0o644)
    path.write_text(canonical({'a':'vulnerable_CWE-121'}))
    with pytest.raises(ValueError,match='Locked artifact changed'):study.verify_release(destination)
    assert read_json(source/'predictions.json')=={'a':'not_vulnerable'}


def test_full_accepted_campaign_control_counts_and_regeneration():
    root=study.CAMPAIGN
    historical=read_json(root/'results/final/phase9-a/evaluation.json')
    freeze=read_json(root/'release/freeze.json')
    public=read_json(root/'build/final/preflight'/freeze['context_run_id']/'shared-eligibility.json')
    eligibility=[{'observation_id':r['observation_id'],'status':r['status']} for r in public['observations']]
    first=study.artifacts(historical,eligibility)
    assert first==study.artifacts(historical,eligibility)
    import json
    comparison=json.loads(first['comparison.json'])
    expected={'control_not_vulnerable':100,'control_cwe121':28,'control_cwe122':32,'control_uncertain':0,
              'saved_llm':125,'saved_baseline_v2':18}
    for method,count in expected.items():
        assert comparison['binary']['primary']['methods'][method]['C']['estimate']==count
    assert comparison['binary']['primary']['methods']['control_uncertain']['U']['estimate']==160
    assert comparison['binary']['primary']['paired_llm_minus_comparator']['control_not_vulnerable']['correct_rate_difference']['estimate']==.15625
    predictions=json.loads(first['controls/predictions.json'])
    assert len(predictions)==160 and all(len(r['predictions'])==4 for r in predictions)
    assert '\r' not in first['comparison.csv']
    assert 'uninformative' in first['claims.md'] and 'post-hoc' in first['claims.md']
