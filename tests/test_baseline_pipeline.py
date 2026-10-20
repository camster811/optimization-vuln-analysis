"""Preparation/runtime failures are not analyzer abstentions and never drop matrix cells."""
from copy import deepcopy
import hashlib
import shutil
import sys

import pytest

from redesign.pipeline import baseline, baseline_worker
from redesign.pipeline.bundles import canonical
from redesign.pipeline.inventory import ROOT, digest, encode, read_json
from test_bounds import Program


def test_worker_records_runtime_failure_separately_from_input_unavailability(tmp_path,monkeypatch):
    p=Program();source=tmp_path/'input.json';source.write_text(canonical(p.bundle))
    def fail(*args):raise RuntimeError('Independent engine-crash fixture')
    monkeypatch.setattr(baseline_worker,'lift',fail)
    result=baseline_worker.execute('lift',source,tmp_path/'job',p.policy)
    assert result['status']=='runtime_failed' and result['prediction'] is None
    baseline_worker.validate_result(result,p.bundle)
    p.bundle['status']='context_unavailable'
    p.bundle['completeness']['omissions']=[{'reason':'function_limit','address':None}]
    source.write_text(canonical(p.bundle))
    result=baseline_worker.execute('lift',source,tmp_path/'not-dispatched',p.policy)
    assert result['status']=='input_unavailable' and not (tmp_path/'not-dispatched').exists()


def test_result_validation_rejects_invented_bounds_and_evidence():
    p=Program(16);prediction=p.run()
    result={'schema_version':2,'method_id':p.policy['method_id'],
            'bundle_sha256':hashlib.sha256(canonical(p.bundle).encode()).hexdigest(),
            'ir_sha256':'0'*64,'status':'completed','prediction':prediction,'error_code':None}
    baseline_worker.validate_result(result,p.bundle)
    altered=deepcopy(result);altered['prediction']['write_checks'][0]['capacity']=1
    with pytest.raises(ValueError,match='Contradictory'):baseline_worker.validate_result(altered,p.bundle)
    altered=deepcopy(result);altered['prediction']['evidence']=['0x3000']
    with pytest.raises(ValueError,match='outside'):baseline_worker.validate_result(altered,p.bundle)


def test_crashed_workers_preserve_full_inventory_and_previous_outputs(tmp_path,monkeypatch):
    original=ROOT;root=tmp_path
    for name in baseline.METHODS:
        destination=root/name;destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(original/name,destination)
    p=Program();rows=[];hashes={}
    for i in range(2):
        name=f'data/pilot/records/r{i}.json';path=root/name;path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(canonical(p.bundle));hashes[name]=digest(path)
        rows.append({'observation_id':f'r{i}','record_path':name})
    plan={'observations':rows}
    monkeypatch.setattr(baseline,'ROOT',root)
    monkeypatch.setattr(baseline,'inputs',lambda:(p.policy,plan,hashes))
    monkeypatch.setattr(baseline,'engine_identity',lambda *args:{'home':str(root),'files':{},
        'java':{'path':sys.executable,'sha256':digest(sys.executable)}})
    def crash(*args,**kwargs):raise RuntimeError('Worker crashed')
    monkeypatch.setattr(baseline.subprocess,'run',crash)
    lifted=baseline.run('lift','fixture-lift')
    assert lifted['counts']=={'runtime_failed':2}
    predicted=baseline.run('analyze','fixture','fixture-lift',write=True)
    assert predicted['counts']=={'runtime_failed':2}
    assert all(r['decision'] is None for r in predicted['observations'])
    baseline.verify('fixture')
    published=root/'results/pilot/baseline/fixture.json';published.write_text('preserve previous run')
    with pytest.raises(ValueError,match='Existing baseline results differ'):baseline.publish(predicted)
    assert published.read_text()=='preserve previous run'
    directory=baseline.directory('baseline','fixture');manifest=directory/'manifest.json'
    missing=deepcopy(predicted);missing['observations'].pop();manifest.write_text(encode(missing))
    with pytest.raises(ValueError,match='inventory'):baseline.verify('fixture')
