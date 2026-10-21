"""A larger context is a new campaign, with no changes to frozen requests."""
from copy import deepcopy

import pytest

from redesign.pipeline import context_campaign as amendment, final_run, llm, llm_runtime
from redesign.pipeline.inventory import read_json


def test_policy_changes_only_context():
    policy = read_json(amendment.CAMPAIGN/'llm_policy.json')
    updated = amendment.amended_policy(policy)
    assert policy['llm']['context_limit']==8192
    assert updated['llm']['context_limit']==12288
    updated['llm']['context_limit']=8192
    assert updated==policy


def test_amended_freeze_and_execution_use_exact_parent_requests(tmp_path,monkeypatch):
    monkeypatch.setattr(amendment.final_freeze,'verify',lambda root:{'status':'verified'})
    root=tmp_path/'amended'
    amendment.prepare(root)
    parent=read_json(amendment.CAMPAIGN/'release/freeze.json')
    prior=root/'build/final/preflight'/parent['context_run_id']
    policy=read_json(root/'llm_policy.json')
    server=read_json(prior/'server.json')
    server['policy_sha256']=llm.sha(policy)
    server['props']['default_generation_settings']['n_ctx']=12288
    server_path=tmp_path/'server.json'
    llm_runtime.write_new(server_path,server)
    monkeypatch.setattr(llm_runtime,'verify_live',lambda *args:None)
    budgets={}
    for row in read_json(prior/'manifest.json')['slots']:
        budgets[(prior/row['request']).read_text()]=read_json(prior/row['budget'])
    calls=[]
    def budget(request,config):
        assert config['llm']['context_limit']==12288
        calls.append(request)
        result=deepcopy(budgets[amendment.wire(request)])
        result['status']='available' if result['total_budget']<=12288 else 'context_unavailable'
        return result
    monkeypatch.setattr(llm_runtime,'budget',budget)
    report=amendment.freeze(server_path,root)
    assert len(calls)==480
    assert report['observation_statuses']=={'available':160}
    assert report['slot_statuses']=={'available':480}
    assert read_json(amendment.CAMPAIGN/'llm_policy.json')['llm']['context_limit']==8192
    run=tmp_path/'run'
    result=final_run.prepare(run,root=root)
    assert result['attempt_statuses']=={'pending':480}
    assert set(result['shared_availability'].values())=={'available'}
    manifest,_=final_run.validate_manifest(run,root)
    assert manifest['policy']['llm']['context_limit']==12288
    final_run.verify(run,root)
    # The amendment cannot also alter sampling/model settings.
    path=root/'llm_policy.json';path.chmod(0o644)
    changed=read_json(path);changed['llm']['temperature']=0.3
    path.write_text(amendment.canonical(changed))
    with pytest.raises(ValueError,match='Only context_limit may change'):amendment.verify(root)


def test_runtime_amendment_preserves_model_samplers_and_template():
    old=read_json(amendment.method_lock.LOCK)['runtime_configuration']
    policy=amendment.amended_policy(read_json(amendment.CAMPAIGN/'llm_policy.json'))
    updated=amendment.expected_runtime(policy)
    assert updated['props']['default_generation_settings']['n_ctx']==12288
    updated['props']['default_generation_settings']['n_ctx']=8192
    updated['policy_sha256']=old['policy_sha256']
    assert updated==old
