"""Phase 8 cannot silently alter the matrix, prompt, eligibility, or release."""
from copy import deepcopy
import hashlib
import io
import tarfile

import pytest

from redesign.pipeline import final_freeze as final, llm, llm_runtime
from redesign.pipeline.bundles import canonical
from redesign.pipeline.inventory import ROOT, read_json


def test_prediction_guard(tmp_path):
    final.no_predictions(tmp_path)
    path=tmp_path/'results/final/baseline/result.json'
    path.parent.mkdir(parents=True);path.write_text('{}')
    with pytest.raises(ValueError,match='predictions already exist'):
        final.no_predictions(tmp_path)


@pytest.mark.parametrize('gate', ['oracle_coverage_gate','scope_parity_gate'])
def test_context_gates_fail_closed(gate):
    audit={'oracle_coverage_gate':True,'scope_parity_gate':True,'observations':[{}]*160,'symbol_partners':[{}]*80}
    final.check_audit(audit)
    audit[gate]=False
    with pytest.raises(ValueError):final.check_audit(audit)


def test_archive_requires_exact_members_and_content(tmp_path):
    path=tmp_path/'archive.tar.gz'
    with tarfile.open(path,'w:gz') as archive:
        item=tarfile.TarInfo('input.json');item.size=2
        archive.addfile(item,io.BytesIO(b'{}'))
    files={'input.json':hashlib.sha256(b'{}').hexdigest()}
    final.verify_archive(path,files)
    with pytest.raises(ValueError,match='content differs'):
        final.verify_archive(path,{'input.json':'0'*64})
    with pytest.raises(ValueError,match='inventory differs'):
        final.verify_archive(path,{**files,'missing.json':'0'*64})


def test_preflight_public_only_and_tamper_detection(tmp_path,monkeypatch):
    plan=read_json(final.CAMPAIGN/'build/final/build-manifest.json')['plan']
    policy,prompt,schema=llm.settings()
    bundle=read_json(next((ROOT/'data/pilot/records').glob('*.json')))
    for row in plan['observations']:
        target=tmp_path/row['record_path'];target.parent.mkdir(parents=True,exist_ok=True)
        target.write_text(canonical(bundle))
    audit={'oracle_coverage_gate':True,'scope_parity_gate':True,'observations':[{}]*160,'symbol_partners':[{}]*80}
    server={'identity':'test-runtime'}
    server_path=tmp_path/'server.json';server_path.write_text(canonical(server))
    monkeypatch.setattr(final,'check_sources',lambda root:plan)
    monkeypatch.setattr(final,'check_methods',lambda root:{'runtime_configuration':server})
    monkeypatch.setattr(final.method_lock,'runtime_configuration',lambda evidence:evidence)
    monkeypatch.setattr(final.export_context,'audit_run',lambda *args:audit)
    monkeypatch.setattr(llm,'settings',lambda root:(policy,prompt,schema))
    monkeypatch.setattr(llm_runtime,'verify_live',lambda *args:None)
    calls=[]
    def query(policy,method,path,payload):
        calls.append(path)
        if path=='/apply-template':
            # Exact adapter output from public input, no private observation mapping.
            assert set(payload)==set(llm.payload(bundle,prompt,schema,policy,1))
            assert payload['messages'][0]['content']==prompt.replace('{{BUNDLE_JSON}}',canonical(bundle))
            return {'prompt':'rendered public prompt'}
        assert path=='/tokenize'
        return {'tokens':[1]*4097}
    monkeypatch.setattr(llm_runtime,'query',query)
    result=final.preflight(tmp_path,'test',server_path)
    assert result['slot_statuses']=={'context_unavailable':480}
    assert result['observation_statuses']=={'context_unavailable':160}
    assert len(calls)==960 and set(calls)=={'/apply-template','/tokenize'}
    directory=tmp_path/'build/final/preflight/test'
    manifest=read_json(directory/'manifest.json')
    row=manifest['slots'][0]
    # Overflow keeps the complete request; it is never cropped or dispatched.
    assert read_json(directory/row['request'])==llm.payload(bundle,prompt,schema,policy,row['repetition'])
    for path, mutate, message in [
        (directory/row['request'],lambda data:{**data,'max_tokens':1},'Public request changed'),
        (directory/row['budget'],lambda data:{**data,'prompt_tokens':4096},'Token evidence changed'),
        (directory/'shared-eligibility.json',lambda data:{**data,'observations':[]},'Shared eligibility differs'),
        (directory/'manifest.json',lambda data:{**data,'slots':data['slots'][:-1]},'Scheduled slots differ')]:
        before=path.read_text();path.write_text(canonical(mutate(read_json(path))))
        with pytest.raises(ValueError,match=message):final.verify_preflight(tmp_path,'test')
        path.write_text(before)
    # Even rehashing the budget cannot disguise wrong arithmetic/disposition.
    budget_path=directory/row['budget'];before=budget_path.read_text()
    changed=read_json(budget_path);changed['status']='available';budget_path.write_text(canonical(changed))
    manifest['slots'][0]['budget_sha256']=final.digest(budget_path)
    (directory/'manifest.json').write_text(canonical(manifest))
    with pytest.raises(ValueError,match='Budget disposition differs'):final.verify_preflight(tmp_path,'test')


def test_freeze_rejects_failed_test_gate(tmp_path,monkeypatch):
    monkeypatch.setattr(final,'verify_preflight',lambda *args:{'status':'verified'})
    path=tmp_path/'provenance/phase8-tests.json';path.parent.mkdir()
    path.write_text(canonical({'exit_code':1,'skipped':0}))
    with pytest.raises(ValueError,match='test gate incomplete'):final.freeze(tmp_path)
    assert not (tmp_path/'release').exists()


def test_campaign_cannot_change_locked_method(tmp_path,monkeypatch):
    monkeypatch.setattr(final.method_lock,'verify',lambda:None)
    lock=tmp_path/'lock.json'
    expected=hashlib.sha256(b'locked').hexdigest()
    lock.write_text(canonical({'methods':{'redesign/config.json':expected}}))
    monkeypatch.setattr(final.method_lock,'LOCK',lock)
    (tmp_path/'config.json').write_text('locked')
    final.check_methods(tmp_path)
    (tmp_path/'config.json').write_text('changed')
    with pytest.raises(ValueError,match='Campaign method changed'):final.check_methods(tmp_path)
