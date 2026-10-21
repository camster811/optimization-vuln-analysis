"""Independent bounded library semantics; no research labels enter the engine."""
from copy import deepcopy
import pytest

from redesign.extensions.baseline_study.baseline_v3.engine import Engine,State,Pointer,Value,Stop,HERE,analyze
from redesign.extensions.baseline_study.baseline_v3.worker import validate_result
from redesign.pipeline.inventory import read_json,digest
from redesign.pipeline.bundles import normalize,string_prefix,canonical
from test_bounds import Program

PC='0x1100'


def environment(raw=b'A\0\0\0\0\0\0\0',capacity=16):
    p=Program(mode='copy')
    p.bundle['data'][0].update(size=len(raw),bytes=raw.hex(),string_prefix=string_prefix(raw))
    p.bundle=normalize(p.bundle)
    engine=Engine(p.bundle,p.ir,read_json(HERE/'policy.json'))
    state=deepcopy(engine.initial);state.allocations['dest']=capacity
    return engine,state,Value(Pointer('heap','dest'))


def call(engine,state,api,*args):
    return engine.external(state,{'target_name':api},list(args),PC)[0][1]


@pytest.mark.parametrize('capacity,count,outcome',[(16,4,'within_bounds'),(15,4,'exceeds_allocation'),(8,2,'within_bounds')])
def test_wide_fill_checks_full_byte_footprint_before_mutation(capacity,count,outcome):
    e,s,p=environment(capacity=capacity)
    if outcome=='exceeds_allocation':
        before=deepcopy(s.memory)
        with pytest.raises(Stop,match='overflow_witness'):call(e,s,'wmemset',p,Value(65),Value(count))
        assert s.memory==before
    else:
        assert call(e,s,'wmemset',p,Value(65),Value(count))==p
        assert e.read(s,p.raw,count*4).raw==int.from_bytes((65).to_bytes(4,'little')*count,'little')
    assert s.checks[-1]['size']==count*4 and s.checks[-1]['outcome']==outcome


@pytest.mark.parametrize('count,reason',[(-1,'invalid_element_count'),(1<<64,'invalid_element_count'),
                                      (1<<63,'invalid_element_count'),(1025,'contract_resource_limit')])
def test_invalid_or_excessive_element_counts_abstain_without_memory_effects(count,reason):
    e,s,p=environment();before=deepcopy(s.memory)
    with pytest.raises(Stop,match=reason):call(e,s,'wmemset',p,Value(0),Value(count))
    assert s.memory==before and not s.checks


def test_zero_fill_and_unknown_value_do_not_invent_bytes_or_termination():
    e,s,p=environment()
    assert call(e,s,'wmemset',Value(),Value(),Value(0)).raw is None
    assert s.checks[-1]['outcome']=='zero_extent'
    call(e,s,'wmemset',p,Value(),Value(4))
    with pytest.raises(Stop,match='unknown_contract_source'):call(e,s,'wcslen',p)


def test_wide_length_requires_zero_element_not_zero_byte():
    e,s,p=environment(b'\x00\x00\x01\x00'+b'\0'*4)
    assert call(e,s,'wcslen',Value(0x3000)).raw==1
    assert call(e,s,'wcscpy',p,Value(0x3000))==p
    assert s.checks[-1]['size']==8
    assert e.read(s,p.raw,8).raw==65536


@pytest.mark.parametrize('capacity',[7,8])
def test_wide_copy_includes_terminator_and_returns_original_destination(capacity):
    e,s,p=environment(capacity=capacity)
    if capacity==7:
        with pytest.raises(Stop,match='overflow_witness'):call(e,s,'wcscpy',p,Value(0x3000))
    else:assert call(e,s,'wcscpy',p,Value(0x3000))==p
    assert s.checks[-1]['size']==8


def test_copy_reads_and_lifetimes_precede_destination_overflow_witness():
    e,s,p=environment(b'A\0\0\0',capacity=1)
    with pytest.raises(Stop,match='unknown_contract_source'):call(e,s,'wcscpy',p,Value(0x3000))
    assert not s.checks
    s.allocations['source']=8;s.freed.add('source')
    with pytest.raises(Stop,match='nonlive_allocation'):call(e,s,'wcscpy',p,Value(Pointer('heap','source')))
    with pytest.raises(Stop,match='nonlive_allocation'):
        s.freed.add('dest');call(e,s,'wmemset',p,Value(0),Value(1))


@pytest.mark.parametrize('capacity,expected',[(6,'within_bounds'),(5,'exceeds_allocation')])
def test_concatenation_preserves_prefix_and_destination_identity(capacity,expected):
    e,s,p=environment(b'abc\0',capacity=capacity)
    for i,b in enumerate(b'hi\0'):e.store(s,e.offset(p.raw,i),1,Value(b))
    if expected=='exceeds_allocation':
        with pytest.raises(Stop,match='overflow_witness'):call(e,s,'strcat',p,Value(0x3000))
    else:
        assert call(e,s,'strcat',p,Value(0x3000))==p
        assert e.read(s,p.raw,6).raw==int.from_bytes(b'hiabc\0','little')
    assert s.checks[-1]['offset']==2 and s.checks[-1]['size']==4


def test_concatenation_empty_unknown_prefix_and_overlap():
    e,s,p=environment(b'\0',capacity=1);e.store(s,p.raw,1,Value(0))
    assert call(e,s,'strcat',p,Value(0x3000))==p
    e,s,p=environment(b'ab\0')
    with pytest.raises(Stop,match='unknown_contract_source'):call(e,s,'strcat',p,Value(0x3000))
    for i,b in enumerate(b'ab\0'):e.store(s,e.offset(p.raw,i),1,Value(b))
    with pytest.raises(Stop,match='overlapping_string_copy'):call(e,s,'strcat',p,p)
    e.store(s,p.raw,8,Value(0))
    with pytest.raises(Stop,match='overlapping_string_copy'):call(e,s,'wcscpy',p,p)


def test_inferred_stack_bound_one_past_end_and_dead_frame():
    e,s,_=environment(b'a\0');p=Value(Pointer('stack','frame',-8,-8))
    e.frame_variables['frame']=[{'offset':-8,'size':8,'array':True,'type':'char[8]','whole_function':True}]
    s.live_frames.add('frame');e.store(s,p.raw,1,Value(0))
    call(e,s,'strcat',p,Value(0x3000))
    assert s.checks[-1]['bound_basis']=='inferred_stack_object_extent'
    with pytest.raises(Stop,match='overflow_witness'):
        call(e,s,'wmemset',Value(e.offset(p.raw,8)),Value(0),Value(1))
    s.live_frames.clear()
    with pytest.raises(Stop,match='unknown_stack_bound'):call(e,s,'wmemset',p,Value(0),Value(1))


def test_readonly_static_and_permission_overlap_are_not_assumed_writable():
    e,s,p=environment(b'\0'*8)
    with pytest.raises(Stop,match='static_write_not_writable'):call(e,s,'wmemset',Value(0x3000),Value(0),Value(1))
    p0=Program(mode='copy');window=deepcopy(p0.bundle['data'][0]);window['writable']=True
    raw=bytes.fromhex(window['bytes'])[1:]
    window.update(address='0x3001',size=len(raw),bytes=raw.hex(),string_prefix=string_prefix(raw))
    p0.bundle['data'].append(window)
    e=Engine(normalize(p0.bundle),p0.ir,read_json(HERE/'policy.json'))
    with pytest.raises(Stop,match='unknown_contract_source'):call(e,deepcopy(e.initial),'wcslen',Value(0x3000))


@pytest.mark.parametrize('fmt',['%n','%*ls','%1$ls','%f','%s','%ld'])
def test_wide_output_rejects_undeclared_formats(fmt):
    e,s,p=environment((fmt+'\0').encode('utf-32-le'))
    with pytest.raises(Stop,match='unsupported_output_format'):call(e,s,'wprintf',Value(0x3000),p)


def test_wide_output_formats_arguments_and_unknown_return():
    e,s,p=environment(('%d %u %lc %%\n\0').encode('utf-32-le'))
    assert call(e,s,'wprintf',Value(0x3000),Value(2),Value(3),Value(65)).raw is None
    assert not s.checks
    with pytest.raises(Stop,match='argument_recovery'):call(e,s,'wprintf',Value(0x3000),Value(2))
    with pytest.raises(Stop,match='argument_recovery'):call(e,s,'wprintf',Value(0x3000),Value(),Value(2),Value(3))
    e,s,p=environment(('%ls\n\0').encode('utf-32-le'))
    with pytest.raises(Stop,match='unknown_contract_source'):call(e,s,'wprintf',Value(0x3000),p)
    e.store(s,p.raw,4,Value(0));assert call(e,s,'wprintf',Value(0x3000),p).raw is None


@pytest.mark.parametrize('before',[True,False])
def test_supported_helper_flow_and_earlier_fault_vs_established_witness(before):
    p=Program(capacity=8,mode='copy')
    op=p.ir['functions'][1]['blocks'][0]['ops'][0]
    op['inputs'][2:]=[p.const(65,4),p.const(3)]
    p.edges[-1]['target_name']='wmemset'
    p.call('opaque',[]);extra=p.block['ops'].pop();p.block['ops'].insert(0 if before else 1,extra)
    p.finish()
    result=analyze(p.bundle,p.ir,read_json(HERE/'policy.json'))
    assert result['decision']==('uncertain' if before else 'vulnerable_CWE-122')


def test_same_ir_ablation_stops_at_disabled_effect():
    e,s,p=environment()
    e.ablation='without_memory'
    with pytest.raises(Stop,match='ablation_disabled_contract'):call(e,s,'wmemset',p,Value(0),Value(1))
    e.ablation='without_output'
    with pytest.raises(Stop,match='ablation_disabled_contract'):call(e,s,'wprintf',Value(0x3000))


def test_wide_string_resource_boundary_and_incomplete_element_are_not_termination():
    e,s,p=environment((65536).to_bytes(4,'little')*1024)
    with pytest.raises(Stop,match='contract_resource_limit'):call(e,s,'wcslen',Value(0x3000))
    e,s,p=environment(b'\x41\0\0')
    with pytest.raises(Stop,match='unknown_contract_source'):call(e,s,'wcslen',Value(0x3000))


def test_worker_v3_schema_projection_and_same_ir_ablations(tmp_path,monkeypatch):
    from redesign.extensions.baseline_study.baseline_v3 import worker
    p=Program(capacity=16,mode='copy');path=tmp_path/'public.json';path.write_text(canonical(p.bundle))
    def lift(bundle,policy,work):
        assert bundle==p.bundle and policy['method_id']=='ghidra-library-contract-bounds-v3'
        work.mkdir(parents=True);(work/'pcode.json').write_text(canonical(p.ir))
    monkeypatch.setattr(worker,'lift',lift)
    result=worker.execute(path,tmp_path/'work',read_json(HERE/'policy.json'))
    assert result['status']=='completed' and result['schema_version']==3
    assert result['ir_sha256']==digest(tmp_path/'work/ir/pcode.json')
    assert set(read_json(tmp_path/'work/ablations.json'))=={'without_memory','without_output'}
    validate_result(result,p.bundle)
    changed=deepcopy(result);changed['prediction']['contract_events']=[{'api':'wcscpy','site':'0xdead','outcome':'completed'}]
    with pytest.raises(ValueError,match='outside bundle'):validate_result(changed,p.bundle)


def test_v3_dispatch_recovery_never_retries_failed_attempts(tmp_path,monkeypatch):
    from datetime import datetime,timezone
    from redesign.extensions.baseline_study.baseline_v3 import campaign
    from redesign.pipeline.llm_runtime import write_new
    p=Program();policy=read_json(HERE/'policy.json')
    write_new(tmp_path/'policy.json',policy)
    schedule=[]
    for identifier in ('opaque-a','opaque-b'):
        write_new(tmp_path/'inputs'/f'{identifier}.json',p.bundle)
        schedule.append({'observation_id':identifier,'bundle_sha256':digest(tmp_path/'inputs'/f'{identifier}.json'),
                         'shared_status':'available'})
    frozen={'methods':campaign.methods(),'policy_sha256':digest(tmp_path/'policy.json'),'schedule':schedule,
            'engine':{},'created_at_utc':'2020-01-01T00:00:00+00:00'}
    write_new(tmp_path/'freeze.json',frozen)
    write_new(tmp_path/'jobs/opaque-a/dispatch.json',{'freeze_sha256':digest(tmp_path/'freeze.json'),
        'bundle_sha256':schedule[0]['bundle_sha256'],'started_at':datetime.now(timezone.utc).isoformat()})
    monkeypatch.setattr(campaign,'verify_freeze',lambda directory:None)
    monkeypatch.setattr(campaign,'engine_identity',lambda policy:{})
    calls=[]
    def worker(argv,**kwargs):
        assert not any('oracle' in a or 'private' in a for a in argv)
        from pathlib import Path
        target=Path(argv[argv.index('--output')+1])
        write_new(target,campaign.failed(policy,schedule[1]['bundle_sha256']))
        calls.append(argv)
        return type('Process',(),{'returncode':0,'stdout':'','stderr':''})()
    monkeypatch.setattr(campaign.subprocess,'run',worker)
    assert campaign.run(tmp_path)['counts']=={'runtime_failed':2}
    first=(tmp_path/'jobs/opaque-a/result.json').read_bytes()
    campaign.run(tmp_path)
    assert len(calls)==1 and (tmp_path/'jobs/opaque-a/result.json').read_bytes()==first


def test_v3_comparison_wrong_cwe_and_shared_unavailability_use_frozen_denominators():
    from redesign.extensions.baseline_study.baseline_v3 import comparison
    from redesign.extensions.baseline_study import scoring
    from test_pilot_evaluation import row
    rows=[row('a',truth='vulnerable_CWE-121'),row('b',shared_availability='context_unavailable')]
    rows=scoring.attach_controls(rows)
    for r in rows:
        for method in ('v3','without_memory','without_output'):
            r['predictions'][method]={'decision':'vulnerable_CWE-122','status':'classified'}
    _,weights=scoring.family_weights(rows,repetitions=20)
    result=comparison.summary(rows,weights,'binary_label')
    metrics=result['methods']['v3']
    assert [metrics[k]['estimate'] for k in ('A','C','E','M','TP','TN')]==[2,0,1,1,1,1]
    assert metrics['selective_accuracy']['estimate']==0
    assert result['paired']['v3_minus_without_memory']['correct_rate']['estimate']==0
