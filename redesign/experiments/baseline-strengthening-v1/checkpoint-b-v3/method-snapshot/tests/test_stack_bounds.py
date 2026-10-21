"""Independent stack IR fixtures exercise the heuristic, not source-derived capacities."""
from copy import deepcopy
import hashlib

import pytest

from redesign.pipeline.baseline_worker import validate_result
from redesign.pipeline.bounds import Engine, Pointer, State, Stop, Value
from redesign.pipeline.bundles import canonical
from test_bounds import Program


def stack_program(capacity=10,width=11,condition=None):
    p=Program(16,width,condition=condition)
    root=p.ir['functions'][0]
    root['stack_variables']=[{'offset':-26,'size':capacity,'array':True,'type':'undefined1[]','whole_function':True}]
    # Replace the allocator call with a genuine caller-frame stack address.
    op=root['blocks'][0]['ops'][0]
    op.update(opcode='PTRSUB',inputs=[dict(p.temp(),stack_base=True),p.const(-26)])
    p.bundle['calls']=[c for c in p.bundle['calls'] if c['site']!=op['address']]
    # Drop free: selected stack storage does not use the allocator contract.
    root['blocks'][2]['ops']=[o for o in root['blocks'][2]['ops'] if o['opcode']!='CALL' or o['address']==p.edges[1]['site']]
    p.edges=[c for c in p.edges if c['target_name'] not in ('malloc','free')]
    p.finish()
    return p


@pytest.mark.parametrize('capacity,width,decision',[(10,10,'not_vulnerable'),(10,11,'vulnerable_CWE-121'),(12,11,'not_vulnerable')])
def test_inferred_array_bound_crosses_into_padding_without_frame_overlap(capacity,width,decision):
    p=stack_program(capacity,width);result=p.run()
    assert result['decision']==decision
    assert 'inferred_stack_object_extent' in result['reason_codes']
    check=result['write_checks'][0]
    assert (check['object_offset'],check['capacity'],check['offset'],check['size'])==(-26,capacity,0,width)
    envelope={'schema_version':2,'method_id':p.policy['method_id'],
              'bundle_sha256':hashlib.sha256(canonical(p.bundle).encode()).hexdigest(),
              'ir_sha256':'0'*64,'status':'completed','prediction':result,'error_code':None}
    validate_result(envelope,p.bundle)
    if decision=='vulnerable_CWE-121':
        changed=deepcopy(envelope);changed['prediction']['write_checks'][0]['capacity']=100
        with pytest.raises(ValueError,match='Contradictory'):validate_result(changed,p.bundle)
        changed=deepcopy(envelope);changed['prediction']['reason_codes'].remove('inferred_stack_object_extent')
        with pytest.raises(ValueError,match='qualification'):validate_result(changed,p.bundle)


def test_pointer_offsets_keep_the_original_array_identity_one_past_end():
    p=stack_program(width=1)
    helper=p.ir['functions'][1];block=helper['blocks'][0];store=block['ops'][0]
    dest=p.temp();block['ops'].insert(0,{'opcode':'INT_ADD','address':'0x1100','inputs':[store['inputs'][1],p.const(10)],'output':dest})
    store['inputs'][1]=dest
    result=p.run();assert result['decision']=='vulnerable_CWE-121'
    assert result['write_checks'][0]['offset']==10


@pytest.mark.parametrize('layout,reason',[('missing','missing_stack_array_extent'),('scalar','missing_stack_array_extent'),
    ('overlap','ambiguous_stack_layout'),('lifetime','ambiguous_stack_layout')])
def test_missing_or_ambiguous_recovery_never_borrows_frame_size(layout,reason):
    p=stack_program();variables=p.ir['functions'][0]['stack_variables']
    if layout=='missing':variables.clear()
    if layout=='scalar':variables[0]['array']=False
    if layout=='overlap':variables.append(dict(variables[0],offset=-25,size=4))
    if layout=='lifetime':variables[0]['whole_function']=False
    result=p.run()
    assert result['decision']=='uncertain' and reason in result['reason_codes']
    assert not any(c['outcome']=='exceeds_inferred_extent' for c in result['write_checks'])


def test_infeasible_and_unknown_branches_do_not_create_stack_witnesses():
    assert stack_program(condition='false').run()['decision']=='not_vulnerable'
    result=stack_program(condition='unknown').run()
    assert result['decision']=='uncertain' and 'unresolved_branch' in result['reason_codes']


def test_unknown_stack_offset_stops_before_a_later_witness():
    p=stack_program();block=p.ir['functions'][1]['blocks'][0];store=block['ops'][0]
    dest=p.temp();block['ops'].insert(0,{'opcode':'INT_ADD','address':'0x1100',
        'inputs':[store['inputs'][1],p.temp()],'output':dest})
    store['inputs'][1]=dest
    result=p.run()
    assert result['decision']=='uncertain' and result['reason_codes']==['unresolved_stack_offset']


def test_unestablished_stack_read_cannot_support_a_later_overflow():
    p=stack_program();block=p.ir['functions'][1]['blocks'][0];pointer=block['ops'][0]['inputs'][1]
    block['ops'].insert(0,{'opcode':'LOAD','address':'0x1100','output':p.temp(11),
                          'inputs':[p.const(0),pointer]})
    result=p.run()
    assert result['decision']=='uncertain' and result['reason_codes']==['unknown_read_address']
    assert not result['write_checks']


def test_erased_instruction_store_fallback_is_explicit_and_updates_memory():
    p=stack_program(width=10)
    root=p.ir['functions'][0];block=root['blocks'][2]
    pc=block['ops'][0]['address']
    # Complete independent raw P-code: entry SP - 26, followed by an 11-byte write.
    sp=root['stack_register'];tmp=p.temp();tmp.update(space='unique')
    raw=[{'opcode':'INT_ADD','address':pc,'output':tmp,'inputs':[sp,p.const(-26)]},
         {'opcode':'STORE','address':pc,'output':None,'inputs':[p.const(0),tmp,p.const(0,11)]}]
    block['instructions']=[{'address':pc,'protocol':False,'call':False,'ops':raw}]
    root['native_writes'].append({'address':pc,'size':11})
    result=p.run()
    assert result['decision']=='vulnerable_CWE-121'
    assert 'instruction_pcode_store_fallback' in result['reason_codes']
    assert result['write_checks'][0]['size']==11


def test_fallback_cannot_assume_a_destination_after_a_load_or_unknown_join():
    p=stack_program();root=p.ir['functions'][0];block=root['blocks'][0]
    pc=block['ops'][0]['address'];dest=p.temp()
    block['instructions']=[{'address':pc,'protocol':False,'call':False,'ops':[
        {'opcode':'LOAD','address':pc,'output':dest,'inputs':[p.const(0),p.const(0x3000)]},
        {'opcode':'STORE','address':pc,'output':None,'inputs':[p.const(0),dest,p.const(0,11)]}]}]
    root['native_writes'].append({'address':pc,'size':11})
    assert p.run()['reason_codes']==['unaccounted_native_write']


def test_unmodeled_raw_load_invalidates_even_an_independent_stack_destination():
    p=stack_program();root=p.ir['functions'][0];block=root['blocks'][0]
    pc=block['ops'][0]['address'];dest=p.temp()
    block['instructions']=[{'address':pc,'protocol':False,'call':False,'ops':[
        {'opcode':'LOAD','address':pc,'output':p.temp(),'inputs':[p.const(0),p.const(0xdeadbeef)]},
        {'opcode':'INT_ADD','address':pc,'output':dest,'inputs':[root['stack_register'],p.const(-26)]},
        {'opcode':'STORE','address':pc,'output':None,'inputs':[p.const(0),dest,p.const(0,11)]}]}]
    root['native_writes'].append({'address':pc,'size':11})
    assert p.run()['reason_codes']==['unaccounted_native_write']
