"""Independent IR fixtures for the declared constant-bounds rule support boundary."""
from copy import deepcopy

import pytest

from redesign.pipeline.bounds import Engine, Pointer, State, Value, analyze, signed
from redesign.pipeline.bundles import empty_bundle, normalize, string_prefix
from redesign.pipeline.inventory import ROOT, read_json


class Program:
    def __init__(self, capacity=16, width=12, mode='store', condition=None):
        self.policy=read_json(ROOT/'baseline_policy.json')
        self.bundle=empty_bundle('0x1000','entry_unavailable')
        self.bundle.update(status='available')
        self.bundle['completeness'].update(traversal='complete',data='complete',decompilation='complete',omissions=[])
        self.ir={'schema_version':2,'engine':'ghidra-high-pcode','status':'ok','functions':[]}
        self.counter=0;self.edges=[];self.pc=0x1000
        p=self.temp();nonnull=self.temp(1)
        self.fn=self.function(0x1000,0)
        self.block=self.new_block(0,[],[1,2])
        self.call('malloc',[self.const(capacity)],p)
        self.op('INT_NOTEQUAL',[p,self.const(0)],nonnull)
        self.op('CBRANCH',[self.const(0),nonnull])
        self.block=self.new_block(1,[0],[]);self.op('RETURN',[self.const(0)])
        self.block=self.new_block(2,[0],[])
        self.call('helper',[p],None,0x1100)
        self.call('free',[p]);self.op('RETURN',[self.const(0)])
        self.pc=0x1100;self.fn=self.function(0x1100,1)
        self.block=self.new_block(0,[],[1,2] if condition else [])
        parameter=self.temp();parameter['parameter']=0
        if condition:
            value=self.const(0) if condition=='false' else self.temp(1)
            self.op('CBRANCH',[self.const(0),value])
            self.block=self.new_block(1,[0],[]);self.op('RETURN',[self.const(0)])
            self.block=self.new_block(2,[0],[])
        if mode=='unsupported_before':self.call('opaque',[])
        if mode=='stack':
            parameter=self.temp();parameter.update(space='register',stack_base=True)
        if mode in ('copy','string_copy'):
            source=self.const(0x3000)
            if mode=='copy':self.call('memcpy',[parameter,source,self.const(width)])
            else:self.call('strcpy',[parameter,source])
        else:self.op('STORE',[self.const(0),parameter,self.const(0,width)])
        if mode=='unsupported_after':self.call('opaque',[])
        self.op('RETURN',[self.const(0)])
        self.finish()

    def temp(self,size=8):
        self.counter+=1
        return {'id':str(self.counter),'space':'unique','offset':hex(self.counter),'size':size,'parameter':None,'stack_base':False}

    def const(self,value,size=8):
        node=self.temp(size);node.update(space='const',offset=hex(value & ((1<<64)-1)));return node

    def function(self,entry,parameters):
        sp=self.temp();sp.update(space='register',offset='0x20')
        bp=self.temp();bp.update(space='register',offset='0x28')
        function={'entry':hex(entry),'parameter_count':parameters,'blocks':[],'native_writes':[],
                  'stack_variables':[],'stack_register':sp,'frame_register':bp}
        self.ir['functions'].append(function);return function

    def new_block(self,index,incoming,outgoing):
        block={'index':index,'start':hex(self.pc),'incoming':incoming,'outgoing':outgoing,'ops':[],'instructions':[]}
        self.fn['blocks'].append(block);return block

    def op(self,opcode,inputs,output=None):
        pc=hex(self.pc);self.pc+=1
        op={'opcode':opcode,'address':pc,'output':output,'inputs':inputs};self.block['ops'].append(op)
        if opcode=='STORE':self.fn['native_writes'].append({'address':pc,'size':inputs[2]['size']})
        return pc

    def call(self,name,args,output=None,target=None):
        pc=self.op('CALL',[self.const(target or 0x8000),*args],output)
        self.edges.append({'caller':self.fn['entry'],'site':pc,'target_address':hex(target or 0x8000),
                           'target_entry':hex(target) if target else None,'target_name':name,'kind':'call',
                           'resolution':'application' if target else 'external'})

    def finish(self):
        self.bundle['functions']=[]
        for function in self.ir['functions']:
            pcs=sorted({o['address'] for b in function['blocks'] for o in b['ops']},key=lambda a:int(a,16))
            self.bundle['functions'].append({'entry':function['entry'],'name':'unit_'+function['entry'][2:],
                'name_origin':'analysis','ranges':[{'start':pcs[0],'end':hex(int(pcs[-1],16)+1)}],
                'instructions':[{'address':pc,'size':1,'bytes':'90','mnemonic':'NOP','operands':''} for pc in pcs],
                'decompilation':{'status':'ok','text':'void unit(void) { return; }'}})
        self.bundle['calls']=deepcopy(self.edges)
        self.bundle['data']=[{'address':'0x3000','size':12,'bytes':b'ABCDEFGHIJK\0'.hex(),'string_prefix':'ABCDEFGHIJK',
            'writable':False,'storage':'initialized','extent_status':'recovered_type_extent','recovered_type':'string',
            'interpretation':'uncertain_binary_recovery_not_an_object_bound','references':['0x1100'],'truncated':False}]
        self.bundle=normalize(self.bundle)

    def run(self):return analyze(self.bundle,self.ir,self.policy)


@pytest.mark.parametrize('mode',['store','copy','string_copy'])
@pytest.mark.parametrize('capacity,expected',[(8,'vulnerable_CWE-122'),(16,'not_vulnerable')])
def test_allocations_in_caller_and_writes_in_callee(mode,capacity,expected):
    p=Program(capacity,mode=mode);result=p.run()
    assert result['decision']==expected
    assert result['paths']==2  # Null and successful malloc returns are both accounted for.
    assert any(check['capacity']==capacity for check in result['write_checks'])
    if expected.startswith('vulnerable'):
        assert '0x1000' in result['evidence'] and any(int(a,16)>=0x1100 for a in result['evidence'])


@pytest.mark.parametrize('mode,reason',[('stack','missing_stack_array_extent'),('unsupported_before','unsupported_library_call')])
def test_supported_engine_declines_unknown_effects(mode,reason):
    result=Program(8,mode=mode).run()
    assert result['decision']=='uncertain' and reason in result['reason_codes']


def test_unknown_bounds_inferred_array_types_and_function_names_do_not_create_truth():
    p=Program(8);original=p.run()
    for f in p.bundle['functions']:
        f['name']='handle'
        f['decompilation']['text']='void handle(void) { char buffer[4096]; }'
    assert p.run()==original
    # No source/debug-derived capacity is accepted by the public schema.
    p.bundle['source_capacity']=4096
    with pytest.raises(Exception):p.run()


def test_missing_destination_capacity_abstains_without_borrowing_an_allocation():
    p=Program(16)
    store=p.ir['functions'][1]['blocks'][0]['ops'][0]
    store['inputs'][1]=p.temp()  # An unknown incoming pointer, not the caller's tracked allocation.
    result=p.run()
    assert result['decision']=='uncertain' and result['reason_codes']==['unknown_destination']


@pytest.mark.parametrize('direct',[False,True])
def test_read_outside_shared_data_cannot_support_a_later_overflow(direct):
    p=Program(8);block=p.ir['functions'][1]['blocks'][0]
    # Reading 16 bytes from a 12-byte window cannot be assumed nonfaulting, even if unused.
    node=p.const(0x3000)
    if direct:
        node.update(space='ram',size=16)
        op={'opcode':'COPY','address':'0x1100','output':p.temp(16),'inputs':[node]}
    else:
        op={'opcode':'LOAD','address':'0x1100','output':p.temp(16),'inputs':[p.const(0),node]}
    block['ops'].insert(0,op)
    result=p.run()
    assert result['decision']=='uncertain' and result['reason_codes']==['unknown_read_address']


def test_concrete_infeasibility_does_not_turn_into_speculative_overflow():
    assert Program(8,condition='false').run()['decision']=='not_vulnerable'
    result=Program(8,condition='unknown').run()
    assert result['decision']=='uncertain' and result['reason_codes']==['unresolved_branch']
    assert not any(c['outcome']=='exceeds_allocation' for c in result['write_checks'])


def test_feasible_write_preceding_unsupported_effect_is_preserved():
    assert Program(8,mode='unsupported_after').run()['decision']=='vulnerable_CWE-122'
    assert Program(8,mode='unsupported_before').run()['decision']=='uncertain'


def test_dead_or_missing_high_pcode_cannot_hide_a_native_write():
    p=Program(16)
    function=p.ir['functions'][1]
    pc=function['blocks'][0]['ops'][-1]['address']
    function['native_writes'].append({'address':pc,'size':1})
    result=p.run()
    assert result['decision']=='uncertain' and result['reason_codes']==['unaccounted_native_write']


def test_loop_step_and_call_resource_limits_decline_without_fake_safety():
    p=Program(16);function=p.ir['functions'][1];block=function['blocks'][0]
    block.update(incoming=[0],outgoing=[0]);block['ops'][-1]['opcode']='BRANCH'
    assert p.run()['reason_codes']==['cyclic_control_flow']
    p=Program(16);p.policy['max_steps']=1
    assert p.run()['reason_codes']==['step_limit']
    p=Program(16);p.policy['max_call_depth']=1
    assert p.run()['reason_codes']==['call_depth_limit']


def test_distinct_allocations_do_not_share_sizes_or_byte_contents():
    p=Program();engine=Engine(p.bundle,p.ir,p.policy)
    edge={'target_name':'malloc'};state=State()
    state,first=engine.external(state,edge,[Value(8)],'0x1000')[0]
    state,second=engine.external(state,edge,[Value(16)],'0x1000')[0]
    assert first.raw.base!=second.raw.base
    engine.check(state,Value(Pointer('heap',second.raw.base,12)),Value(4),'0x1000')
    assert state.checks[-1]['capacity']==16 and state.checks[-1]['outcome']=='within_bounds'
    engine.store(state,first.raw,1,Value(42))
    assert engine.read(state,second.raw,1).raw is None


def test_integer_bit_widths_and_pointer_truncation_are_not_ignored():
    p=Program();engine=Engine(p.bundle,p.ir,p.policy)
    output=p.temp(4)
    op={'opcode':'INT_ADD','address':'0x1000','output':output,'inputs':[p.const(0xffffffff,4),p.const(1,4)]}
    value=engine.primitive(op,[Value(0xffffffff),Value(1)])
    env={};engine.assign(output,value,env,'frame',State(),'0x1000')
    assert env[output['id']].raw==0
    engine.assign(output,Value(Pointer('heap','obj')),env,'frame',State(),'0x1000')
    assert env[output['id']].raw is None
    assert signed(0xffffffff,32)==-1
    op={'opcode':'PTRADD','address':'0x1000','output':p.temp(),
        'inputs':[p.temp(),p.const(0x40000000,4),p.const(4)]}
    value=engine.primitive(op,[Value(Pointer('heap','obj')),Value(0x40000000),Value(4)])
    assert value.raw is None  # A four-GiB offset must not wrap to zero in a 32-bit temporary.


def test_mutable_static_initial_bytes_are_not_assumed_to_be_runtime_constants():
    p=Program();p.bundle['data'][0]['writable']=True
    engine=Engine(p.bundle,p.ir,p.policy)
    assert engine.string(engine.initial,Value(0x3000)) is None


@pytest.mark.parametrize('mode',['store','direct','memset'])
@pytest.mark.parametrize('writable',[False,True])
def test_static_write_permissions_gate_later_overflow(mode,writable):
    p=Program(8);p.bundle['data'][0]['writable']=writable
    function=p.ir['functions'][1];block=function['blocks'][0]
    pc='0x1100'
    if mode=='direct':
        output=p.temp(1);output.update(space='ram',offset='0x3000')
        op={'opcode':'COPY','address':pc,'output':output,'inputs':[p.const(88,1)]}
    elif mode=='memset':
        op={'opcode':'CALL','address':pc,'output':None,
            'inputs':[p.const(0x8000),p.const(0x3000),p.const(88),p.const(1)]}
        p.bundle['calls'].append({'caller':function['entry'],'site':pc,'target_address':'0x8000',
            'target_entry':None,'target_name':'memset','kind':'call','resolution':'external'})
    else:
        op={'opcode':'STORE','address':pc,'output':None,
            'inputs':[p.const(0),p.const(0x3000),p.const(88,1)]}
    block['ops'].insert(0,op)
    result=p.run()
    assert result['decision']==('vulnerable_CWE-122' if writable else 'uncertain')
    if not writable:
        assert result['reason_codes']==['static_write_not_writable']
        assert not any(c['outcome']=='exceeds_allocation' for c in result['write_checks'])


def overlapping_window(p,writable=None):
    original=p.bundle['data'][0]
    overlap=deepcopy(original);raw=bytes.fromhex(original['bytes'])[1:]
    overlap.update(address='0x3001',size=len(raw),bytes=raw.hex(),string_prefix=string_prefix(raw))
    if writable is not None:overlap['writable']=writable
    p.bundle['data'].append(overlap)
    return overlap


@pytest.mark.parametrize('writable',[False,True])
def test_consistent_overlapping_windows_validate_image_bytes_not_runtime_values(writable):
    p=Program();p.bundle['data'][0]['writable']=writable
    overlapping_window(p)
    engine=Engine(p.bundle,p.ir,p.policy)
    assert engine.read(engine.initial,Pointer('static','image',0x3001),1).raw==(None if writable else 66)
    assert p.run()['decision']=='not_vulnerable'


def test_conflicting_original_bytes_are_rejected_even_for_writable_windows():
    p=Program();p.bundle['data'][0]['writable']=True
    overlap=overlapping_window(p)
    raw=b'Z'+bytes.fromhex(overlap['bytes'])[1:]
    overlap.update(bytes=raw.hex(),string_prefix=string_prefix(raw))
    with pytest.raises(Exception,match='Conflicting public data windows'):p.run()


@pytest.mark.parametrize('first_writable',[False,True])
def test_conflicting_permissions_cannot_prove_writability_or_constant_contents(first_writable):
    p=Program();p.bundle['data'][0]['writable']=first_writable
    overlapping_window(p,writable=not first_writable)
    engine=Engine(p.bundle,p.ir,p.policy)
    assert engine.read(engine.initial,Pointer('static','image',0x3001),1).raw is None
    state=State()
    with pytest.raises(Exception,match='static_write_not_writable'):
        engine.check(state,Value(0x3001),Value(1),'0x1100')
    # Even one read-only byte prevents establishing the whole write.
    with pytest.raises(Exception,match='static_write_not_writable'):
        engine.check(state,Value(0x3000),Value(2),'0x1100')
    engine.check(state,Value(0x3000),Value(0),'0x1100')
    assert state.checks[-1]['outcome']=='zero_extent'
