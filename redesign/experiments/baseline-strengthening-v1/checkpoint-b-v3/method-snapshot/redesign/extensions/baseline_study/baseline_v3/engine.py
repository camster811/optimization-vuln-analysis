"""Five bounded effects over the unchanged v2 interpreter and recovery rules."""
from copy import deepcopy
from pathlib import Path
import re

from redesign.pipeline import bounds as v2
from redesign.pipeline.inventory import ROOT, read_json, require

HERE = Path(__file__).resolve().parent
ADDED = ('wmemset','wcslen','wcscpy','strcat','wprintf')
NEW_REASONS = ('contract_resource_limit','invalid_element_count','unknown_contract_source',
               'overlapping_string_copy','ablation_disabled_contract')
Pointer, Value, State, Stop = v2.Pointer, v2.Value, v2.State, v2.Stop


def policy_check(policy):
    expected = read_json(HERE/'policy.json')
    require(policy == expected, 'Unsupported v3 policy; declare a new revision for changes')
    original = read_json(ROOT/'baseline_policy.json')
    projected = deepcopy(policy)
    projected.update(schema_version=1,method_id=original['method_id'])
    projected.pop('wchar_bytes')
    for api in ADDED: projected['library_contracts'].pop(api)
    require(projected == original, 'V3 changed inherited v2 rules/limits')
    return policy


class Engine(v2.Engine):
    def __init__(self,bundle,ir,policy,ablation='full'):
        policy_check(policy)
        require(ablation in ('full','without_memory','without_output'), 'Unknown v3 ablation')
        # The original constructor validates its own version; only the public
        # policy identity is projected. Its recovery/coverage logic is inherited.
        projected=deepcopy(policy);projected.update(schema_version=1,method_id='ghidra-inferred-stack-bounds-v2')
        super().__init__(bundle,ir,projected)
        self.policy=policy;self.ablation=ablation;self.contract_events=[]

    def count_bytes(self,state,count,unit):
        if type(count.raw) is not int or not 0<=count.raw<(1<<64):
            self.stop(state,'invalid_element_count')
        if count.raw>((1<<64)-1)//unit:self.stop(state,'invalid_element_count')
        size=count.raw*unit
        if size>self.policy['max_object_bytes']:self.stop(state,'contract_resource_limit')
        return Value(size,count.evidence)

    def readable(self,state,pointer,size):
        if pointer is None:self.stop(state,'unknown_contract_source')
        if pointer.kind=='heap':
            if pointer.base in state.freed or pointer.base not in state.allocations:
                self.stop(state,'nonlive_allocation')
            if not 0<=pointer.offset<=pointer.offset+size<=state.allocations[pointer.base]:
                self.stop(state,'unknown_contract_source')
        elif pointer.kind=='stack':
            variable=self.stack_extent(state,pointer)
            if not variable['offset']<=pointer.offset<=pointer.offset+size<=variable['offset']+variable['size']:
                self.stop(state,'unknown_contract_source')
        elif pointer.kind=='static':
            if not all(pointer.offset+i in self.static for i in range(size)):
                self.stop(state,'unknown_contract_source')
        else:self.stop(state,'unknown_contract_source')

    @staticmethod
    def offset(pointer,amount):
        return Pointer(pointer.kind,pointer.base,pointer.offset+amount,pointer.object_offset)

    def terminated(self,state,value,unit):
        pointer=self.ptr(value.raw);proof=set(value.evidence);raw=bytearray()
        for offset in range(0,self.policy['max_string_bytes']-unit+1,unit):
            at=self.offset(pointer,offset) if pointer else None
            self.readable(state,at,unit)
            part=self.read(state,at,unit)
            if not isinstance(part.raw,int):self.stop(state,'unknown_contract_source')
            proof.update(part.evidence);raw.extend(part.raw.to_bytes(unit,'little'))
            if part.raw==0:return bytes(raw),frozenset(proof)
        self.stop(state,'contract_resource_limit')

    def overlap(self,state,dest,dest_size,source,source_size):
        if dest and source and dest.kind==source.kind and dest.base==source.base and dest_size and source_size \
                and dest.offset<source.offset+source_size and source.offset<dest.offset+dest_size:
            self.stop(state,'overlapping_string_copy')

    def external(self,state,edge,args,pc):
        api=edge['target_name']
        if api not in ADDED:return super().external(state,edge,args,pc)
        event={'api':api,'site':pc,'outcome':'completed'};self.contract_events.append(event)
        try:
            if self.ablation=='without_memory' and api!='wprintf' or self.ablation=='without_output' and api=='wprintf':
                self.stop(state,'ablation_disabled_contract')
            def arg(index):
                if index>=len(args):self.stop(state,'argument_recovery')
                return args[index]
            if api=='wmemset':
                dest=arg(0);value=arg(1);count=self.count_bytes(state,arg(2),4)
                self.check(state,dest,count,pc)
                pointer=self.ptr(dest.raw)
                for offset in range(0,count.raw,4):
                    self.store(state,self.offset(pointer,offset),4,Value(
                        value.raw&0xffffffff if isinstance(value.raw,int) else None,value.evidence|{pc}))
                return [(state,dest)]
            if api=='wcslen':
                raw,proof=self.terminated(state,arg(0),4)
                return [(state,Value(len(raw)//4-1,proof|{pc}))]
            if api in ('wcscpy','strcat'):
                dest,src=arg(0),arg(1);dp,sp=self.ptr(dest.raw),self.ptr(src.raw)
                raw,proof=self.terminated(state,src,4 if api=='wcscpy' else 1)
                prefix=0
                if api=='strcat':
                    current,previous=self.terminated(state,dest,1);prefix=len(current)-1;proof|=previous
                self.overlap(state,dp,prefix+len(raw),sp,len(raw))
                count=self.count_bytes(state,Value(len(raw),proof),1)
                shifted=Value(self.offset(dp,prefix) if dp else None,dest.evidence|proof)
                self.check(state,shifted,count,pc)
                for index,byte in enumerate(raw):
                    self.store(state,self.offset(dp,prefix+index),1,Value(byte,proof|{pc}))
                return [(state,dest)]
            raw,proof=self.terminated(state,arg(0),4)
            codepoints=[int.from_bytes(raw[i:i+4],'little') for i in range(0,len(raw)-4,4)]
            if any(c>127 for c in codepoints):self.stop(state,'unsupported_output_format')
            text=''.join(map(chr,codepoints));index=0;argument=1
            while index<len(text):
                if text[index]!='%':index+=1;continue
                conversion=next((c for c in ('%%','%ls','%lc','%d','%u') if text.startswith(c,index)),None)
                if conversion is None:self.stop(state,'unsupported_output_format')
                index+=len(conversion)
                if conversion=='%%':continue
                value=arg(argument);argument+=1
                if conversion=='%ls':self.terminated(state,value,4)
                elif not isinstance(value.raw,int):self.stop(state,'argument_recovery')
            return [(state,Value(None,proof|{pc}))]
        except Stop as error:
            event['outcome']=str(error)
            raise

    def run(self):
        result=super().run()
        result['contract_events']=self.contract_events
        return result


def analyze(bundle,ir,policy,ablation='full'):
    return Engine(bundle,ir,policy,ablation).run()
