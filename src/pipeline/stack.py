"""Narrow instruction-P-code projection for high-P-code-erased stack stores.

Only constants and entry-SP-plus-constant expressions are propagated. No loads,
instruction-name decoding, flag evaluation, branch solving or ABI argument recovery.
The high CFG remains the execution authority; joins retain identical facts only.
"""
from copy import deepcopy
from collections import Counter

from .bundles import address


def key(node):
    return node['space'], node['offset'], node['size']


def project(instruction, incoming, sp, bp):
    env = dict(incoming)
    # A returned call restores SP and preserves RBP under the fixed GCC ABI.
    # All other register facts are discarded; call protocol stores are excluded.
    if instruction['call']:
        return {k:v for k,v in env.items() if k in (sp,bp)}, []
    stores = []
    def get(node):
        if node['space'] == 'const':
            return ('constant',address(node['offset']) & ((1 << (8*node['size']))-1))
        return env.get(key(node))
    for op in instruction['ops']:
        name = op['opcode']; nodes = op['inputs']; values = [get(n) for n in nodes]
        output = op['output']; value = None
        if name=='LOAD':
            # A raw load can fault. Without evaluating it, do not let its erased
            # effect support this or a later fallback store, even if unused.
            return {}, []
        if name in ('BRANCH','CBRANCH','BRANCHIND','CALLOTHER'):
            # Intra-instruction control or userops cannot support a projected store.
            if name == 'CALLOTHER' or nodes and nodes[0]['space'] == 'const':
                return {}, []
        if name == 'STORE' and not instruction['protocol']:
            dest, source = values[1:3]
            if dest is None or dest[0] != 'stack':return {}, []
            stores.append((dest[1],nodes[2]['size'],source[1] if source and source[0]=='constant' else None))
        if name == 'COPY' and values:value=values[0]
        elif name in ('INT_ADD','INT_SUB') and all(values):
            a,b=values
            if name=='INT_ADD' and a[0]=='constant' and b[0]=='stack':a,b=b,a
            if b[0]=='constant':
                bits=8*nodes[1]['size']; amount=b[1]
                if amount & (1 << (bits-1)):amount-=1<<bits
                value=(a[0],a[1]+(amount if name=='INT_ADD' else -amount))
        if output:
            # Overlapping register writes invalidate wider/partial affine facts.
            space,offset,size=key(output); start=address(offset)
            for old in list(env):
                if old[0]==space and address(old[1])<start+size and start<address(old[1])+old[2]:del env[old]
            if value and (value[0]!='stack' or output['size']==8):
                env[key(output)]=(value[0],value[1] & ((1 << (8*output['size']))-1) if value[0]=='constant' else value[1])
    # Unique-space temporaries are instruction-local, never cross-instruction facts.
    return {k:v for k,v in env.items() if k[0]=='register'}, stores


def augment(function):
    """Return a private execution copy with positionable erased stores restored.

    An unmatched/partially represented write remains subject to the native guard.
    Scalar register values are deliberately not exported as execution facts.
    """
    result=deepcopy(function)
    blocks={b['index']:b for b in result['blocks']}
    sp,bp=key(function['stack_register']),key(function['frame_register'])
    owners=Counter(i['address'] for b in result['blocks'] for i in b['instructions'])
    exits={};pending=set(blocks);projections={}
    while pending:
        ready=[i for i in sorted(pending) if (i==0 or blocks[i]['incoming'])
               and all(p in exits for p in blocks[i]['incoming'])]
        if not ready:break  # Cyclic/ambiguous propagation has no fallback.
        for index in ready:
            block=blocks[index]
            if index==0:env={sp:('stack',0)}
            else:
                parents=[exits[p] for p in block['incoming']]
                env={k:v for k,v in parents[0].items() if all(p.get(k)==v for p in parents[1:])}
            for instruction in sorted(block['instructions'],key=lambda i:address(i['address'])):
                if owners[instruction['address']]!=1:
                    env={};continue
                env,stores=project(instruction,env,sp,bp)
                projections[instruction['address']]=(index,stores)
            exits[index]=env;pending.remove(index)
    covered={}
    for block in result['blocks']:
        for op in block['ops']:
            width=(op['inputs'][2]['size'] if op['opcode']=='STORE' else
                   op['output']['size'] if op['opcode'] in ('COPY','CAST') and op['output']
                   and op['output']['space'] in ('ram','stack') else 0)
            covered[op['address']]=covered.get(op['address'],0)+width
    needed={}
    for write in function['native_writes']:
        needed[write['address']]=needed.get(write['address'],0)+write['size']
    for pc,(index,stores) in sorted(projections.items(),key=lambda pair:address(pair[0])):
        if covered.get(pc,0) or not stores or sum(s[1] for s in stores)!=needed.get(pc):continue
        ops=blocks[index]['ops'];cut=next((i for i,o in enumerate(ops) if address(o['address'])>=address(pc)),len(ops))
        # Decompiler reordering must not move a restored effect past an earlier
        # fault or a later witness. Ambiguous placements retain the native guard.
        if any(address(o['address'])<address(pc) for o in ops[cut:] if o['opcode']!='MULTIEQUAL'):continue
        if any(o['opcode'] in ('RETURN','BRANCH','CBRANCH') for o in ops[:cut]):continue
        restored=[]
        for number,(offset,size,value) in enumerate(stores):
            def node(space,raw,width):
                return {'id':f'fallback-{pc}-{number}-{space}','space':space,'offset':hex(raw & ((1<<64)-1)),
                        'size':width,'parameter':None,'stack_base':False}
            restored.append({'opcode':'STORE','address':pc,'output':None,
                             'inputs':[node('const',0,8),node('stack_address',offset,8),
                                       node('const' if value is not None else 'unique',value or 0,size)]})
        ops[cut:cut]=restored
        result.setdefault('fallback_sites',[]).append(pc)
    return result
