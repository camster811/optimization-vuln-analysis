"""Bounded constant/offset checks on Ghidra high P-code from public bundles only.

No x86 instruction simulator, source capacities, decompiler type bounds, loop solver,
speculative feasibility, general alias analysis or testcase-specific summaries.
"""
from copy import deepcopy
from dataclasses import dataclass, field
import re

from .bundles import address, canonical, evidence_addresses, validate
from .inventory import require
from .pcode import validate_ir


@dataclass(frozen=True)
class Pointer:
    kind: str
    base: str
    offset: int = 0


@dataclass(frozen=True)
class Value:
    raw: object = None
    evidence: frozenset = frozenset()


@dataclass
class State:
    memory: dict = field(default_factory=dict)
    slots: dict = field(default_factory=dict)
    allocations: dict = field(default_factory=dict)
    freed: set = field(default_factory=set)
    checks: list = field(default_factory=list)
    reasons: set = field(default_factory=set)
    path: set = field(default_factory=set)
    terminated: bool = False
    serial: int = 0


class Stop(Exception):
    pass


def signed(value, bits):
    return (value & ((1 << bits) - 1)) - ((1 << bits) if value & (1 << (bits - 1)) else 0)


def policy_check(policy):
    require(policy['schema_version'] == 1 and policy['method_id'] == 'ghidra-constant-bounds-v1'
            and policy['engine'] == 'ghidra-high-pcode'
            and policy['control_flow'] == 'concrete_acyclic_paths_only'
            and policy['allocation_failure'] == 'explore_null_and_fresh_success'
            and policy['stack_bounds'] == 'unknown_without_independent_binary_object_evidence', 'Unsupported baseline policy')
    for key in ('max_steps', 'max_paths', 'max_call_depth', 'max_object_bytes', 'max_string_bytes',
                'decompiler_timeout_seconds', 'process_timeout_seconds'):
        require(type(policy[key]) is int and policy[key] > 0, 'Invalid baseline limit')
    return policy


class Engine:
    def __init__(self, bundle, ir, policy):
        validate(bundle); validate_ir(ir, bundle); policy_check(policy)
        self.bundle, self.policy = bundle, policy
        self.functions = {f['entry']: f for f in ir['functions']}
        self.calls = {(c['caller'], c['site']): c for c in bundle['calls']}
        self.effect_sites = {(f['entry'], op['address']) for f in ir['functions'] for b in f['blocks']
                             for op in b['ops'] if op['opcode'] in ('CALL', 'STORE')}
        self.uncovered = set()
        for function in ir['functions']:
            covered = {}
            for block in function['blocks']:
                for op in block['ops']:
                    width = (op['inputs'][2]['size'] if op['opcode'] == 'STORE' else
                             op['output']['size'] if op['opcode'] in ('COPY', 'CAST') and op['output']
                             and op['output']['space'] in ('ram', 'stack') else 0)
                    covered[op['address']] = covered.get(op['address'], 0) + width
            needed = {}
            for write in function['native_writes']:
                needed[write['address']] = needed.get(write['address'], 0) + write['size']
            self.uncovered.update(pc for pc, size in needed.items() if covered.get(pc, 0) < size)
        self.initial = State()
        self.static = set()
        original_bytes, permissions = {}, {}
        for data in bundle['data']:
            for index, byte in enumerate(bytes.fromhex(data['bytes'])):
                key = ('static', 'image', address(data['address']) + index)
                if key in original_bytes:
                    require(original_bytes[key] == byte, 'Conflicting public data windows')
                original_bytes[key] = byte
                permissions.setdefault(key[2], set()).add(data['writable'])
                self.static.add(key[2])
        # Validate image bytes independently of runtime values. Mutable initial
        # contents are unknown, including overlaps with conflicting permissions.
        self.writable = {offset for offset, flags in permissions.items() if flags == {True}}
        for key, byte in original_bytes.items():
            self.initial.memory[key] = Value(None if True in permissions[key[2]] else byte)
        self.steps = self.paths = 0
        self.frames = 0

    def stop(self, state, reason):
        state.reasons.add(reason)
        raise Stop(reason)

    def ptr(self, value):
        if isinstance(value, Pointer):
            return value
        if isinstance(value, int) and value in self.static:
            return Pointer('static', 'image', value)
        return None

    def read(self, state, pointer, size):
        if pointer is None:
            return Value()
        slot = (pointer.kind, pointer.base, pointer.offset, size)
        if slot in state.slots:
            return state.slots[slot]
        items = [state.memory.get((pointer.kind, pointer.base, pointer.offset + i), Value()) for i in range(size)]
        if not all(isinstance(v.raw, int) for v in items):
            return Value()
        return Value(sum(v.raw << (8 * i) for i, v in enumerate(items)), frozenset().union(*(v.evidence for v in items)))

    def store(self, state, pointer, size, value):
        for key in list(state.slots):
            if key[:2] == (pointer.kind, pointer.base) and key[2] < pointer.offset + size and pointer.offset < key[2] + key[3]:
                del state.slots[key]
        for i in range(size):
            byte = (value.raw >> (i * 8)) & 255 if isinstance(value.raw, int) else None
            state.memory[(pointer.kind, pointer.base, pointer.offset + i)] = Value(byte, value.evidence)
        state.slots[(pointer.kind, pointer.base, pointer.offset, size)] = value

    def get(self, node, env, args, frame, state):
        if node['space'] == 'const':
            return Value(address(node['offset']) & ((1 << (8 * node['size'])) - 1))
        if node['stack_base']:
            return Value(Pointer('stack', frame))
        if node['parameter'] is not None:
            value = args[node['parameter']] if node['parameter'] < len(args) else Value()
            if isinstance(value.raw, int): return Value(value.raw & ((1 << (8*node['size']))-1), value.evidence)
            return value if node['size'] == 8 else Value(None, value.evidence)
        if node['space'] == 'ram':
            return self.read(state, Pointer('static', 'image', address(node['offset'])), node['size'])
        return env.get(node['id'], Value())

    def assign(self, output, value, env, frame, state, pc):
        if output is None:
            return
        if isinstance(value.raw, int):
            value = Value(value.raw & ((1 << (8 * output['size'])) - 1), value.evidence)
        if isinstance(value.raw, Pointer) and output['size'] != 8:
            value = Value(None, value.evidence)
        if output['space'] == 'stack':
            self.stop(state, 'unknown_stack_bound')
        if output['space'] == 'ram':
            pointer = Pointer('static', 'image', address(output['offset']))
            self.check(state, Value(pointer), Value(output['size']), pc)
            self.store(state, pointer, output['size'], value)
        env[output['id']] = value

    def check(self, state, destination, count, pc):
        pointer = self.ptr(destination.raw)
        proof = set(destination.evidence | count.evidence) | state.path | {pc}
        row = {'site': pc, 'region': pointer.kind if pointer else 'unknown',
               'offset': pointer.offset if pointer else None, 'size': count.raw if isinstance(count.raw, int) else None,
               'capacity': None, 'outcome': 'unknown', 'evidence': sorted(proof, key=address)}
        state.checks.append(row)
        if not isinstance(count.raw, int): self.stop(state, 'unknown_write_extent')
        if count.raw == 0:
            row['outcome'] = 'zero_extent'; return
        if pointer is None: self.stop(state, 'unknown_destination')
        if pointer.kind == 'stack': self.stop(state, 'unknown_stack_bound')
        if pointer.kind == 'heap':
            if pointer.base in state.freed: self.stop(state, 'nonlive_allocation')
            capacity = state.allocations[pointer.base]
            row['capacity'] = capacity
            row['outcome'] = ('within_bounds' if 0 <= pointer.offset and pointer.offset + count.raw <= capacity
                              else 'exceeds_allocation')
            if row['outcome'] == 'exceeds_allocation': self.stop(state, 'overflow_witness')
        elif pointer.kind == 'static':
            if not all(pointer.offset + i in self.static for i in range(count.raw)):
                self.stop(state, 'static_write_outside_export')
            if not all(pointer.offset + i in self.writable for i in range(count.raw)):
                self.stop(state, 'static_write_not_writable')
            row['outcome'] = 'static_storage_write'

    def string(self, state, value):
        pointer = self.ptr(value.raw)
        if pointer is None: return None
        chars, proof = [], set(value.evidence)
        for offset in range(self.policy['max_string_bytes']):
            p = Pointer(pointer.kind, pointer.base, pointer.offset + offset)
            if p.kind == 'heap' and (p.base in state.freed or not 0 <= p.offset < state.allocations[p.base]):
                return None
            byte = self.read(state, p, 1)
            if not isinstance(byte.raw, int): return None
            proof.update(byte.evidence)
            if byte.raw == 0: return bytes(chars), frozenset(proof)
            chars.append(byte.raw)
        return None

    def primitive(self, op, values):
        name = op['opcode']; raw = [v.raw for v in values]
        proof = frozenset({op['address']}).union(*(v.evidence for v in values))
        out = op['output']; bits = out['size'] * 8 if out else 64
        if name in ('COPY', 'CAST', 'INT_ZEXT'):
            return Value(None if isinstance(raw[0], Pointer) and out['size'] != 8 else raw[0], proof)
        if name == 'INT_SEXT' and isinstance(raw[0], int):
            return Value(signed(raw[0], op['inputs'][0]['size'] * 8), proof)
        if name in ('PTRADD', 'PTRSUB', 'INT_ADD', 'INT_SUB'):
            base = raw[0]; amount = raw[1]
            if name == 'PTRADD': amount = amount * raw[2] if isinstance(amount, int) and isinstance(raw[2], int) else None
            if isinstance(base, Pointer) and isinstance(amount, int):
                width = op['inputs'][1]['size'] * 8
                if width < 64 and raw[1] >= (1 << (width-1)): return Value(None, proof)
                amount = signed(amount, 64 if name == 'PTRADD' else width)
                offset = base.offset + (-amount if name == 'INT_SUB' else amount)
                return Value(Pointer(base.kind, base.base, offset) if -(1 << 31) <= offset < (1 << 31) else None, proof)
            if name == 'INT_ADD' and isinstance(raw[1], Pointer) and isinstance(raw[0], int):
                if op['inputs'][0]['size'] < 8 and raw[0] >= (1 << (op['inputs'][0]['size']*8-1)):
                    return Value(None, proof)
                offset = raw[1].offset + signed(raw[0], op['inputs'][0]['size'] * 8)
                return Value(Pointer(raw[1].kind, raw[1].base, offset) if -(1 << 31) <= offset < (1 << 31) else None, proof)
        if name in ('INT_EQUAL', 'INT_NOTEQUAL'):
            if any(v is None for v in raw): return Value(None, proof)
            if any(isinstance(v, Pointer) for v in raw):
                if raw[0] == 0 or raw[1] == 0:
                    equal = False
                elif isinstance(raw[0], Pointer) and isinstance(raw[1], Pointer) and raw[0].kind == raw[1].kind and raw[0].base == raw[1].base:
                    equal = raw[0].offset == raw[1].offset
                else: return Value(None, proof)
            else: equal = raw[0] == raw[1]
            return Value(int(equal == (name == 'INT_EQUAL')), proof)
        supported = {'INT_SEXT','PTRADD','PTRSUB','INT_ADD','INT_SUB','INT_MULT','INT_AND','INT_OR','INT_XOR',
                     'INT_LEFT','INT_RIGHT','INT_SRIGHT','INT_LESS','INT_LESSEQUAL','INT_SLESS','INT_SLESSEQUAL',
                     'BOOL_NEGATE','BOOL_AND','BOOL_OR','BOOL_XOR','INT_NEGATE','INT_2COMP','SUBPIECE','PIECE'}
        if name not in supported: raise Stop('unsupported_pcode')
        if not all(isinstance(v, int) for v in raw): return Value(None, proof)
        a = raw[0] if raw else 0; b = raw[1] if len(raw) > 1 else 0
        width = op['inputs'][0]['size'] * 8 if raw else bits
        sa, sb = signed(a, width), signed(b, width)
        operations = {
            'INT_ADD': lambda: a+b, 'INT_SUB': lambda: a-b, 'PTRSUB': lambda: a+b,
            'PTRADD': lambda: a+b*raw[2], 'INT_MULT': lambda: a*b,
            'INT_AND': lambda: a&b, 'INT_OR': lambda: a|b, 'INT_XOR': lambda: a^b,
            'INT_LEFT': lambda: a << b if b < width else 0,
            'INT_RIGHT': lambda: a >> b if b < width else 0,
            'INT_SRIGHT': lambda: sa >> min(b, width),
            'INT_LESS': lambda: int(a<b), 'INT_LESSEQUAL': lambda: int(a<=b),
            'INT_SLESS': lambda: int(sa<sb), 'INT_SLESSEQUAL': lambda: int(sa<=sb),
            'BOOL_NEGATE': lambda: int(not a), 'BOOL_AND': lambda: int(bool(a) and bool(b)),
            'BOOL_OR': lambda: int(bool(a) or bool(b)), 'BOOL_XOR': lambda: int(bool(a) != bool(b)),
            'INT_NEGATE': lambda: ~a, 'INT_2COMP': lambda: -a,
            'SUBPIECE': lambda: a >> (8*b), 'PIECE': lambda: (a << (8*op['inputs'][1]['size'])) | b,
        }
        if name not in operations: raise Stop('unsupported_pcode')
        return Value(operations[name](), proof)

    def external(self, state, edge, args, pc):
        contract = self.policy['library_contracts'].get(edge['target_name'])
        if contract is None: self.stop(state, 'unsupported_library_call')
        kind = contract['kind']
        def argument(i):
            if i >= len(args): self.stop(state, 'argument_recovery')
            return args[i]
        if kind in ('malloc', 'calloc'):
            size = argument(0).raw
            if kind == 'calloc':
                other = argument(1).raw
                size = size * other if isinstance(size, int) and isinstance(other, int) else None
            if not isinstance(size, int) or not 0 <= size <= self.policy['max_object_bytes']:
                self.stop(state, 'unknown_allocation_size')
            self.paths += 1
            if self.paths > self.policy['max_paths']: self.stop(state, 'path_limit')
            failed = deepcopy(state)
            state.serial += 1; base = f'object-{state.serial}'
            state.allocations[base] = size
            if kind == 'calloc':
                for i in range(size): state.memory[('heap', base, i)] = Value(0, frozenset({pc}))
            proof = frozenset({pc}).union(*(v.evidence for v in args))
            return [(state, Value(Pointer('heap', base), proof)), (failed, Value(0, proof))]
        if kind == 'free':
            value = argument(0).raw
            if value == 0: return [(state, Value())]
            if not isinstance(value, Pointer) or value.kind != 'heap' or value.offset != 0 or value.base in state.freed:
                self.stop(state, 'nonlive_allocation')
            state.freed.add(value.base)
        elif kind == 'terminate': state.terminated = True
        elif kind == 'formatted_output':
            text = self.string(state, argument(0))
            # Only a fully recovered fixed integer/character/string format without %n or dynamic widths.
            if text is None or re.sub(rb'%%|%[-+ #0]*[0-9]*(?:\.[0-9]+)?(?:ll|l|h|hh|z)?[diuoxXcp]', b'', text[0]).find(b'%') >= 0:
                self.stop(state, 'unsupported_output_format')
            conversions = re.findall(rb'%%|%[-+ #0]*[0-9]*(?:\.[0-9]+)?(?:ll|l|h|hh|z)?[diuoxXcp]', text[0])
            if len(args) < 1 + sum(c != b'%%' for c in conversions): self.stop(state, 'argument_recovery')
        elif kind == 'string_length':
            text = self.string(state, argument(0))
            if text is None: self.stop(state, 'unknown_string_extent')
            return [(state, Value(len(text[0]), text[1] | {pc}))]
        elif kind in ('copy', 'set', 'string_copy'):
            dest, src = argument(0), argument(1)
            if kind == 'string_copy':
                text = self.string(state, src)
                if text is None: self.stop(state, 'unknown_string_extent')
                count = Value(len(text[0]) + 1, text[1])
            else: count = argument(2)
            if not isinstance(count.raw, int) or count.raw > self.policy['max_object_bytes']:
                self.stop(state, 'unknown_write_extent')
            # Copy witnesses require known readable source bytes, not an assumed valid input pointer.
            copied = []
            dp, sp = self.ptr(dest.raw), self.ptr(src.raw)
            if edge['target_name'] == 'memcpy' and dp and sp and dp.kind == sp.kind and dp.base == sp.base \
                    and count.raw and dp.offset < sp.offset + count.raw and sp.offset < dp.offset + count.raw:
                self.stop(state, 'overlapping_memcpy')
            for i in range(count.raw):
                pointer = self.ptr(src.raw)
                if kind != 'set' and pointer and pointer.kind == 'heap' and (pointer.base in state.freed or not 0 <= pointer.offset + i < state.allocations[pointer.base]):
                    self.stop(state, 'unknown_copy_source')
                byte = Value(src.raw & 255, src.evidence) if kind == 'set' and isinstance(src.raw, int) else (
                    self.read(state, Pointer(pointer.kind, pointer.base, pointer.offset + i), 1) if pointer else Value())
                if not isinstance(byte.raw, int): self.stop(state, 'unknown_copy_source')
                copied.append(byte)
            self.check(state, dest, count, pc)
            pointer = self.ptr(dest.raw)
            if pointer:
                for i, byte in enumerate(copied): self.store(state, Pointer(pointer.kind, pointer.base, pointer.offset+i), 1, byte)
            return [(state, dest)]
        elif kind == 'read_only':
            if edge['target_name'] == 'puts' and self.string(state, argument(0)) is None:
                self.stop(state, 'unknown_string_extent')
        else: self.stop(state, 'unsupported_library_call')
        return [(state, Value())]

    def function(self, entry, args, initial, active=()):
        if entry in active: self.stop(initial, 'recursive_call')
        if len(active) >= self.policy['max_call_depth']: self.stop(initial, 'call_depth_limit')
        function = self.functions[entry]
        if len(args) < function['parameter_count']: self.stop(initial, 'argument_recovery')
        blocks = {b['index']: b for b in function['blocks']}
        self.frames += 1; frame = f'frame-{self.frames}'
        queue = [(0, None, 0, initial, {}, frozenset())]; results = []
        while queue:
            bid, predecessor, position, state, env, seen = queue.pop()
            try:
                block = blocks[bid]
                if position == 0:
                    if bid in seen: self.stop(state, 'cyclic_control_flow')
                    seen = seen | {bid}
                if position >= len(block['ops']):
                    if len(block['outgoing']) != 1: self.stop(state, 'incomplete_control_flow')
                    queue.append((block['outgoing'][0], bid, 0, state, env, seen)); continue
                op = block['ops'][position]; pc = op['address']; name = op['opcode']
                self.steps += 1
                if self.steps > self.policy['max_steps']: self.stop(state, 'step_limit')
                if name == 'INDIRECT' and (entry, pc) in self.effect_sites:
                    # A memory-SSA effect marker is not an additional machine write. Effects
                    # are applied by the modeled CALL/STORE at this same public instruction.
                    if op['output'] is not None: env[op['output']['id']] = Value()
                    queue.append((bid, predecessor, position+1, state, env, seen)); continue
                values = []
                for i, node in enumerate(op['inputs']):
                    control_target = i == 0 and name in ('CALL','CALLIND','BRANCH','CBRANCH','RETURN')
                    if node['space'] == 'ram' and not control_target:
                        start = address(node['offset'])
                        if not all(start+j in self.static for j in range(node['size'])):
                            self.stop(state, 'unknown_read_address')
                    values.append(Value() if control_target else self.get(node, env, args, frame, state))
                if name == 'MULTIEQUAL':
                    value = values[block['incoming'].index(predecessor)] if predecessor in block['incoming'] else Value()
                elif name in ('CALL', 'CALLIND'):
                    edge = self.calls.get((entry, pc))
                    if edge is None or name == 'CALLIND': self.stop(state, 'unresolved_call')
                    state.path.add(pc)
                    call_args = [Value(v.raw, v.evidence | {pc}) for v in values[1:]]
                    outcomes = (self.external(state, edge, call_args, pc) if edge['resolution'] == 'external'
                                else self.function(edge['target_entry'], call_args, state, active + (entry,)))
                    for next_state, returned in outcomes:
                        next_env = dict(env)
                        if next_state.terminated or next_state.reasons:
                            results.append((next_state, Value())); continue
                        self.assign(op['output'], returned, next_env, frame, next_state, pc)
                        queue.append((bid, predecessor, position+1, next_state, next_env, seen))
                    continue
                elif name == 'RETURN':
                    results.append((state, values[1] if len(values)>1 else Value())); continue
                elif name in ('CBRANCH', 'BRANCH'):
                    if name == 'CBRANCH':
                        condition = values[1]
                        if not isinstance(condition.raw, int): self.stop(state, 'unresolved_branch')
                        if len(block['outgoing']) != 2: self.stop(state, 'incomplete_control_flow')
                        state.path.update(condition.evidence); state.path.add(pc)
                        target = block['outgoing'][int(bool(condition.raw))]
                    else:
                        if len(block['outgoing']) != 1: self.stop(state, 'incomplete_control_flow')
                        target = block['outgoing'][0]
                    queue.append((target, bid, 0, state, env, seen)); continue
                elif name == 'STORE':
                    self.check(state, values[1], Value(op['inputs'][2]['size']), pc)
                    pointer = self.ptr(values[1].raw)
                    self.store(state, pointer, op['inputs'][2]['size'], values[2]); value = Value()
                elif name == 'LOAD':
                    pointer = self.ptr(values[1].raw); size = op['output']['size']
                    if pointer is None: self.stop(state, 'unknown_read_address')
                    if pointer.kind == 'stack': self.stop(state, 'unknown_stack_bound')
                    if pointer.kind == 'heap' and (pointer.base in state.freed or not 0 <= pointer.offset <= pointer.offset + size <= state.allocations[pointer.base]):
                        self.stop(state, 'unknown_read_address')
                    if pointer.kind == 'static' and not all(pointer.offset+i in self.static for i in range(size)):
                        self.stop(state, 'unknown_read_address')
                    value = self.read(state, pointer, size)
                else: value = self.primitive(op, values)
                value = Value(value.raw, value.evidence | {pc})
                self.assign(op['output'], value, env, frame, state, pc)
                queue.append((bid, predecessor, position+1, state, env, seen))
            except Stop as error:
                state.reasons.add(str(error)); results.append((state, Value()))
        return results

    def run(self):
        if self.uncovered:
            return {'decision': 'uncertain', 'status': 'abstained', 'reason_codes': ['unaccounted_native_write'],
                    'evidence': sorted(self.uncovered, key=address), 'write_checks': [], 'steps': 0, 'paths': 0}
        entry_pc = address(self.bundle['entry_address'])
        entry = next(f['entry'] for f in self.bundle['functions']
                     if any(address(r['start']) <= entry_pc < address(r['end']) for r in f['ranges']))
        if self.bundle['entry_address'] != entry:
            return {'decision': 'uncertain', 'status': 'abstained', 'reason_codes': ['entry_inside_function'],
                    'evidence': [], 'write_checks': [], 'steps': 0, 'paths': 0}
        initial = deepcopy(self.initial)
        try:
            states = [s for s, _ in self.function(entry, [Value()] * self.functions[entry]['parameter_count'], initial)]
        except Stop as error:
            initial.reasons.add(str(error)); states = [initial]
        unique = {canonical(c): c for s in states for c in s.checks}
        checks = [unique[k] for k in sorted(unique)]
        violations = [c for c in checks if c['outcome'] == 'exceeds_allocation']
        reasons = sorted({r for s in states for r in s.reasons})
        if violations:
            decision, status, codes = 'vulnerable_CWE-122', 'classified', ['heap_write_exceeds_allocation']
            proof = {a for c in violations for a in c['evidence']}
        elif reasons:
            decision, status, codes = 'uncertain', 'abstained', reasons
            proof = {c['site'] for c in checks}
        else:
            decision, status, codes = 'not_vulnerable', 'classified', ['all_selected_writes_accounted_for']
            proof = {a for c in checks for a in c['evidence']}
        evidence = sorted(proof, key=address)
        evidence_addresses(self.bundle, evidence)
        return {'decision': decision, 'status': status, 'reason_codes': codes, 'evidence': evidence,
                'write_checks': checks, 'steps': self.steps, 'paths': self.paths + 1}


def analyze(bundle, ir, policy):
    return Engine(bundle, ir, policy).run()
