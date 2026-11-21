#!/usr/bin/env python3
"""Deterministic x86-64 write-bound baseline using exported JSON records only.

The model uses the System V AMD64 register convention and successful malloc/
calloc returns. It follows acyclic paths, models a small instruction subset,
and declines a within-bounds decision after unknown effects or incomplete
control flow. It never uses decompiled array sizes, function names as truth,
neighboring records, or private experiment inputs.

Evidence lists contain key evidence locations, not complete provenance traces.
Method revision 3 retains the live-frame and branch checks from revision 2.
Write-time feasibility preserves earlier proven writes when later branches are
unknown, while speculative writes cannot prove overflow. This is a restricted
heuristic interpreter, not a generally sound proof system.
Some instructions establishing addresses, allocation arguments, and copy
lengths are omitted. Decompiler status and text do not determine eligibility
or influence classification when a valid instruction export is present.
"""

import argparse
import copy
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import sys
import tempfile


DECISIONS = {"vulnerable_CWE-121", "vulnerable_CWE-122", "not_vulnerable", "uncertain"}
RULE_DECISIONS = {
    "heap_write_exceeds_allocation": "vulnerable_CWE-122",
    "heap_write_within_allocation": "not_vulnerable",
    "stack_write_overlaps_saved_frame_state": "vulnerable_CWE-121",
    "unresolved_copy_call": "uncertain",
    "insufficient_evidence": "uncertain",
}
COPY_CALLS = {"memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat", "strncat"}
READ_ONLY_CALLS = {"puts", "putchar", "fputs", "strcmp", "strncmp", "memcmp"}
NO_RETURN_CALLS = {"exit", "_exit", "abort", "__stack_chk_fail"}
ARGUMENTS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
CALLER_SAVED = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}
WIDTHS = {"byte": 1, "word": 2, "dword": 4, "qword": 8,
          "xmmword": 16, "oword": 16, "ymmword": 32, "zmmword": 64}
MAX_BYTES = 4096
MAX_STEPS = 8192
MAX_PATHS = 128
ADDRESS = re.compile(r"0x(?:0|[1-9a-f][0-9a-f]{0,15})\Z")
REGISTERS = {}
for names in (("rax", "eax", "ax", "al", "ah"), ("rbx", "ebx", "bx", "bl", "bh"),
              ("rcx", "ecx", "cx", "cl", "ch"), ("rdx", "edx", "dx", "dl", "dh"),
              ("rsi", "esi", "si", "sil"), ("rdi", "edi", "di", "dil"),
              ("rsp", "esp", "sp", "spl"), ("rbp", "ebp", "bp", "bpl")):
    for name, bits in zip(names, (64, 32, 16, 8, 8)):
        REGISTERS[name] = (names[0], bits, 8 if name in ("ah", "bh", "ch", "dh") else 0)
for index in range(8, 16):
    for suffix, bits in (("", 64), ("d", 32), ("w", 16), ("b", 8)):
        REGISTERS[f"r{index}{suffix}"] = (f"r{index}", bits, 0)
for prefix, bits in (("xmm", 128), ("ymm", 256), ("zmm", 512)):
    for index in range(32):
        REGISTERS[f"{prefix}{index}"] = (f"v{index}", bits, 0)


@dataclass(frozen=True)
class Pointer:
    kind: str
    base: str
    offset: int = 0


@dataclass
class State:
    registers: dict = field(default_factory=lambda: {"rsp": Pointer("stack", "frame")})
    slots: dict = field(default_factory=dict)
    memory: dict = field(default_factory=dict)
    allocations: dict = field(default_factory=dict)
    stack_writes: list = field(default_factory=list)
    stack_overlaps: list = field(default_factory=list)
    validated_stack_overlaps: list = field(default_factory=list)
    saved_frame_slots: list = field(default_factory=lambda: [(0, 8, "return-address slot")])
    frame_evidence: set = field(default_factory=set)
    unresolved: set = field(default_factory=set)
    calls_seen: set = field(default_factory=set)
    incomplete: bool = False
    zero: object = None
    comparison: object = None
    path_validated: bool = True
    condition_key: object = None
    branch_facts: dict = field(default_factory=dict)
    register_versions: dict = field(default_factory=dict)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse_integer(text):
    """Return an integer or None; no expression evaluation or C parsing."""
    text = text.strip().lower()
    if re.fullmatch(r"[+-]?0x[0-9a-f]+", text):
        return int(text, 16)
    if re.fullmatch(r"[+-]?[0-9]+", text):
        return int(text, 10)
    return None


def operands_of(instruction):
    return [operand.strip().lower() for operand in instruction["operands"].split(",")
            if operand.strip()]


def register_value(state, name):
    register = REGISTERS.get(name)
    if register is None:
        return None
    base, bits, shift = register
    value = state.registers.get(base)
    if isinstance(value, int):
        return (value >> shift) & ((1 << bits) - 1)
    return value if bits == 64 else None


def set_register(state, name, value):
    base, bits, shift = REGISTERS[name]
    state.register_versions[base] = state.register_versions.get(base, 0) + 1
    if isinstance(value, Pointer) and bits != 64:
        value = None
    if isinstance(value, int):
        value &= (1 << bits) - 1
    if bits < 32:
        previous = state.registers.get(base)
        if isinstance(previous, int) and isinstance(value, int):
            mask = ((1 << bits) - 1) << shift
            value = (previous & ~mask) | (value << shift)
        else:
            value = None
    # A 32-bit GPR write zero-extends; a narrow vector write invalidates wider
    # aliases rather than assuming their unmodified upper lanes are zero.
    if base.startswith("v") and bits != 512:
        value = None
    state.registers[base] = value


def add_value(value, amount):
    if isinstance(value, Pointer) and isinstance(amount, int):
        # Register offsets use 64-bit two's-complement arithmetic.
        amount = ((amount & ((1 << 64) - 1)) ^ (1 << 63)) - (1 << 63)
        return Pointer(value.kind, value.base, value.offset + amount)
    if isinstance(value, int) and isinstance(amount, int):
        return value + amount
    return None


def memory_address(state, operand):
    match = re.search(r"\[([^\]]+)\]", operand)
    if not match:
        return None
    expression = re.sub(r"\s+", "", match[1]).replace("+-", "-")
    # Ghidra spells negative displacements as [RBP + -0x8]. Scaled integer
    # indexes are accepted only when their complete values are known.
    if not re.fullmatch(r"[a-z0-9x*+\-]+", expression):
        return None
    pointer, constant = None, 0
    for term in re.findall(r"[+-]?[^+-]+", expression):
        sign = -1 if term.startswith("-") else 1
        term = term.lstrip("+-")
        factors = term.split("*")
        if len(factors) > 2:
            return None
        value = register_value(state, factors[0]) if factors[0] in REGISTERS else parse_integer(factors[0])
        if len(factors) == 2:
            scale = parse_integer(factors[1])
            value = value * scale if isinstance(value, int) and scale in (1, 2, 4, 8) else None
        if isinstance(value, Pointer) and sign == 1 and pointer is None:
            pointer = value
        elif isinstance(value, int):
            constant += sign * value
        else:
            return None
    return add_value(pointer, constant) if pointer is not None else constant


def memory_width(mnemonic, operands):
    if mnemonic.lower() in ("movd", "movq"):
        return 4 if mnemonic.lower() == "movd" else 8
    parts = [part.strip().lower() for part in operands.split(",")]
    for part in parts:
        if "[" in part:
            match = re.match(r"(byte|word|dword|qword|xmmword|oword|ymmword|zmmword)\s+(?:ptr\s+)?\[", part)
            if match:
                return WIDTHS[match[1]]
    for part in parts:
        if part in REGISTERS:
            return REGISTERS[part][1] // 8
    return None


def read_operand(state, operand, width=None):
    if operand in REGISTERS:
        return register_value(state, operand)
    if "[" not in operand:
        return parse_integer(operand)
    pointer = memory_address(state, operand)
    if not isinstance(pointer, Pointer) or width is None:
        return None
    key = (pointer.kind, pointer.base, pointer.offset, width)
    if key in state.slots:
        return state.slots[key]
    data = [state.memory.get((pointer.kind, pointer.base, pointer.offset + index))
            for index in range(width)]
    return sum(byte << (8 * index) for index, byte in enumerate(data)) if all(
        isinstance(byte, int) for byte in data) else None


def invalidate_memory(state, pointer=None):
    for mapping in (state.memory, state.slots):
        for key in list(mapping):
            if pointer is None or key[:2] == (pointer.kind, pointer.base):
                del mapping[key]
    if pointer is not None and pointer.kind == "heap":
        state.allocations[pointer.base]["zeroed"] = False
    elif pointer is None:
        for allocation in state.allocations.values():
            allocation["zeroed"] = False


def write_memory(state, pointer, width, value, location, record=True):
    if not isinstance(pointer, Pointer) or not isinstance(width, int) or width < 0:
        state.incomplete = True
        invalidate_memory(state, pointer if isinstance(pointer, Pointer) else None)
        return
    if width == 0:
        return
    start, end = pointer.offset, pointer.offset + width
    if record:
        if pointer.kind == "heap":
            allocation = state.allocations[pointer.base]
            if allocation["freed"]:
                state.incomplete = True
            else:
                allocation["writes"].append((start, end, location))
                if state.path_validated:
                    allocation["validated_writes"].append((start, end, location))
        else:
            state.stack_writes.append((start, end, location))
            # Capture live protection at write time: later pops must neither
            # invent collisions with retired slots nor erase real overwrites.
            overlaps = [
                (start, end, location, low, high, slot)
                for low, high, slot in state.saved_frame_slots if start < high and low < end]
            state.stack_overlaps.extend(overlaps)
            if state.path_validated:
                state.validated_stack_overlaps.extend(overlaps)
    for key in list(state.slots):
        if key[:2] == (pointer.kind, pointer.base) and key[2] < end and start < key[2] + key[3]:
            del state.slots[key]
    for key in list(state.memory):
        if key[:2] == (pointer.kind, pointer.base) and start <= key[2] < end:
            del state.memory[key]
    if width <= MAX_BYTES:
        if isinstance(value, int):
            value &= (1 << (width * 8)) - 1
        state.slots[(pointer.kind, pointer.base, start, width)] = value
        for index in range(width):
            state.memory[(pointer.kind, pointer.base, start + index)] = (
                (value >> (index * 8)) & 255 if isinstance(value, int) else None)


def string_length(state, pointer):
    if not isinstance(pointer, Pointer):
        return None
    for length in range(MAX_BYTES):
        key = (pointer.kind, pointer.base, pointer.offset + length)
        byte = state.memory.get(key)
        if key not in state.memory and pointer.kind == "heap":
            allocation = state.allocations[pointer.base]
            if allocation["zeroed"] and not allocation["freed"] and allocation["size"] is not None \
                    and 0 <= pointer.offset + length < allocation["size"]:
                byte = 0
        if byte is None:
            return None
        if byte == 0:
            return length
    return None


def call_name(target):
    return target.rsplit("::", 1)[-1].split("@", 1)[0].lower()


def handle_call(state, target, location):
    """Return True for a known non-returning call."""
    name = call_name(target)
    state.calls_seen.add(location)
    arguments = [register_value(state, register) for register in ARGUMENTS]
    result = None
    if name in ("malloc", "calloc"):
        size = arguments[0]
        if name == "calloc":
            size = size * arguments[1] if isinstance(size, int) and isinstance(arguments[1], int) else None
        if not isinstance(size, int) or not 0 <= size < 1 << 64:
            size = None
        state.allocations[location] = {
            "size": size, "writes": [], "validated_writes": [], "complete": True, "freed": False,
            "zeroed": name == "calloc",
        }
        result = Pointer("heap", location)
    elif name == "strlen":
        result = string_length(state, arguments[0])
    elif name in COPY_CALLS:
        destination, source, count = arguments[:3]
        if name == "strcpy":
            length = string_length(state, source)
            count = None if length is None else length + 1
        elif name in ("strcat", "strncat"):
            before, length = string_length(state, destination), string_length(state, source)
            if name == "strncat" and count == 0:
                length = 0
            elif name == "strncat":
                length = min(length, count) if isinstance(length, int) and isinstance(count, int) else None
            count = None if length is None else length + 1
            destination = add_value(destination, before) if before is not None else None
        if isinstance(destination, Pointer) and isinstance(count, int) and count >= 0:
            write_memory(state, destination, count, None, location)
            if destination.kind == "stack":
                state.unresolved.add(location)  # Frame extent is not an object bound.
            if name == "memset" and isinstance(source, int) and count <= MAX_BYTES:
                fill = sum((source & 255) << (index * 8) for index in range(count))
                write_memory(state, destination, count, fill, location, record=False)
        else:
            state.unresolved.add(location)
            original = arguments[0]
            if isinstance(original, Pointer):
                invalidate_memory(state, original)
                if original.kind == "heap":
                    state.allocations[original.base]["complete"] = False
            else:
                state.incomplete = True
        result = arguments[0]
    elif name == "free":
        pointer = arguments[0]
        if isinstance(pointer, Pointer) and pointer.kind == "heap" and pointer.offset == 0:
            state.allocations[pointer.base]["freed"] = True
            invalidate_memory(state, pointer)
        elif pointer != 0:
            state.incomplete = True
    elif name not in READ_ONLY_CALLS | NO_RETURN_CALLS:
        # An unknown callee may write, free, or retain pointers. Do not grant
        # it a read-only contract based on a neutral helper's developer name.
        state.incomplete = True
        invalidate_memory(state)
        for allocation in state.allocations.values():
            allocation["complete"] = False
            allocation["zeroed"] = False
        for key, value in list(state.registers.items()):
            if isinstance(value, Pointer) and value.kind == "heap":
                set_register(state, key, None)
        if any(copy_name in name for copy_name in COPY_CALLS):
            state.unresolved.add(location)
    for register in CALLER_SAVED:
        set_register(state, register, None)
    for index in range(32):
        state.registers[f"v{index}"] = None
    set_register(state, "rax", result)
    state.comparison, state.zero = None, None
    state.condition_key = None
    return name in NO_RETURN_CALLS


def step_instruction(state, instruction):
    """Apply one non-control-flow instruction; False means unsupported effects."""
    mnemonic = instruction["mnemonic"].lower()
    operands = operands_of(instruction)
    location = instruction["address"]
    if mnemonic in ("nop", "endbr64"):
        return True
    if mnemonic == "push" and len(operands) == 1:
        if operands[0] in REGISTERS and REGISTERS[operands[0]][1] != 64:
            return False
        pointer = add_value(register_value(state, "rsp"), -8)
        if not isinstance(pointer, Pointer) or pointer.kind != "stack":
            return False
        write_memory(state, pointer, 8, read_operand(state, operands[0], 8), location, record=False)
        set_register(state, "rsp", pointer)
        if operands[0] == "rbp":
            state.saved_frame_slots.append((pointer.offset, pointer.offset + 8, "saved frame-pointer slot"))
            state.frame_evidence.add(location)
        return True
    if mnemonic in ("pop", "leave"):
        if mnemonic == "leave":
            set_register(state, "rsp", register_value(state, "rbp"))
            operands = ["rbp"]
        if len(operands) != 1 or operands[0] not in REGISTERS or operands[0] == "rsp" \
                or REGISTERS[operands[0]][1] != 64:
            return False
        pointer = register_value(state, "rsp")
        value = None if not isinstance(pointer, Pointer) else state.slots.get(
            (pointer.kind, pointer.base, pointer.offset, 8))
        if isinstance(pointer, Pointer) and pointer.kind == "stack":
            state.saved_frame_slots = [slot for slot in state.saved_frame_slots
                                       if not (slot[0] == pointer.offset and slot[1] == pointer.offset + 8
                                               and slot[2] == "saved frame-pointer slot")]
        set_register(state, operands[0], value)
        set_register(state, "rsp", add_value(pointer, 8))
        return True
    if len(operands) != 2:
        return False
    destination, source = operands
    width = memory_width(mnemonic, instruction["operands"])
    if mnemonic in ("cmp", "test"):
        left, right = read_operand(state, destination, width), read_operand(state, source, width)
        state.comparison, state.zero = None, None
        # Only register/immediate predicates are reusable; memory may change.
        state.condition_key = None
        if all(operand in REGISTERS or parse_integer(operand) is not None for operand in operands):
            versions = tuple((REGISTERS[operand][0], state.register_versions.get(REGISTERS[operand][0], 0))
                             for operand in operands if operand in REGISTERS)
            state.condition_key = (mnemonic, tuple(operands), versions)
        if mnemonic == "test" and destination == source and isinstance(left, Pointer):
            state.zero = False  # Successful allocation or frame address.
        elif mnemonic == "test" and (left == 0 or right == 0):
            state.zero = True
        elif mnemonic == "cmp" and isinstance(left, Pointer) and right == 0:
            state.zero = False
        elif isinstance(left, int) and isinstance(right, int):
            bits = (width or 8) * 8
            left, right = left & ((1 << bits) - 1), right & ((1 << bits) - 1)
            state.zero = (left == right) if mnemonic == "cmp" else (left & right) == 0
            if mnemonic == "cmp":
                state.comparison = (left, right, bits)
        if state.zero is None and state.condition_key in state.branch_facts:
            state.zero = state.branch_facts[state.condition_key]
        return True
    if mnemonic == "lea" and destination in REGISTERS:
        set_register(state, destination, memory_address(state, source))
        return True
    if mnemonic.startswith(("mov", "vmov")):
        if mnemonic not in ("mov", "movabs", "movzx", "movsx", "movsxd", "movd", "movq",
                             "movaps", "movups", "movdqa", "movdqu", "vmovaps", "vmovups",
                             "vmovdqa", "vmovdqu", "vmovdqa32", "vmovdqa64", "vmovdqu8",
                             "vmovdqu16", "vmovdqu32", "vmovdqu64"):
            return False
        value = read_operand(state, source, width)
        if mnemonic in ("movsx", "movsxd") and isinstance(value, int):
            source_bits = REGISTERS[source][1] if source in REGISTERS else (width or 4) * 8
            value = (value ^ (1 << (source_bits - 1))) - (1 << (source_bits - 1))
        if destination in REGISTERS:
            set_register(state, destination, value)
            if destination == "rbp" and source == "rsp":
                state.frame_evidence.add(location)
        elif "[" in destination:
            write_memory(state, memory_address(state, destination), width, value, location)
        else:
            return False
        return True
    if destination not in REGISTERS:
        return False
    left, right = register_value(state, destination), read_operand(state, source, width)
    previous_flags = state.zero, state.comparison, state.condition_key
    state.zero, state.comparison = None, None
    state.condition_key = None
    if mnemonic in ("xor", "sub") and destination == source:
        value = 0
    elif mnemonic in ("add", "sub"):
        value = add_value(left, right if mnemonic == "add" else -right) if isinstance(right, int) else None
    elif mnemonic in ("and", "or", "xor", "imul", "shl", "sal", "shr", "sar"):
        value = 0 if mnemonic == "and" and right == 0 else None
        if isinstance(left, int) and isinstance(right, int):
            bits = REGISTERS[destination][1]
            shift = right & (63 if bits == 64 else 31)
            signed = (left ^ (1 << (bits - 1))) - (1 << (bits - 1))
            value = {"and": lambda: left & right, "or": lambda: left | right,
                     "xor": lambda: left ^ right, "imul": lambda: left * right,
                     "shl": lambda: left << shift, "sal": lambda: left << shift,
                     "shr": lambda: left >> shift, "sar": lambda: signed >> shift}[mnemonic]()
    else:
        return False
    set_register(state, destination, value)
    state.zero = (value & ((1 << REGISTERS[destination][1]) - 1)) == 0 if isinstance(value, int) else None
    if mnemonic == "imul":
        state.zero = None  # IMUL leaves ZF undefined.
    if mnemonic in ("shl", "sal", "shr", "sar") and isinstance(right, int) \
            and (right & (63 if REGISTERS[destination][1] == 64 else 31)) == 0:
        state.zero, state.comparison, state.condition_key = previous_flags
    return True


def branch_decision(state, mnemonic):
    if mnemonic in ("je", "jz", "jne", "jnz"):
        return state.zero if mnemonic in ("je", "jz") else (
            None if state.zero is None else not state.zero)
    if state.comparison is None:
        return None
    left, right, bits = state.comparison
    signed_left = (left ^ (1 << (bits - 1))) - (1 << (bits - 1))
    signed_right = (right ^ (1 << (bits - 1))) - (1 << (bits - 1))
    comparisons = {
        "ja": left > right, "jae": left >= right, "jb": left < right, "jbe": left <= right,
        "jg": signed_left > signed_right, "jge": signed_left >= signed_right,
        "jl": signed_left < signed_right, "jle": signed_left <= signed_right,
    }
    return comparisons.get(mnemonic)


def follow_paths(record):
    instructions = record["instructions"]
    indexes = {int(item["address"], 16): index for index, item in enumerate(instructions)}
    targets = {}
    for call in record["calls"]:
        targets.setdefault(call["address"], []).append(call["target"])
    pending, finished, steps = [(0, State(), frozenset())], [], 0
    while pending:
        index, state, seen = pending.pop()
        while 0 <= index < len(instructions):
            steps += 1
            if index in seen or steps > MAX_STEPS or len(pending) + len(finished) >= MAX_PATHS:
                state.incomplete = True
                break
            seen = seen | {index}
            instruction = instructions[index]
            mnemonic = instruction["mnemonic"].lower()
            location = instruction["address"]
            names = targets.get(location, [])
            name = names[0] if len(names) == 1 else ""
            if mnemonic in ("ret", "retq"):
                break
            if mnemonic in ("call", "callq"):
                if handle_call(state, name, location):
                    break
            elif mnemonic.startswith("j"):
                destination = parse_integer(instruction["operands"])
                target = indexes.get(destination)
                if mnemonic == "jmp":
                    if target is None:
                        handle_call(state, name, location)
                        break
                    index = target
                    continue
                decision = branch_decision(state, mnemonic)
                if decision is None:
                    # Forking is exploration, not a feasibility proof. Facts
                    # prune repeated contradictory tests; more complex branch
                    # relations remain unvalidated and cannot prove a finding.
                    state.path_validated = False
                if decision is not False:
                    branch = copy.deepcopy(state)
                    if decision is None and state.condition_key is not None and mnemonic in ("je", "jz", "jne", "jnz"):
                        branch.branch_facts[state.condition_key] = mnemonic in ("je", "jz")
                        state.branch_facts[state.condition_key] = mnemonic in ("jne", "jnz")
                    if target is None:
                        branch.incomplete = True
                        finished.append(branch)
                    else:
                        pending.append((target, branch, seen))
                if decision is True:
                    state = None
                    break
            elif not step_instruction(state, instruction):
                state.incomplete = True
                break
            index += 1
        else:
            state.incomplete = True  # Body ended without an understood transfer.
        if state is not None:
            finished.append(state)
    return finished


def merge_intervals(intervals):
    result = []
    for start, end in sorted(intervals):
        require(type(start) is int and type(end) is int and start <= end, "Invalid byte interval")
        if start == end:
            continue
        if result and start <= result[-1][1]:
            result[-1] = (result[-1][0], max(result[-1][1], end))
        else:
            result.append((start, end))
    return result


def finding(rule, evidence, summary):
    """Export key evidence locations; this is not a full provenance trace."""
    return {"decision": RULE_DECISIONS[rule], "rule": rule,
            "evidence": sorted(set(evidence), key=lambda value: int(value, 16)), "summary": summary}


def stack_overlap(state):
    return state.stack_overlaps


def classify_heap(states):
    evidence, saw_write = [], False
    for state in states:
        for site, allocation in sorted(state.allocations.items()):
            intervals = merge_intervals([(start, end) for start, end, _ in allocation["writes"]])
            # A later unknown branch cannot invalidate writes already reached
            # along a validated prefix. Speculative writes never prove overflow.
            validated = allocation["validated_writes"]
            validated_intervals = merge_intervals([(start, end) for start, end, _ in validated])
            size = allocation["size"]
            if size is not None and any(start < 0 or end > size for start, end in validated_intervals):
                description = ", ".join(f"[{start}, {end})" for start, end in validated_intervals)
                return finding("heap_write_exceeds_allocation", [site] +
                               [location for _, _, location in validated],
                               f"Heap write intervals {description} exceed the {size}-byte allocation.")
            if intervals:
                saw_write = True
                evidence += [site] + [location for _, _, location in allocation["writes"]]
    if saw_write and all(state.path_validated and not state.incomplete and not state.unresolved and not stack_overlap(state)
                        and all(allocation["size"] is not None and allocation["complete"]
                                for allocation in state.allocations.values()) for state in states):
        return finding("heap_write_within_allocation", evidence,
                       "All modeled heap writes lie within their constant allocations; all paths and write effects are resolved.")
    return None


def classify_stack(states):
    for state in states:
        overlaps = state.validated_stack_overlaps
        if overlaps:
            start, end, location, low, high, slot = overlaps[0]
            count = min(end, high) - max(start, low)
            extent = "one byte" if count == 1 else f"{count} bytes"
            return finding("stack_write_overlaps_saved_frame_state", [location, *state.frame_evidence],
                           f"Stack write overlaps {extent} of the {slot}.")
    return None


def analyze_record(record):
    states = follow_paths(record)
    result = classify_heap(states) or classify_stack(states)
    if result is not None:
        return result
    unresolved = {location for state in states for location in state.unresolved}
    if any(state.incomplete for state in states):
        seen = {location for state in states for location in state.calls_seen}
        unresolved.update(call["address"] for call in record["calls"] if call_name(call["target"]) in COPY_CALLS
                          and call["address"] not in seen)
    if unresolved:
        return finding("unresolved_copy_call", unresolved,
                       "A copy call is visible, but its complete write extent or destination capacity cannot be proved.")
    evidence = {location for state in states for _, _, location in state.stack_writes}
    evidence.update(site for state in states for site in state.allocations)
    evidence.update(location for state in states for allocation in state.allocations.values()
                    for _, _, location in allocation["writes"])
    if any(state.incomplete or not state.path_validated for state in states):
        summary = "Unknown call effects, unsupported instructions, or incomplete control flow prevent a complete bounds proof."
    elif any(state.allocations for state in states):
        summary = "The write extent is visible, but a constant allocation size was not recovered."
    elif any(state.stack_writes for state in states):
        summary = "Frame-relative stores are visible, but the destination's source-level stack capacity is not recoverable."
    else:
        summary = "No complete, sound allocation-to-write relationship was recovered by the supported instruction model."
    return finding("insufficient_evidence", evidence, summary)


def validate_record(record):
    def keys(value, expected):
        require(isinstance(value, dict) and set(value) == expected, "Invalid record keys")

    def addr(value):
        require(isinstance(value, str) and ADDRESS.fullmatch(value), "Invalid instruction address")
        return int(value, 16)

    required = {"schema_version", "architecture", "function", "instructions", "calls", "decompilation"}
    require(isinstance(record, dict) and required <= set(record) and set(record) <= required | {"error"},
            "Invalid record keys")
    require(type(record["schema_version"]) is int and record["schema_version"] == 1
            and record["architecture"] == "x86-64", "Unsupported record schema or architecture")
    keys(record["function"], {"name", "entry", "end"})
    require(isinstance(record["function"]["name"], str), "Invalid function name")
    entry, end = addr(record["function"]["entry"]), addr(record["function"]["end"])
    require(entry < end, "Invalid function bounds")
    keys(record["decompilation"], {"status", "text"})
    require(isinstance(record["decompilation"]["status"], str)
            and record["decompilation"]["status"] in {"ok", "error", "timeout", "cancelled", "not_run"}
            and isinstance(record["decompilation"]["text"], str), "Invalid decompilation metadata")
    if "error" in record:
        keys(record["error"], {"code", "message"})
        require(record["decompilation"]["status"] != "ok"
                and all(isinstance(value, str) for value in record["error"].values()),
                "Invalid structured error metadata")
    require(isinstance(record["instructions"], list) and record["instructions"], "Empty instructions")
    addresses = []
    for instruction in record["instructions"]:
        keys(instruction, {"address", "mnemonic", "operands"})
        value = addr(instruction["address"])
        require(entry <= value < end and isinstance(instruction["mnemonic"], str)
                and instruction["mnemonic"] and isinstance(instruction["operands"], str), "Invalid instruction")
        addresses.append(value)
    require(addresses == sorted(set(addresses)) and addresses[0] == entry, "Instructions are not entry-first and ordered")
    require(isinstance(record["calls"], list), "Invalid calls")
    call_addresses = []
    for call in record["calls"]:
        keys(call, {"address", "target"})
        value = addr(call["address"])
        require(value in addresses and isinstance(call["target"], str), "Invalid call")
        call_addresses.append(value)
    require(call_addresses == sorted(call_addresses), "Calls are not address ordered")


def parse_record(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    def invalid(value):
        raise ValueError(f"Nonstandard JSON value: {value}")

    with path.open(encoding="utf-8") as stream:
        record = json.load(stream, object_pairs_hook=unique, parse_constant=invalid)
    validate_record(record)
    return record


def validate_prediction(prediction):
    require(set(prediction) == {"observation_id", "decision", "rule", "evidence", "summary"}, "Invalid prediction keys")
    require(isinstance(prediction["observation_id"], str) and re.fullmatch(r"r\d{4}", prediction["observation_id"]),
            "Invalid observation ID")
    require(prediction["decision"] in DECISIONS and
            RULE_DECISIONS.get(prediction["rule"]) == prediction["decision"], "Invalid decision or rule")
    require(isinstance(prediction["evidence"], list) and all(
        isinstance(value, str) and ADDRESS.fullmatch(value) for value in prediction["evidence"]), "Invalid evidence")
    require(prediction["evidence"] == sorted(set(prediction["evidence"]), key=lambda value: int(value, 16)),
            "Evidence is not unique and address ordered")
    require(isinstance(prediction["summary"], str) and prediction["summary"].strip(), "Missing prediction summary")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    require(args.inputs.is_dir(), f"Record directory not found: {args.inputs}")
    paths = sorted(args.inputs.glob("*.json"))
    require(paths, f"No JSON records found in {args.inputs}")
    predictions = []
    for path in paths:
        require(not path.is_symlink() and re.fullmatch(r"r\d{4}\.json", path.name), f"Invalid record filename: {path.name}")
        require(path.resolve() != args.output.resolve(), "Output would overwrite an input record")
        try:
            record = parse_record(path)
            prediction = {"observation_id": path.stem, **analyze_record(record)}
            validate_prediction(prediction)
            require(set(prediction["evidence"]) <= {item["address"] for item in record["instructions"]},
                    "Prediction evidence is outside the exported instructions")
        except ValueError as error:
            raise ValueError(f"{path.name}: {error}") from error
        predictions.append(prediction)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=args.output.parent, delete=False) as stream:
            temporary = Path(stream.name)
            for prediction in predictions:
                stream.write(json.dumps(prediction, ensure_ascii=False, allow_nan=False) + "\n")
        temporary.replace(args.output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    print(f"Wrote {len(predictions)} predictions to {args.output}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        print(f"Baseline failed: {error}", file=sys.stderr)
        sys.exit(1)
