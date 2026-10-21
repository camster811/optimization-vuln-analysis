"""Public-only bundle validation, canonicalization, budgets and evidence references."""
from copy import deepcopy
import json
import re
import struct

from jsonschema import Draft202012Validator

from .inventory import ROOT, read_json, require
from .sanitize import scan_metadata


PUBLIC_ASSUMPTIONS = [
    'One invocation of the localized entry; no concurrent mutation or library interposition.',
    'System V x86-64 ABI and ordinary libc allocation, string and output semantics.',
    'Decompiler types and referenced-data windows are uncertain recovery, not proven object bounds.',
]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False) + '\n'


def address(value):
    require(isinstance(value, str) and re.fullmatch(r'0x(?:0|[1-9a-f][0-9a-f]{0,15})', value),
            'Invalid canonical address')
    return int(value, 16)


def policy_check(policy):
    require(policy['schema_version'] == 1 and policy['bundle_schema_version'] == 2
            and policy['policy_id'] == 'entry-closure-v1', 'Unknown context policy')
    for name in ('analysis_timeout_seconds', 'decompiler_timeout_seconds', 'process_timeout_seconds',
                 'max_functions', 'max_instructions', 'max_data_bytes', 'max_data_bytes_per_reference',
                 'unknown_data_window_bytes', 'max_bundle_utf8_bytes', 'max_token_upper_bound'):
        require(type(policy[name]) is int and 0 < policy[name] <= 2147483647, 'Invalid context limit')
    require(policy['token_accounting'] == 'utf8_bytes_upper_bound'
            and policy['allow_assembly_only'] is False
            and policy['unresolved_transfers'] == 'extraction_unavailable'
            and policy['data_policy'] == 'direct_references_recovered_extent_or_explicit_unknown_window'
            and policy['external_policy'] == 'exclude_external_bodies_and_linkage_thunks'
            and policy['ordering'] == 'ascending_function_entry_instruction_address_transfer_site_data_address'
            and policy['language'] == 'x86:LE:64:default' and policy['compiler_spec'] == 'gcc',
            'Unsupported context rule; amend and implement the policy explicitly')
    require(policy['external_debug_information'] == 'disabled' and policy['autoload_libraries'] is False,
            'Public extraction must not restore external debug information or library bodies')
    return policy


def empty_bundle(entry, reason):
    return {'schema_version': 2, 'architecture': 'x86-64', 'policy_id': 'entry-closure-v1',
            'assumptions': list(PUBLIC_ASSUMPTIONS),
            'entry_address': entry, 'status': 'extraction_unavailable', 'functions': [], 'calls': [],
            'data': [], 'unresolved_transfers': [],
            'completeness': {'traversal': 'incomplete', 'data': 'incomplete',
                             'decompilation': 'incomplete', 'external_bodies': 'excluded',
                             'localization': 'private_entry_address',
                             'omissions': [{'reason': reason, 'address': None}]}}


def normalize(raw):
    result = deepcopy(raw)
    result['functions'].sort(key=lambda f: address(f['entry']))
    for function in result['functions']:
        function['ranges'].sort(key=lambda r: address(r['start']))
        function['instructions'].sort(key=lambda i: address(i['address']))
    for field in ('calls', 'unresolved_transfers'):
        result[field].sort(key=lambda c: (address(c['site']), canonical(c)))
    result['data'].sort(key=lambda d: address(d['address']))
    for item in result['data']:
        item['references'].sort(key=address)
    result['completeness']['omissions'].sort(key=canonical)
    return result


def loaded_bytes(binary, start, size):
    """Read bytes from the public ELF load image, including zero-initialized PT_LOAD tails."""
    raw = binary.read_bytes()
    require(raw[:6] == b'\x7fELF\x02\x01', 'Expected ELF64 little endian')
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', raw)
    require(header[2] == 62 and header[9] == 56, 'Expected x86-64 program headers')
    for index in range(header[10]):
        kind, _, offset, virtual, _, file_size, memory_size, _ = struct.unpack_from(
            '<IIQQQQQQ', raw, header[5] + index * header[9])
        if kind == 1 and virtual <= start < start + size <= virtual + memory_size:
            relative = start - virtual
            count = max(0, min(size, file_size - relative))
            require(offset + relative + count <= len(raw) or count == 0, 'Truncated ELF load image')
            return raw[offset + relative:offset + relative + count] + b'\0' * (size - count)
    raise ValueError('Evidence outside public ELF load image')


def string_prefix(raw):
    end = raw.find(b'\0')
    if end <= 0 or any(b not in (9, 10, 13) and not 32 <= b <= 126 for b in raw[:end]):
        return None
    return raw[:end].decode('ascii')


def validate(bundle, binary=None, schema=None):
    Draft202012Validator(schema or read_json(ROOT / 'schemas/bundle-v2.json')).validate(bundle)
    scan_metadata(canonical(bundle))
    # Also reject treatment/path clues not covered by the source metadata scanner.
    require(not re.search(r'(?i)(?<![a-z0-9])(?:O[0-3]|retained|stripped)(?![a-z0-9])|'
                          r'/home/|/experiment/|corpus/|\.c(?:[\s"\']|$)', canonical(bundle)),
            'Private treatment/path metadata in public bundle')
    require(bundle == normalize(bundle), 'Noncanonical bundle ordering')
    functions, instructions = {}, {}
    for function in bundle['functions']:
        entry = address(function['entry'])
        require(entry not in functions and bool(function['name']), 'Duplicate/unnamed function')
        functions[entry] = function
        ranges = [(address(r['start']), address(r['end'])) for r in function['ranges']]
        require(ranges and all(start < end for start, end in ranges)
                and all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])), 'Invalid function ranges')
        require(any(start <= entry < end for start, end in ranges), 'Function entry outside body')
        previous_end = 0
        for ins in function['instructions']:
            pc = address(ins['address'])
            require(pc not in instructions and previous_end <= pc
                    and any(start <= pc < pc + ins['size'] <= end for start, end in ranges),
                    'Instruction overlaps or is outside function')
            previous_end = pc + ins['size']
            require(len(bytes.fromhex(ins['bytes'])) == ins['size'], 'Instruction size differs')
            if binary is not None:
                require(loaded_bytes(binary, pc, ins['size']).hex() == ins['bytes'],
                        'Instruction bytes differ from public binary')
            instructions[pc] = entry
        status = function['decompilation']['status']
        text = function['decompilation']['text']
        require(bool(text.strip()) == (status == 'ok'), 'Decompilation status/text differs')
    edge_keys = set()
    for edge in bundle['calls']:
        key = (edge['caller'], edge['site'], edge['target_address'], edge['kind'])
        require(key not in edge_keys, 'Duplicate call edge')
        edge_keys.add(key)
        require(instructions.get(address(edge['site'])) == address(edge['caller']), 'Call site outside caller')
        if edge['resolution'] == 'application':
            target = address(edge['target_entry'])
            if target in functions:
                require(any(address(r['start']) <= address(edge['target_address']) < address(r['end'])
                            for r in functions[target]['ranges']), 'Call target outside recovered body')
            else:
                require(bundle['status'] != 'available', 'Available bundle omits application callee')
        else:
            require(edge['target_entry'] is None, 'Nonapplication edge has function entry')
    for transfer in bundle['unresolved_transfers']:
        require(instructions.get(address(transfer['site'])) == address(transfer['caller']),
                'Unresolved transfer outside caller')
    data_addresses = set()
    for item in bundle['data']:
        pc = address(item['address'])
        require(pc not in data_addresses, 'Duplicate data address')
        data_addresses.add(pc)
        require(len(bytes.fromhex(item['bytes'])) == item['size'], 'Data size differs')
        scan_metadata(bytes.fromhex(item['bytes']))
        require(item['string_prefix'] == string_prefix(bytes.fromhex(item['bytes'])),
                'String interpretation differs from public bytes')
        require(item['references'] and len(set(item['references'])) == len(item['references'])
                and all(address(a) in instructions for a in item['references']), 'Data reference outside bundle')
        if binary is not None:
            require(loaded_bytes(binary, pc, item['size']).hex() == item['bytes'], 'Data bytes differ from public binary')
    complete = bundle['completeness']
    if bundle['status'] == 'available':
        require(functions and bundle['entry_address'] is not None
                and address(bundle['entry_address']) in instructions, 'Available bundle has no entry instruction')
        require(complete['traversal'] == 'complete' and complete['data'] != 'incomplete'
                and complete['decompilation'] == 'complete' and not complete['omissions']
                and not bundle['unresolved_transfers'] and not any(d['truncated'] for d in bundle['data'])
                and all(f['decompilation']['status'] == 'ok' and f['instructions'] for f in bundle['functions'])
                and not any(c['resolution'] == 'unresolved' for c in bundle['calls']),
                'Available bundle has incomplete evidence')
        reachable = {instructions[address(bundle['entry_address'])]}
        while True:
            expanded = reachable | {address(c['target_entry']) for c in bundle['calls']
                                    if c['resolution'] == 'application' and address(c['caller']) in reachable}
            if expanded == reachable:
                break
            reachable = expanded
        require(reachable == set(functions), 'Bundle includes unreachable functions')
    else:
        require(complete['omissions'], 'Unavailable bundle has no reason')
    return bundle


def apply_budget(bundle, policy):
    result = deepcopy(bundle)
    reasons = []
    if len(result['functions']) > policy['max_functions']:
        reasons.append('function_limit')
    if sum(len(f['instructions']) for f in result['functions']) > policy['max_instructions']:
        reasons.append('instruction_limit')
    if sum(d['size'] for d in result['data']) > policy['max_data_bytes']:
        reasons.append('data_total_limit')
    if any(d['size'] > policy['max_data_bytes_per_reference'] for d in result['data']):
        reasons.append('data_reference_limit')
    for reason in reasons:
        result['completeness']['omissions'].append({'reason': reason, 'address': None})
    if reasons:
        result['status'] = 'context_unavailable'
    # Account for the final serialized diagnostic itself. No code/data is silently removed.
    for field, reason in (('max_bundle_utf8_bytes', 'bundle_byte_limit'),
                          ('max_token_upper_bound', 'token_upper_bound_limit')):
        if len(canonical(normalize(result)).encode('utf-8')) > policy[field]:
            result['status'] = 'context_unavailable'
            result['completeness']['omissions'].append({'reason': reason, 'address': None})
    return normalize(result)


def evidence_addresses(bundle, supplied):
    """Check evidence in any included function; callers gate on bundle availability separately."""
    included = {i['address'] for f in bundle['functions'] for i in f['instructions']}
    require(isinstance(supplied, list) and all(isinstance(a, str) and a in included for a in supplied),
            'Evidence address outside bundle instructions')
    return True
