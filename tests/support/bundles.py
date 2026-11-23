"""Synthetic bundles builders."""
from optimization_vuln_analysis.inputs import bundles


def build_bundle():
    def ins(pc, opcode='90', mnemonic='NOP'):
        return {'address': hex(pc), 'size': len(bytes.fromhex(opcode)), 'bytes': opcode,
                'mnemonic': mnemonic, 'operands': ''}
    def function(entry, name, instructions):
        return {'entry': hex(entry), 'name': name, 'name_origin': 'analysis',
                'ranges': [{'start': hex(entry), 'end': hex(entry + 2)}], 'instructions': instructions,
                'decompilation': {'status': 'ok', 'text': f'void {name}(void) {{ return; }}'}}
    value = bundles.empty_bundle('0x1000', 'entry_unavailable')
    value['status'] = 'available'
    value['completeness'].update(traversal='complete', data='complete', decompilation='complete', omissions=[])
    value['functions'] = [function(0x1000, 'entry', [ins(0x1000), ins(0x1001, 'c3', 'RET')]),
                          function(0x2000, 'process', [ins(0x2000), ins(0x2001, 'c3', 'RET')])]
    value['calls'] = [{'caller': '0x1000', 'site': '0x1000', 'target_address': '0x2000',
                       'target_entry': '0x2000', 'target_name': 'process', 'kind': 'tail', 'resolution': 'application'}]
    value['data'] = [{'address': '0x3000', 'size': 4, 'bytes': '41424300', 'string_prefix': 'ABC', 'writable': False,
                      'storage': 'initialized', 'extent_status': 'recovered_type_extent',
                      'recovered_type': 'char[4]', 'interpretation': 'uncertain_binary_recovery_not_an_object_bound',
                      'references': ['0x2000'], 'truncated': False}]
    return value

