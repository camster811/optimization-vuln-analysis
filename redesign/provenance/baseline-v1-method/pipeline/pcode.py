"""Public-bundle-only Ghidra lifting. No original binary, source or oracle is opened."""
import os
from pathlib import Path
import subprocess

from .bundles import address, canonical, validate
from .context_worker import engine_home
from .inventory import ROOT, digest, encode, read_json, require


def validate_ir(ir, bundle):
    require(set(ir) == {'schema_version', 'engine', 'functions', 'status'}
            and ir['schema_version'] == 1 and ir['engine'] == 'ghidra-high-pcode' and ir['status'] == 'ok',
            'Invalid P-code export')
    functions = {f['entry']: f for f in bundle['functions']}
    require(len(ir['functions']) == len(functions) and {f['entry'] for f in ir['functions']} == set(functions),
            'P-code function inventory differs from public scope')
    for function in ir['functions']:
        require(set(function) == {'entry', 'parameter_count', 'blocks', 'native_writes'}
                and type(function['parameter_count']) is int and 0 <= function['parameter_count'] <= 16,
                'Invalid recovered parameter count')
        instructions = {i['address'] for i in functions[function['entry']]['instructions']}
        for write in function['native_writes']:
            require(set(write) == {'address', 'size'} and write['address'] in instructions
                    and type(write['size']) is int and 0 < write['size'] <= 64, 'Invalid native write inventory')
        blocks = function['blocks']
        ids = [b['index'] for b in blocks]
        require(blocks and len(ids) == len(set(ids)) and 0 in ids, 'Invalid P-code blocks')
        for block in blocks:
            require(set(block) == {'index', 'start', 'incoming', 'outgoing', 'ops'}
                    and set(block['incoming'] + block['outgoing']) <= set(ids), 'Invalid block relationships')
            lookup = {b['index']: b for b in blocks}
            require(all(block['index'] in lookup[target]['incoming'] for target in block['outgoing'])
                    and all(block['index'] in lookup[source]['outgoing'] for source in block['incoming']),
                    'Nonreciprocal block relationships')
            for op in block['ops']:
                require(set(op) == {'opcode', 'address', 'output', 'inputs'}
                        and op['address'] in instructions and isinstance(op['opcode'], str),
                        'P-code evidence outside selected instructions')
                for node in op['inputs'] + ([op['output']] if op['output'] is not None else []):
                    require(set(node) == {'id', 'space', 'offset', 'size', 'parameter', 'stack_base'}
                            and isinstance(node['id'], str) and isinstance(node['space'], str)
                            and type(node['size']) is int and 0 < node['size'] <= 64
                            and type(node['stack_base']) is bool, 'Invalid P-code varnode')
                    address(node['offset'])
                    require(node['parameter'] is None or type(node['parameter']) is int
                            and 0 <= node['parameter'] < function['parameter_count'], 'Invalid parameter slot')
    return ir


def lift(bundle, policy, work):
    validate(bundle)
    require(bundle['status'] == 'available', 'Unavailable public context')
    work = work.resolve(); work.mkdir(parents=True, exist_ok=False)
    input_path = work / 'input.json'; input_path.write_text(canonical(bundle))
    policy_path = work / 'policy.json'; policy_path.write_text(encode(policy))
    seed = work / 'seed.bin'; seed.write_bytes(b'\xc3')
    output = work / 'pcode.json'
    home = engine_home(read_json(ROOT / 'context_policy.json'))
    profile = work / 'profile'; profile.mkdir()
    settings = {'user.home': profile, 'application.settingsdir': work / 'settings',
                'application.cachedir': work / 'cache', 'application.tempdir': work / 'tmp'}
    environment = {**os.environ, 'JAVA_TOOL_OPTIONS': '-XX:-UsePerfData ' +
                   ' '.join(f'-D{k}={v}' for k, v in settings.items())}
    argv = [str(home / 'support/analyzeHeadless'), str(work), 'bounds', '-processor', 'x86:LE:64:default',
            '-cspec', 'gcc', '-import', str(seed), '-loader', 'BinaryLoader', '-loader-baseAddr', '0x0',
            '-noanalysis', '-scriptPath', str(ROOT / 'ghidra'), '-deleteProject', '-max-cpu', '2',
            '-log', str(work / 'headless.log'), '-scriptlog', str(work / 'script.log'),
            '-postScript', 'LiftBundle.java', str(input_path), str(policy_path), str(output)]
    trace = {'argv': argv, 'input_sha256': digest(input_path)}
    with (work / 'console.log').open('w') as stream:
        result = subprocess.run(argv, env=environment, stdout=stream, stderr=subprocess.STDOUT,
                                timeout=policy['process_timeout_seconds'])
    trace['exit_code'] = result.returncode
    (work / 'worker.json').write_text(encode(trace))
    require(result.returncode == 0 and output.is_file(), 'Ghidra P-code export failed; inspect console.log')
    ir = read_json(output)
    require(ir.get('status') == 'ok', f'Ghidra P-code export failed: {ir.get("error")}')
    validate_ir(ir, bundle)
    return ir
