"""Phase 3 campaign builds and private evidence. Never runs a predictor or a testcase."""
import argparse
import hashlib
import os
import platform
import re
import shlex
import shutil
import struct
import subprocess

from .inventory import ROOT, digest, encode, generate, local_path, read_json, require
from .sanitize import scan_metadata


def elf_sections(path):
    """Read ELF64 little-endian sections, including all allocated code/data, not just .text."""
    data = path.read_bytes()
    require(data[:6] == b'\x7fELF\x02\x01', 'Expected little-endian ELF64')
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    require(header[2] == 62, 'Expected x86-64 ELF')
    offset, width, count, names_index = header[6], header[11], header[12], header[13]
    require(width == 64 and count > 0 and names_index < count, 'Unsupported ELF section table')
    rows = [struct.unpack_from('<IIQQQQIIQQ', data, offset + i * width) for i in range(count)]
    names = rows[names_index]
    strings = data[names[4]:names[4] + names[5]]
    result = {}
    for name, kind, flags, address, start, size, _, _, alignment, _ in rows:
        end = strings.find(b'\0', name)
        require(end >= name, 'Invalid ELF section name')
        label = strings[name:end].decode()
        if not label:
            continue
        require(label not in result, 'Duplicate ELF section')
        require(kind == 8 or start + size <= len(data), 'Truncated ELF section')
        result[label] = {'type': kind, 'flags': flags, 'address': address, 'size': size,
                         'alignment': alignment,
                         'sha256': None if kind == 8 else hashlib.sha256(data[start:start + size]).hexdigest()}
    return result


def allocated_sections(path):
    return {k: v for k, v in elf_sections(path).items() if v['flags'] & 2}


def check_partner(reference, public, stripped=False):
    sections = elf_sections(public)
    require(not any(n.startswith(('.debug', '.zdebug')) or n == '.gdb_index' for n in sections),
            'Public debug information remains')
    require(not stripped or '.symtab' not in sections, 'Stripped static symbols remain')
    require(allocated_sections(reference) == allocated_sections(public),
            'Symbol partner changed allocated code/data')
    scan_metadata(public.read_bytes())


def command(argv, cwd, commands):
    args = [str(a) for a in argv]
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=120)
    commands.append({'argv': args, 'cwd': str(cwd), 'exit_code': result.returncode,
                     'stdout': result.stdout, 'stderr': result.stderr})
    require(result.returncode == 0, f'Command failed: {args}; {result.stderr}')
    return result.stdout


def identity(path):
    from pathlib import Path
    resolved = Path(path).resolve(strict=True)
    return {'path': str(resolved), 'sha256': digest(resolved)}


def toolchain(config, directory, commands):
    compiler = config['compiler']
    tools = {}
    for name in (compiler['name'], 'objcopy', 'strip', 'objdump', 'readelf', 'nm', 'ld', 'as'):
        path = shutil.which(name)
        require(path, f'Missing pinned tool: {name}')
        version = command([path, '--version'], directory, commands).splitlines()[0]
        expected = compiler['expected_version'] if name == compiler['name'] else compiler['expected_binutils_version']
        require(re.search(r'(?<![\d.])' + re.escape(expected) + r'(?![\d.])', version),
                f'Pinned version differs: {name}: {version}')
        tools[name] = {**identity(path), 'version': version}
    require(command([compiler['name'], '-dumpfullversion'], directory, commands).strip()
            == compiler['expected_version'], 'Compiler version differs')
    require(command([compiler['name'], '-dumpmachine'], directory, commands).strip()
            == config['platform'].replace('x86-64', 'x86_64'), 'Compiler target differs')
    for name in ('cc1', 'collect2', 'libc.so.6', 'ld-linux-x86-64.so.2', 'crt1.o', 'crti.o', 'crtbegin.o', 'libgcc.a'):
        option = '-print-prog-name=' if name in {'cc1', 'collect2'} else '-print-file-name='
        path = command([compiler['name'], option + name], directory, commands).strip()
        tools[name] = identity(path)
    return {'tools': tools, 'os': platform.platform(), 'machine': platform.machine(),
            'environment': {n: os.environ.get(n) for n in ('PATH', 'CPATH', 'C_INCLUDE_PATH',
                            'LIBRARY_PATH', 'COMPILER_PATH', 'GCC_EXEC_PREFIX', 'SOURCE_DATE_EPOCH',
                            'LANG', 'LC_ALL')}}


def private_evidence(reference, directory, commands):
    # Stable relative tool arguments avoid embedding the workspace path in objdump's header.
    reference = os.path.relpath(reference, directory)
    outputs = {'assembly.txt': ['objdump', '-d', '-w', '-Mintel', reference],
               'symbols.txt': ['nm', '-S', '-n', '--defined-only', reference],
               'debug-info.txt': ['readelf', '--debug-dump=info', reference],
               'debug-lines.txt': ['readelf', '--debug-dump=decodedline', reference],
               'debug-ranges.txt': ['readelf', '--debug-dump=Ranges', reference]}
    texts = {}
    for name, argv in outputs.items():
        texts[name] = command(argv, directory, commands)
        (directory / name).write_text(texts[name])
    functions = []
    for line in texts['symbols.txt'].splitlines():
        match = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] (.+)', line)
        if match:
            functions.append({'name': match[3], 'start': int(match[1], 16),
                              'end': int(match[1], 16) + int(match[2], 16)})
    instructions = [int(m[1], 16) for line in texts['assembly.txt'].splitlines()
                    if (m := re.match(r'^\s*([0-9a-f]+):\s+[0-9a-f]{2}\s', line))]
    return {'functions': functions, 'instruction_addresses': instructions,
            'files': {name: digest(directory / name) for name in outputs}}


def build_one(root, config, pair, cell, observations, commands):
    directory = root / 'build' / observations[0]['analysis_path'].split('/')[1] / 'private' / cell['build_id']
    directory.mkdir(parents=True, exist_ok=True)
    compiler = config['compiler']
    flags = [f.replace('{workspace}', str(root)) for f in compiler['common_flags']]
    flags += ['-' + cell['optimization']]
    flags += [v for p in pair.get('include_dirs', []) for v in ('-I', str(local_path(root, p)))]
    flags += ['-D' + d for d in pair['variant_selection'][cell['variant']]['defines']]
    units = list(pair.get('translation_units', pair['sources']))
    units += pair['variant_selection'][cell['variant']]['driver_sources'] + pair['support_sources']
    units = list(dict.fromkeys(units))
    objects, headers = [], {}
    for i, name in enumerate(units):
        obj, deps = directory / f'unit-{i}.o', directory / f'unit-{i}.d'
        command([compiler['name'], *flags, '-MD', '-MF', deps, '-c', local_path(root, name), '-o', obj],
                root, commands)
        dependencies = shlex.split(deps.read_text().replace('\\\n', ' ').split(':', 1)[1])
        for dependency in dependencies:
            headers[dependency] = digest(root / dependency)
        objects.append(obj)
    command([compiler['name'], *flags, '-Q', '--help=optimizers', '--help=target', '-c', '-x', 'c',
             '/dev/null', '-o', directory / 'options.o'], root, commands)
    (directory / 'effective-options.txt').write_text(commands[-1]['stdout'] + commands[-1]['stderr'])
    reference = local_path(root, cell['reference_path'])
    reference.parent.mkdir(parents=True, exist_ok=True)
    command([compiler['name'], '-' + cell['optimization'], *objects, *compiler['link_flags'], '-o', reference],
            root, commands)
    require(any(n.startswith('.debug_info') for n in elf_sections(reference)), 'Private debug information missing')
    artifacts = {'reference': {'path': cell['reference_path'], 'sha256': digest(reference)}}
    retained = local_path(root, next(o['analysis_path'] for o in observations if o['symbols'] == 'retained'))
    retained.parent.mkdir(parents=True, exist_ok=True)
    command(['objcopy', '--strip-debug', reference, retained], root, commands)
    for observation in observations:
        public = local_path(root, observation['analysis_path'])
        public.parent.mkdir(parents=True, exist_ok=True)
        if observation['symbols'] == 'stripped':
            command(['strip', '--strip-all', '-o', public, retained], root, commands)
        check_partner(reference, public, observation['symbols'] == 'stripped')
        artifacts[observation['symbols']] = {'path': observation['analysis_path'], 'sha256': digest(public)}
    evidence = private_evidence(reference, directory, commands)
    return {'status': 'built', 'artifacts': artifacts, 'allocated_sections': allocated_sections(reference),
            'dependencies': headers, 'translation_units': units, 'evidence': evidence,
            'evidence_directory': directory.relative_to(root).as_posix(),
            'effective_options_sha256': digest(directory / 'effective-options.txt')}


def build(root=ROOT, split='pilot'):
    root = root.resolve()
    config, manifest = read_json(root / 'config.json'), read_json(root / 'corpus/manifest.json')
    plan = generate(config, manifest, root, split, require_assigned=True)
    directory = root / 'build' / split
    directory.mkdir(parents=True, exist_ok=True)
    report_path = directory / 'build-manifest.json'
    require(not report_path.exists(), 'Build manifest already exists; verify it or use a separate workspace')
    commands = []
    environment = toolchain(config, root, commands)
    pairs = {p['pair_id']: p for p in manifest['pairs']}
    report = {'schema_version': 3, 'phase': 3, 'campaign_id': config['campaign_id'], 'split': split,
              'config_sha256': digest(root / 'config.json'), 'manifest_sha256': digest(root / 'corpus/manifest.json'),
              'methods': {f'pipeline/{n}': digest(root / 'pipeline' / n)
                          for n in ('build.py', 'inventory.py', 'sanitize.py')},
              'environment': environment, 'plan': plan, 'builds': []}
    for cell in plan['builds']:
        log = []
        try:
            result = build_one(root, config, pairs[cell['pair_id']], cell,
                               [o for o in plan['observations'] if o['build_id'] == cell['build_id']], log)
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            result = {'status': 'build_unavailable', 'reason': str(error)}
        report['builds'].append({**cell, **result, 'commands': log})
        report_path.write_text(encode(report))
    report['toolchain_commands'] = commands
    report_path.write_text(encode(report))
    return report


def verify(report, root=ROOT):
    config, manifest = read_json(root / 'config.json'), read_json(root / 'corpus/manifest.json')
    plan = generate(config, manifest, root, report['split'], require_assigned=True)
    require(report['schema_version'] == 3 and report['plan'] == plan, 'Build plan differs')
    for field, path in (('config_sha256', 'config.json'), ('manifest_sha256', 'corpus/manifest.json')):
        require(report[field] == digest(root / path), 'Build inputs changed')
    for name, expected in report['methods'].items():
        require(digest(local_path(root, name)) == expected, 'Build method changed')
    for tool in report['environment']['tools'].values():
        require(digest(tool['path']) == tool['sha256'], 'Toolchain/library changed')
    require([{k: b[k] for k in cell} for b, cell in zip(report['builds'], plan['builds'])] == plan['builds']
            and len(report['builds']) == len(plan['builds']), 'Build inventory differs')
    for cell in report['builds']:
        require(cell['status'] in {'built', 'build_unavailable'}, 'Invalid build status')
        if cell['status'] != 'built':
            require(bool(cell.get('reason')), 'Missing build failure reason')
            continue
        require(set(cell['artifacts']) == {'reference', 'retained', 'stripped'}, 'Artifact inventory differs')
        expected_paths = {'reference': cell['reference_path'], **{
            o['symbols']: o['analysis_path'] for o in plan['observations'] if o['build_id'] == cell['build_id']}}
        for kind, artifact in cell['artifacts'].items():
            require(artifact['path'] == expected_paths[kind], 'Artifact path differs')
            require(digest(local_path(root, artifact['path'])) == artifact['sha256'], 'Artifact hash differs')
        reference = root / cell['reference_path']
        require(allocated_sections(reference) == cell['allocated_sections'], 'Allocated evidence differs')
        for kind in ('retained', 'stripped'):
            check_partner(reference, root / cell['artifacts'][kind]['path'], kind == 'stripped')
        for path, expected in cell['dependencies'].items():
            require(digest(root / path) == expected, 'Source/header dependency changed')
        for name, expected in cell['evidence']['files'].items():
            require(digest(local_path(root, cell['evidence_directory']) / name) == expected, 'Private evidence changed')
        assembly = (root / cell['evidence_directory'] / 'assembly.txt').read_text()
        addresses = [int(m[1], 16) for line in assembly.splitlines()
                     if (m := re.match(r'^\s*([0-9a-f]+):\s+[0-9a-f]{2}\s', line))]
        require(addresses == cell['evidence']['instruction_addresses'], 'Instruction inventory differs')
        require(digest(root / cell['evidence_directory'] / 'effective-options.txt')
                == cell['effective_options_sha256'], 'Effective options changed')
    return {'reference_builds': len(report['builds']),
            'built': sum(c['status'] == 'built' for c in report['builds']),
            'build_unavailable': sum(c['status'] != 'built' for c in report['builds'])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('build', 'verify'))
    parser.add_argument('--split', choices=('pilot', 'final'), default='pilot')
    args = parser.parse_args()
    report = build(split=args.split) if args.action == 'build' else read_json(ROOT / 'build' / args.split / 'build-manifest.json')
    print(encode(verify(report)), end='')


if __name__ == '__main__':
    main()
