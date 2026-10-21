"""Phase 2 source-preservation checks; these builds are not campaign inputs or binary truth."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from .import_juliet import verify_import
from .inventory import ROOT, digest, encode, read_json, require
from .sanitize import scan_metadata


def run(command, directory, log):
    result = subprocess.run([str(v) for v in command], cwd=directory,
                            capture_output=True, text=True, timeout=120)
    with log.open('a') as stream:
        stream.write(repr([str(v) for v in command]) + '\n' + result.stdout + result.stderr)
    require(result.returncode == 0, f'Command failed; inspect {log}: {command[0]}')
    return result.stdout


def code_sections(binary, directory, log):
    listing = run(['objdump', '-h', binary], directory, log)
    sections = []
    for line in listing.splitlines():
        match = re.match(r'\s*\d+\s+(\.text\S*)\s+', line)
        if match:
            sections.append(match.group(1))
    require(sections, 'No executable text sections found')
    result = {}
    for i, section in enumerate(sections):
        output = directory / (binary.name + f'.section-{i}')
        run(['objcopy', '--dump-section', f'{section}={output}', binary], directory, log)
        result[section] = digest(output)
    return result


def relocations(binary, directory, log, mapping):
    listing = run(['objdump', '-r', binary], directory, log)
    active, rows = False, []
    for line in listing.splitlines():
        if line.startswith('RELOCATION RECORDS FOR ['):
            active = bool(re.match(r'RELOCATION RECORDS FOR \[\.text', line))
        elif active and re.match(r'^[0-9a-f]+\s+R_', line):
            # Symbol renaming is the only normalization; section offsets stay visible.
            line = re.sub(r'[A-Za-z_][A-Za-z0-9_]*', lambda m: mapping.get(m[0], m[0]), line)
            rows.append(' '.join(line.split()))
    return rows


def verify_relocations(old_rows, new_rows, old_binary, new_binary, directory, log, diagnostics):
    """Permit only resolved literal relocation changes, never arbitrary operand changes."""
    require(len(old_rows) == len(new_rows), 'Relocation count changed')
    literal_map = {json.loads(k).encode(): json.loads(v).encode() for k, v in diagnostics.items()}
    cache = {}

    def literal(binary, section, offset):
        key = (binary, section)
        if key not in cache:
            output = directory / f'relocation-data-{len(cache)}'
            run(['objcopy', '--dump-section', f'{section}={output}', binary], directory, log)
            cache[key] = output.read_bytes()
        data = cache[key]
        require(0 <= offset < len(data), 'Literal relocation outside section')
        end = data.find(b'\0', offset)
        require(end >= 0, 'Unterminated relocated literal')
        return data[offset:end]

    differences = []
    for old, new in zip(old_rows, new_rows):
        old_offset, old_type, old_target = old.split()
        new_offset, new_type, new_target = new.split()
        require((old_offset, old_type) == (new_offset, new_type), 'Instruction relocation changed')
        pattern = r'(\.rodata(?:\.[A-Za-z0-9_.]+)?)(?:\+0x([0-9a-f]+))?'
        old_match, new_match = re.fullmatch(pattern, old_target), re.fullmatch(pattern, new_target)
        if old_type in {'R_X86_64_32', 'R_X86_64_32S'} and old_match and new_match:
            before = literal(old_binary, old_match[1], int(old_match[2] or '0', 16))
            after = literal(new_binary, new_match[1], int(new_match[2] or '0', 16))
            require(literal_map.get(before, before) == after, 'Referenced literal changed without approval')
            if old != new or before != after:
                differences.append({'instruction_offset': old_offset, 'original_target': old_target,
                                    'sanitized_target': new_target,
                                    'reason': 'reviewed diagnostic replacement or resulting literal layout',
                                    'original_literal_sha256': hashlib.sha256(before).hexdigest(),
                                    'sanitized_literal_sha256': hashlib.sha256(after).hexdigest()})
        else:
            require(old == new, 'Unexplained relocation target change')
    return differences


def compile_case(root, pair, decision, variant, opt, original=False, sanitizer=False):
    side = 'original' if original else 'sanitized'
    directory = root / 'build/phase2-validation' / pair['pair_id'] / variant / opt / (side + ('-asan' if sanitizer else ''))
    directory.mkdir(parents=True, exist_ok=True)
    log = directory / 'commands.log'
    log.write_text('')
    config = read_json(root / 'config.json')['compiler']
    flags = [flag.replace('{workspace}', str(root)) for flag in config['common_flags']]
    if sanitizer:
        flags += ['-fsanitize=address', '-fno-omit-frame-pointer']
    if original:
        original_path = root / 'corpus/upstream' / decision['source']
        driver = directory / 'driver.c'
        driver.write_text(f'#include "{original_path.as_posix()}"\nint main(void)\n{{\n    {decision["original_entries"][variant]}();\n    return 0;\n}}\n')
        units = [driver, root / 'corpus/upstream/testcasesupport/io.c']
        include_dirs = [root / 'corpus/upstream/testcasesupport']
        defines = ['OMITGOOD' if variant == 'vulnerable' else 'OMITBAD']
    else:
        units = [root / p for p in pair['translation_units'] + pair['support_sources']]
        include_dirs = [root / p for p in pair['include_dirs']]
        defines = pair['variant_selection'][variant]['defines']
    include_flags = [v for directory in include_dirs for v in ('-I', str(directory))]
    objects = []
    for i, unit in enumerate(units):
        target = directory / f'unit-{i}.o'
        run([config['name'], *flags, '-' + opt, *include_flags, *['-D' + d for d in defines],
             '-c', unit, '-o', target], directory, log)
        objects.append(target)
    reference = directory / 'reference'
    run([config['name'], '-' + opt, *objects, *config['link_flags'],
         *(['-fsanitize=address'] if sanitizer else []), '-o', reference], directory, log)
    if not sanitizer:
        retained, stripped = directory / 'retained', directory / 'stripped'
        run(['objcopy', '--strip-debug', reference, retained], directory, log)
        run(['strip', '--strip-all', '-o', stripped, retained], directory, log)
        sections = code_sections(reference, directory, log)
        for binary in (retained, stripped):
            require(code_sections(binary, directory, log) == sections, 'Stripping changed executable text')
            require('.debug_' not in run(['readelf', '-SW', binary], directory, log), 'Public debug sections remain')
            if not original:
                scan_metadata(binary.read_bytes())
    return reference, objects, directory, log


def validate(root=ROOT):
    imported = verify_import(root)
    config = read_json(root / 'config.json')
    require(subprocess.check_output([config['compiler']['name'], '-dumpfullversion'], text=True).strip()
            == config['compiler']['expected_version'], 'Compiler version differs')
    for tool in ('objcopy', 'strip', 'objdump', 'readelf'):
        require(config['compiler']['expected_binutils_version'] in subprocess.check_output([tool, '--version'], text=True).splitlines()[0],
                f'{tool} version differs')
    selections = read_json(root / 'corpus/pilot_selection.json')
    decisions = {d['pair_id']: d for d in selections['decisions'] if d['decision'] == 'pilot'}
    manifest = read_json(root / 'corpus/manifest.json')
    comparisons, sanitizer_runs = [], []
    for pair in manifest['pairs']:
        if pair['split'] != 'pilot':
            continue
        decision = decisions[pair['pair_id']]
        transformation = read_json(root / pair['sanitization_manifest'])
        mapping = transformation['identifiers']
        for variant in config['matrix']['variants']:
            for opt in config['matrix']['optimizations']:
                original = compile_case(root, pair, decision, variant, opt, original=True)
                sanitized = compile_case(root, pair, decision, variant, opt)
                unit_results = []
                for old_object, new_object in zip(original[1], sanitized[1]):
                    old_code = code_sections(old_object, original[2], original[3])
                    new_code = code_sections(new_object, sanitized[2], sanitized[3])
                    old_relocs = relocations(old_object, original[2], original[3], mapping)
                    new_relocs = relocations(new_object, sanitized[2], sanitized[3], {})
                    explained = verify_relocations(old_relocs, new_relocs, old_object, new_object,
                                                   sanitized[2], sanitized[3], transformation['diagnostics'])
                    unit_results.append({'unit': new_object.name, 'text_equal': old_code == new_code,
                                         'text_section_sha256': new_code,
                                         'normalized_relocations_equal': old_relocs == new_relocs,
                                         'relocation_equivalence_verified': True,
                                         'explained_literal_changes': explained})
                require(all(r['text_equal'] for r in unit_results),
                        f'Unexpected machine-code difference: {pair["pair_id"]}/{variant}/{opt}')
                comparisons.append({'pair_id': pair['pair_id'], 'variant': variant, 'optimization': opt,
                                    'units': unit_results, 'symbol_partners_text_equal': True,
                                    'metadata_scan': 'passed', 'debug_sections_absent': True,
                                    'reference': sanitized[0].relative_to(root).as_posix(),
                                    'reference_sha256': digest(sanitized[0])})
            # O0 sanitizer runs validate original/sanitized source behavior separately.
            # They do not label optimized experimental binaries or constrain selection.
            for original in (True, False):
                reference, _, directory, _ = compile_case(root, pair, decision, variant, 'O0', original, True)
                environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=0:halt_on_error=1:symbolize=0')
                result = subprocess.run([str(reference)], capture_output=True, timeout=30, env=environment)
                (directory / 'stdout.log').write_bytes(result.stdout)
                (directory / 'stderr.log').write_bytes(result.stderr)
                expected = ('stack' if pair['cwe'] == 'CWE-121' else 'heap') + '-buffer-overflow'
                if variant == 'safe':
                    require(result.returncode == 0 and b'ERROR: AddressSanitizer' not in result.stderr,
                            f'Unexpected safe sanitizer outcome: {directory}')
                else:
                    require(result.returncode != 0 and expected.encode() in result.stderr,
                            f'Expected sanitizer evidence absent: {directory}')
                sanitizer_runs.append({'pair_id': pair['pair_id'], 'variant': variant,
                                       'side': 'original' if original else 'sanitized', 'optimization': 'O0',
                                       'exit_code': result.returncode,
                                       'outcome': expected if variant == 'vulnerable' else 'completed_without_asan_error',
                                       'stdout_sha256': hashlib.sha256(result.stdout).hexdigest()})
        safe = [r for r in sanitizer_runs if r['pair_id'] == pair['pair_id'] and r['variant'] == 'safe']
        require(safe[0]['stdout_sha256'] == safe[1]['stdout_sha256'], 'Safe observable output changed')
    report = {'schema_version': 2, 'phase': 2, 'status': 'validated', 'import_checks': imported,
              'compiler_version': config['compiler']['expected_version'],
              'binutils_version': config['compiler']['expected_binutils_version'],
              'manifest_sha256': digest(root / 'corpus/manifest.json'),
              'config_sha256': digest(root / 'config.json'),
              'validation_methods': {f'pipeline/{name}': digest(root / 'pipeline' / name)
                                     for name in ('inventory.py', 'sanitize.py', 'import_juliet.py', 'validate_sources.py')},
              'source_comparisons': comparisons, 'sanitizer_runs': sanitizer_runs,
              'public_records': 'not_exported_phase_4_pending',
              'scope': 'Source-preservation validation only. Phase 3 must build campaign artifacts and adjudicate optimized behavior.'}
    (root / 'provenance/phase2-validation.json').write_text(encode(report))
    return {'status': 'validated', 'original_sanitized_build_comparisons': len(comparisons),
            'sanitizer_runs': len(sanitizer_runs),
            'relocation_differences': sum(not u['normalized_relocations_equal'] for c in comparisons for u in c['units'])}


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    print(encode(validate()), end='')


if __name__ == '__main__':
    main()
