"""Import the source-reviewed pilots from the pinned Juliet archive, without changing logic."""
import argparse
import csv
import difflib
import hashlib
from pathlib import Path
import re
import zipfile

from .inventory import ROOT, digest, encode, local_path, read_json, require, validate_manifest
from .sanitize import sanitize, scan_metadata, verify_preservation


DOCUMENTS = ROOT.parent / 'documentation/juliet-redesign'
SUPPORT = {'testcasesupport/std_testcase.h': 'corpus/support/runtime.h',
           'testcasesupport/std_testcase_io.h': 'corpus/support/output.h',
           'testcasesupport/io.c': 'corpus/support/output.c'}
INCLUDES = {'"std_testcase.h"': '"runtime.h"', '"std_testcase_io.h"': '"output.h"'}
DIAGNOSTICS = {'"Calling good()..."': '"Starting operation"',
               '"Calling bad()..."': '"Starting operation"',
               '"Finished good()"': '"Operation finished"',
               '"Finished bad()"': '"Operation finished"',
               '"Benign, fixed string"': '"Status message"'}


def sha(content):
    return hashlib.sha256(content).hexdigest()


def fingerprint(files):
    return sha(''.join(f'{name}\t{files[name]}\n' for name in sorted(files)).encode())


def store(path, content, readonly=False):
    """Reruns may confirm identical outputs, but cannot silently overwrite changed sources."""
    if isinstance(content, str):
        content = content.encode()
    if path.exists():
        require(path.read_bytes() == content, f'Existing output differs: {path}')
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    if readonly:
        path.chmod(0o444)


def identifier_map(decision):
    stem = Path(decision['source']).stem
    mapping = {'OMITBAD': 'EXCLUDE_BRANCH_ALPHA', 'OMITGOOD': 'EXCLUDE_BRANCH_BETA',
               'INCLUDEMAIN': 'BUILD_STANDALONE', '_STD_TESTCASE_H': 'RUNTIME_SUPPORT_H',
               '_STD_TESTCASE_IO_H': 'OUTPUT_SUPPORT_H',
               stem + '_bad': 'process_case', stem + '_good': 'run_paths'}
    if decision['pair_id'] == 'pilot-01':
        mapping.update({stem + '_badSink': 'write_buffer', stem + '_goodG2BSink': 'write_buffer',
                        'goodG2B': 'process_case', 'dataBadBuffer': 'buffer_first',
                        'dataGoodBuffer': 'buffer_second', 'SRC_STRING': 'SOURCE_TEXT'})
    else:
        mapping.update({'badSink': 'write_buffer', 'badStatic': 'flow_gate',
                        'goodB2G1': 'process_case', 'goodB2G1Sink': 'write_buffer',
                        'goodB2G1Static': 'flow_gate', 'goodB2G2': 'process_alternate',
                        'goodB2G2Sink': 'write_alternate', 'goodB2G2Static': 'flow_gate_second',
                        'goodG2B': 'process_secondary', 'goodG2BSink': 'write_secondary',
                        'goodG2BStatic': 'flow_gate_third'})
    # Unused support hooks are preserved, with neutral names in retained symbols.
    for i, name in enumerate(sorted([f'{prefix}{i}' for prefix in ('good', 'bad') for i in range(1, 10)]), 1):
        mapping[name] = f'unused_hook_{i:02d}'
    return mapping


def verify_archive(archive, extracted_root, root=ROOT):
    expected = read_json(DOCUMENTS / 'candidate_snapshot.json')
    require(digest(archive) == expected['archive_sha256'], 'Juliet archive hash mismatch')
    table = DOCUMENTS / 'candidate_families.csv'
    require(digest(table) == expected['candidate_table_sha256'], 'Candidate ordering changed')
    hashes, grouped = {}, {}
    with zipfile.ZipFile(archive) as zipped:
        require(len(zipped.namelist()) == len(set(zipped.namelist())), 'Duplicate ZIP members')
        for member in zipped.namelist():
            if not re.match(r'C/testcases/CWE12[12]_[^/]+/.*\.c$', member):
                continue
            relative = member[2:]
            content = zipped.read(member)
            hashes[relative] = sha(content)
            require(digest(local_path(extracted_root, relative)) == hashes[relative],
                    f'Extracted file differs from archive: {relative}')
            family = re.sub(r'_[0-9]{2}[a-z]?$', '', Path(relative).stem)
            grouped.setdefault(family, {})[relative] = hashes[relative]
    actual_paths = {p.relative_to(extracted_root).as_posix()
                    for folder in ('CWE121_Stack_Based_Buffer_Overflow', 'CWE122_Heap_Based_Buffer_Overflow')
                    for p in (extracted_root / 'testcases' / folder).rglob('*.c')}
    require(actual_paths == set(hashes), 'Extracted candidate source inventory differs')
    require(len(hashes) == expected['source_file_count'] and fingerprint(hashes) == expected['source_inventory_sha256'],
            'Candidate source snapshot differs from pinned archive')
    with table.open() as stream:
        candidates = list(csv.DictReader(stream))
    require(set(grouped) == {c['family_id'] for c in candidates}, 'Candidate family mismatch')
    for candidate in candidates:
        files = grouped[candidate['family_id']]
        require(len(files) == int(candidate['source_file_count']) and fingerprint(files) == candidate['source_sha256'],
                'Candidate family fingerprint mismatch')
    return {'archive_sha256': expected['archive_sha256'], 'source_file_count': len(hashes),
            'family_count': len(grouped), 'source_inventory_sha256': fingerprint(hashes),
            'archive_equivalence': 'verified', 'candidate_table_sha256': digest(table)}


def import_pilots(archive, extracted_root, root=ROOT):
    report = verify_archive(archive, extracted_root, root)
    config = read_json(root / 'config.json')
    manifest = read_json(root / 'corpus/manifest.json')
    selection_path = root / 'corpus/pilot_selection.json'
    selection = read_json(selection_path)
    records = {row['pair_id']: row for row in selection['decisions'] if row['decision'] == 'pilot'}
    require(set(records) == {'pilot-01', 'pilot-02'}, 'This reviewed import only supports the two pilot assignments')
    imported = {}
    with zipfile.ZipFile(archive) as zipped:
        for decision in selection['decisions']:
            for name in decision.get('evidence_sources', []):
                content = zipped.read('C/' + name)
                store(root / 'corpus/upstream' / name, content, readonly=True)
                imported[name] = sha(content)
        for pair in manifest['pairs']:
            if pair['pair_id'] not in records:
                continue
            decision = records[pair['pair_id']]
            pair_dir = f"corpus/pairs/{pair['pair_id']}"
            mapping = identifier_map(decision)
            transformations, diffs = [], []
            file_map = {decision['source']: pair_dir + '/unit.c', **SUPPORT}
            for original_name, sanitized_name in file_map.items():
                original_bytes = zipped.read('C/' + original_name)
                require(original_bytes == local_path(extracted_root, original_name).read_bytes(),
                        f'Changed extracted dependency: {original_name}')
                original = original_bytes.decode('utf-8')
                sanitized, changes = sanitize(original, mapping, INCLUDES, DIAGNOSTICS)
                scan_metadata(sanitized)
                store(root / 'corpus/upstream' / original_name, original_bytes, readonly=True)
                store(root / sanitized_name, sanitized)
                imported[original_name] = sha(original_bytes)
                transformations.append({'original': 'corpus/upstream/' + original_name,
                                        'sanitized': sanitized_name,
                                        'original_sha256': sha(original_bytes),
                                        'sanitized_sha256': sha(sanitized.encode()),
                                        'changes': changes,
                                        'executable_tokens_checked': verify_preservation(original, sanitized, mapping, INCLUDES, DIAGNOSTICS)})
                diffs.extend(difflib.unified_diff(original.splitlines(True), sanitized.splitlines(True),
                                                fromfile=original_name, tofile=sanitized_name))
            # Include the unmodified translation unit in a tiny external driver so its
            # selected static safe entry is callable without removing static or other paths.
            driver_name = pair_dir + '/driver.c'
            driver = '#include "unit.c"\nint main(void)\n{\n    process_case();\n    return 0;\n}\n'
            store(root / driver_name, driver)
            map_name = f"corpus/private/{pair['pair_id']}/sanitization.json"
            diff_name = f"corpus/private/{pair['pair_id']}/sanitization.diff"
            store(root / diff_name, ''.join(diffs))
            transformation = {'schema_version': 2, 'files': transformations,
                              'identifiers': mapping, 'includes': INCLUDES, 'diagnostics': DIAGNOSTICS,
                              'harness': {'path': driver_name, 'sha256': sha(driver.encode()),
                                          'category': 'external_harness_selection',
                                          'original_entries': decision['original_entries'],
                                          'reason': 'Directly select one original path, including static safe entries, without changing linkage or body.'},
                              'diff_path': diff_name, 'diff_sha256': digest(root / diff_name)}
            store(root / map_name, encode(transformation))
            sources = [pair_dir + '/unit.c', driver_name]
            support = ['corpus/support/output.c']
            headers = ['corpus/support/runtime.h', 'corpus/support/output.h']
            assigned = {key: pair[key] for key in ('pair_id', 'split', 'cwe', 'structure')}
            assigned.update({'status': 'assigned', 'family_id': decision['family_id'],
                             'upstream_case_id': Path(decision['source']).stem,
                             'sources': sources, 'support_sources': support, 'headers': headers,
                             'translation_units': [driver_name], 'include_dirs': ['corpus/support'],
                             'entries': {'vulnerable': 'process_case', 'safe': 'process_case'},
                             'variant_selection': {
                                 'vulnerable': {'defines': ['EXCLUDE_BRANCH_BETA'], 'driver_sources': [driver_name]},
                                 'safe': {'defines': ['EXCLUDE_BRANCH_ALPHA'], 'driver_sources': [driver_name]}},
                             'sanitization_manifest': map_name, 'selection_record': 'corpus/pilot_selection.json',
                             'file_sha256': {name: digest(root / name) for name in sources + support + headers + [map_name, 'corpus/pilot_selection.json']}})
            require(pair['status'] == 'unassigned' or pair == assigned, 'Existing assignment differs')
            pair.clear(); pair.update(assigned)
    validate_manifest(config, manifest, root, 'pilot')
    report.update({'imported_files': imported, 'selection_sha256': digest(selection_path),
                   'scope': 'Two development pilots only; final cases unassigned; no binary truth or inference.'})
    store(root / 'provenance/juliet-import.json', encode(report))
    (root / 'corpus/manifest.json').write_text(encode(manifest))
    return report


def verify_import(root=ROOT):
    report = read_json(root / 'provenance/juliet-import.json')
    require(digest(root / 'corpus/pilot_selection.json') == report['selection_sha256'], 'Selection record changed')
    for name, expected in report['imported_files'].items():
        path = local_path(root, 'corpus/upstream/' + name)
        require(digest(path) == expected, f'Upstream bytes changed: {name}')
        require(path.stat().st_mode & 0o222 == 0, 'Upstream copy is writable')
    config, manifest = read_json(root / 'config.json'), read_json(root / 'corpus/manifest.json')
    validate_manifest(config, manifest, root, 'pilot')
    count = 0
    for pair in manifest['pairs']:
        if pair['split'] != 'pilot':
            continue
        mapping = read_json(root / pair['sanitization_manifest'])
        for file in mapping['files']:
            original = local_path(root, file['original']).read_bytes().decode()
            sanitized = local_path(root, file['sanitized']).read_bytes().decode()
            require(sha(original.encode()) == file['original_sha256'] and sha(sanitized.encode()) == file['sanitized_sha256'],
                    'Transformation file hash mismatch')
            verify_preservation(original, sanitized, mapping['identifiers'], mapping['includes'], mapping['diagnostics'])
            scan_metadata(sanitized)
            count += 1
        require(digest(local_path(root, mapping['diff_path'])) == mapping['diff_sha256'], 'Diff changed')
        require(digest(local_path(root, mapping['harness']['path'])) == mapping['harness']['sha256'], 'Harness changed')
    return {'status': 'verified', 'transformation_checks': count,
            'upstream_files': len(report['imported_files'])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('import', 'verify'))
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--extracted-root', type=Path)
    args = parser.parse_args()
    if args.command == 'import':
        require(args.archive and args.extracted_root, 'Import requires --archive and --extracted-root')
        import_pilots(args.archive, args.extracted_root)
    print(encode(verify_import()), end='')


if __name__ == '__main__':
    main()
