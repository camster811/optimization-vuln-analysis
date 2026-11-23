"""Synthetic parent builders."""
from collections import Counter
from copy import deepcopy
import hashlib
from itertools import product
import struct
import tarfile
from optimization_vuln_analysis.studies.representation import inventory as study
from optimization_vuln_analysis.common.resources import resource
from optimization_vuln_analysis.inputs import bundles
from optimization_vuln_analysis.inputs import parent as parent_input
from optimization_vuln_analysis.inputs.corpus import ROOT, digest, encode, generate, read_json


def put(root, name, value):
    path = root/name
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.chmod(0o644)
    path.write_bytes(value if isinstance(value, bytes) else encode(value).encode())
    return path


def seal(parent, policy, policy_path):
    """Create a small independently pinned fixture release, including coherent private bindings."""
    build = read_json(parent/parent_input.FILES[2])
    oracle = read_json(parent/parent_input.FILES[3])
    dispositions = read_json(parent/parent_input.FILES[4])
    extraction_name = 'build/final/context/fixture/extraction-manifest.json'
    extraction = read_json(parent/extraction_name)
    for value in (build, oracle):
        value.update(config_sha256=digest(parent/'config.json'), manifest_sha256=digest(parent/'corpus/manifest.json'))
    put(parent, parent_input.FILES[2], build)
    put(parent, parent_input.FILES[3], oracle)
    for value in (dispositions, extraction):
        value.update(build_manifest_sha256=digest(parent/parent_input.FILES[2]),
                     oracle_sha256=digest(parent/parent_input.FILES[3]))
    put(parent, parent_input.FILES[4], dispositions)
    put(parent, extraction_name, extraction)
    files = {p.relative_to(parent).as_posix(): digest(p) for p in sorted(parent.rglob('*'))
             if p.is_file() and p.relative_to(parent).parts[0] != 'release'}
    archive = parent/'release/inputs.tar.gz'
    archive.parent.mkdir(exist_ok=True)
    with tarfile.open(archive, 'w:gz') as stream:
        for name in files:
            stream.add(parent/name, arcname=name, recursive=False)
    freeze = {'schema_version': 1, 'freeze_id': 'fixture-final', 'status': 'frozen_before_predictions',
              'files': files, 'archive': 'release/inputs.tar.gz', 'archive_sha256': digest(archive)}
    put(parent, 'release/freeze.json', freeze)
    policy['parent'].update(freeze_id=freeze['freeze_id'], freeze_manifest='release/freeze.json',
                            freeze_manifest_sha256=digest(parent/'release/freeze.json'),
                            input_archive=freeze['archive'], input_archive_sha256=freeze['archive_sha256'],
                            llm_policy_sha256=digest(parent/'llm_policy.json'))
    put(policy_path.parent, policy_path.name, policy)


def build_parent(tmp_path):
    parent = tmp_path/'parent'
    config = read_json(ROOT/'config.json')
    config['splits'] = {split: {cwe: {'intraprocedural': 1, 'interprocedural': 0}
                               for cwe in ('CWE-121', 'CWE-122')} for split in ('pilot', 'final')}
    pairs = []
    for split, cwe in product(('pilot', 'final'), ('CWE-121', 'CWE-122')):
        pair_id = split+'-'+cwe[-3:]
        names = [f'corpus/{pair_id}/{name}' for name in ('unit.c', 'sanitization.json', 'selection.json')]
        for name in names:
            put(parent, name, b'int entry(void) { return 0; }\n' if name.endswith('.c') else {})
        pairs.append({'pair_id': pair_id, 'family_id': 'family-'+pair_id, 'cwe': cwe,
                      'split': split, 'structure': 'intraprocedural', 'status': 'assigned',
                      'upstream_case_id': 'fixture-'+pair_id, 'entries': {'safe': 'entry', 'vulnerable': 'entry'},
                      'sources': names[:1], 'support_sources': [], 'sanitization_manifest': names[1],
                      'selection_record': names[2], 'file_sha256': {n: digest(parent/n) for n in names},
                      'variant_selection': {v: {'defines': [], 'driver_sources': []} for v in ('safe', 'vulnerable')}})
    put(parent, 'config.json', config)
    put(parent, 'corpus/manifest.json', {'schema_version': 2, 'pairs': pairs})
    put(parent, 'llm_policy.json', read_json(ROOT/'llm_policy.json'))
    schema = read_json(resource('inputs/schemas/bundle-v2.json'))
    put(parent, 'schemas/bundle-v2.json', schema)
    plan = generate(config, {'schema_version': 2, 'pairs': pairs}, parent, 'final', True)
    bundle = bundles.empty_bundle('0x1000', 'entry_unavailable')
    bundle['status'] = 'available'
    bundle['completeness'].update(traversal='complete', data='complete', decompilation='complete', omissions=[])
    bundle['functions'] = [{'entry': '0x1000', 'name': 'entry', 'name_origin': 'analysis',
                            'ranges': [{'start': '0x1000', 'end': '0x1001'}],
                            'instructions': [{'address': '0x1000', 'bytes': 'c3', 'size': 1,
                                              'mnemonic': 'RET', 'operands': ''}],
                            'decompilation': {'status': 'ok', 'text': 'void entry(void) { return; }\n'}}]
    # A minimal real ELF load image checks bundle bytes without compiler/tool dependencies.
    elf = struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF\x02\x01'+b'\0'*10,
                      2, 62, 1, 0x1000, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    elf += struct.pack('<IIQQQQQQ', 1, 5, 120, 0x1000, 0x1000, 1, 1, 1)+b'\xc3'
    builds, reviews, judgments, extracted = [], [], [], []
    pair_map = {p['pair_id']: p for p in pairs}
    for cell in plan['builds']:
        build = deepcopy(cell)
        build.update(status='built', evidence_directory=f"build/final/private/{cell['build_id']}")
        build['artifacts'] = {}
        for kind in ('reference', 'retained', 'stripped'):
            name = cell['reference_path'] if kind == 'reference' else f"build/final/{kind}/{cell['build_id']}"
            path = put(parent, name, elf)
            build['artifacts'][kind] = {'path': name, 'sha256': digest(path)}
        evidence = put(parent, build['evidence_directory']+'/assembly.txt', b'0x1000 RET\n')
        build['evidence'] = {'files': {'assembly.txt': digest(evidence)}}
        builds.append(build)
        cwe = pair_map[cell['pair_id']]['cwe']
        label = 'not_vulnerable' if cell['variant'] == 'safe' else 'vulnerable_'+cwe
        reviews.append({'build_id': cell['build_id'], 'cwe': cwe, 'source_label': label, 'binary_label': label,
                        'operation_status': 'present', 'reference_sha256': build['artifacts']['reference']['sha256'],
                        'evidence_sha256': build['evidence']['files'], 'mapping': {'entry_address': 0x1000},
                        'facts': {'path': {'instruction_addresses': [0x1000]}}, 'conclusion': 'fixture judgment'})
    by_id = {r['build_id']: r for r in reviews}
    for cell in plan['observations']:
        raw = bundles.canonical(bundle).encode()
        put(parent, cell['record_path'], raw)
        review = by_id[cell['build_id']]
        judgments.append({**cell, **{k: review[k] for k in ('binary_label', 'source_label', 'operation_status')},
                          'review_build_id': cell['build_id']})
        extracted.append({**cell, 'record_sha256': hashlib.sha256(raw).hexdigest(),
                          'analysis_sha256': hashlib.sha256(elf).hexdigest(), 'entry_address': '0x1000',
                          'status': 'available'})
    put(parent, parent_input.FILES[2], {'split': 'final', 'plan': plan, 'builds': builds})
    put(parent, parent_input.FILES[3], {'schema_version': 3, 'split': 'final', 'reviews': reviews})
    put(parent, parent_input.FILES[4], {'schema_version': 3, 'split': 'final', 'observations': judgments})
    put(parent, 'build/final/context/fixture/extraction-manifest.json', {'plan': plan, 'observations': extracted})
    policy = read_json(study.POLICY)
    policy['matrix'].update(families=2, families_per_source_cwe={'CWE-121': 1, 'CWE-122': 1},
                            reference_builds=16, observations=32, observation_condition_units=96, final_slots=288)
    policy['evaluation'].update(expected_adjudicated=32, expected_control_correct=16,
                                expected_binary_label_counts=dict(Counter(r['binary_label'] for r in judgments)))
    policy_path = tmp_path/'fixture-policy.json'
    seal(parent, policy, policy_path)
    return parent, policy, policy_path

