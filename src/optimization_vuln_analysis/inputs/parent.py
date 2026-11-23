"""Interpret the accepted historical parent format without study scheduling."""
from collections import Counter
import hashlib
from pathlib import Path
import tarfile

from optimization_vuln_analysis.common.artifacts import bytes_digest, plain_file, digest, local_path
from optimization_vuln_analysis.common.serialization import canonical_json, read_json, strict_json
from optimization_vuln_analysis.inputs import bundles
from optimization_vuln_analysis.inputs.corpus import IDENTIFIER, check_record_inventory, generate
from optimization_vuln_analysis.common import require


FILES = ('config.json', 'corpus/manifest.json', 'build/final/build-manifest.json',
                'corpus/private/final-oracle.json', 'build/final/dispositions.json',
                'schemas/bundle-v2.json')


def verify(parent, policy):
    """Check every released file and archive member without extracting or executing it."""
    binding = policy['parent']
    freeze_path = plain_file(parent, binding['freeze_manifest'])
    require(digest(freeze_path) == binding['freeze_manifest_sha256'], 'Parent freeze changed')
    freeze = read_json(freeze_path)
    require(freeze['schema_version'] == 1 and freeze['freeze_id'] == binding['freeze_id']
            and freeze['status'] == 'frozen_before_predictions', 'Unexpected parent freeze')
    require(freeze['archive'] == binding['input_archive']
            and freeze['archive_sha256'] == binding['input_archive_sha256'], 'Parent archive binding differs')
    files = freeze['files']
    require(files and files[binding['llm_policy']] == binding['llm_policy_sha256'],
            'Parent policy binding differs')
    for name, expected in files.items():
        require(digest(plain_file(parent, name)) == expected, f'Changed parent input: {name}')
    archive = plain_file(parent, binding['input_archive'])
    require(digest(archive) == binding['input_archive_sha256'], 'Parent archive changed')
    seen = set()
    with tarfile.open(archive, 'r|gz') as stream:
        for member in stream:
            local_path(parent, member.name)
            require(member.isfile() and member.name in files and member.name not in seen,
                    f'Unexpected/duplicate/nonregular archive member: {member.name}')
            seen.add(member.name)
            with stream.extractfile(member) as content:
                require(hashlib.file_digest(content, 'sha256').hexdigest() == files[member.name],
                        f'Archive content differs: {member.name}')
    require(seen == set(files), 'Parent archive membership differs')
    return freeze


def _indexed(rows, key, expected=None):
    result = {row[key]: row for row in rows}
    require(len(result) == len(rows), f'Duplicate {key}')
    if expected is not None:
        require(set(result) == set(expected), f'Missing/unexpected {key}')
    return result


def bind(policy, documents, public, frozen_files):
    """Join only bound metadata; keep truth out of observation/condition/slot construction."""
    config, corpus, builds, oracle, dispositions, schema = (documents[n] for n in FILES)
    plan = builds['plan']
    matrix = policy['matrix']
    pairs = _indexed([p for p in corpus['pairs'] if p['split'] == 'final'], 'pair_id')
    require(len(pairs) == matrix['families'] and len({p['family_id'] for p in pairs.values()}) == len(pairs),
            'Final family inventory differs')
    require(Counter(p['cwe'] for p in pairs.values()) == matrix['families_per_source_cwe'],
            'Source CWE quotas differ')
    for field in ('variants', 'optimizations', 'symbols'):
        require(config['matrix'][field] == matrix[field], f'Parent {field} matrix differs')
    planned = _indexed(plan['observations'], 'observation_id')
    require(len(planned) == matrix['observations'] and set(public) == set(planned),
            'Observation inventory differs')
    cells = _indexed(builds['builds'], 'build_id')
    require(len(cells) == matrix['reference_builds'], 'Reference-build inventory differs')
    require(oracle['schema_version'] == dispositions['schema_version'] == 3
            and builds['split'] == oracle['split'] == dispositions['split'] == 'final', 'Private schema/split differs')
    for document in (builds, oracle):
        require(document['config_sha256'] == frozen_files['config.json']
                and document['manifest_sha256'] == frozen_files['corpus/manifest.json'],
                'Private source/config binding differs')
    require(dispositions['build_manifest_sha256'] == frozen_files[FILES[2]]
            and dispositions['oracle_sha256'] == frozen_files[FILES[3]], 'Disposition binding differs')
    reviews = _indexed(oracle['reviews'], 'build_id', cells)
    judged = _indexed(dispositions['observations'], 'observation_id', planned)
    extraction_name = next(n for n in documents if n.endswith('/extraction-manifest.json'))
    extraction = documents[extraction_name]
    require(extraction['plan'] == plan
            and extraction['build_manifest_sha256'] == frozen_files[FILES[2]]
            and extraction['oracle_sha256'] == frozen_files[FILES[3]], 'Extraction binding differs')
    extracted = _indexed(extraction['observations'], 'observation_id', planned)
    observations, evaluation = [], []
    treatments = set()
    for obs, cell in sorted(planned.items()):
        require(IDENTIFIER.fullmatch(obs), 'Invalid observation ID')
        pair = pairs[cell['pair_id']]
        build = cells[cell['build_id']]
        review = reviews[cell['build_id']]
        for field in ('pair_id', 'variant', 'optimization'):
            require(cell[field] == build[field], f'Build treatment differs: {obs}')
        treatment = (pair['family_id'], cell['variant'], cell['optimization'], cell['symbols'])
        require(treatment not in treatments, 'Duplicate treatment cell')
        treatments.add(treatment)
        require(cell['variant'] in matrix['variants'] and cell['optimization'] in matrix['optimizations']
                and cell['symbols'] in matrix['symbols'], 'Unknown treatment cell')
        require(build['status'] == 'built', 'Parent reference build unavailable')
        artifact = build['artifacts'][cell['symbols']]
        require(artifact['path'] == cell['analysis_path']
                and frozen_files[artifact['path']] == artifact['sha256']
                and frozen_files[build['artifacts']['reference']['path']] == review['reference_sha256']
                == build['artifacts']['reference']['sha256'], 'Stale binary review binding')
        require(review['evidence_sha256'] == build['evidence']['files'], 'Stale private evidence binding')
        for name, expected in review['evidence_sha256'].items():
            require(frozen_files[f"{build['evidence_directory']}/{name}"] == expected,
                    'Private evidence release binding differs')
        require(review['cwe'] == pair['cwe'] and review['source_label'] ==
                ('vulnerable_'+pair['cwe'] if cell['variant'] == 'vulnerable' else 'not_vulnerable'),
                'Source label/provenance differs')
        require(review['binary_label'] in {'vulnerable_CWE-121', 'vulnerable_CWE-122', 'not_vulnerable', 'unresolved'}
                and review['operation_status'] in {'present', 'inlined/merged', 'eliminated', 'unresolved'},
                'Unknown private judgment')
        require(all(judged[obs][k] == v for k, v in cell.items())
                and judged[obs]['review_build_id'] == cell['build_id']
                and all(judged[obs][k] == review[k] for k in ('binary_label', 'source_label', 'operation_status')),
                'Observation judgment differs from bound review')
        record_hash = hashlib.sha256(public[obs]).hexdigest()
        require(frozen_files[cell['record_path']] == record_hash, 'Public bundle binding differs')
        bundle = strict_json(public[obs].decode('utf-8'))
        bundles.validate(bundle, schema=schema)
        require(bundles.canonical(bundle).encode('utf-8') == public[obs], 'Noncanonical public bundle bytes')
        row = extracted[obs]
        require(all(row[k] == v for k, v in cell.items()) and row['record_sha256'] == record_hash
                and row['analysis_sha256'] == artifact['sha256'] and row['status'] == bundle['status']
                and row['entry_address'] == bundle['entry_address'] == hex(review['mapping']['entry_address']),
                'Public extraction/localization binding differs')
        bundles.evidence_addresses(bundle, [hex(a) for fact in review['facts'].values()
                                           for a in fact['instruction_addresses']])
        observation = {**cell, 'family_id': pair['family_id'], 'cwe': pair['cwe'], 'structure': pair['structure'],
                       'bundle_path': f'public/bundles/{obs}.json', 'parent_bundle_sha256': record_hash,
                       'reference_sha256': review['reference_sha256'], 'analysis_sha256': artifact['sha256']}
        observations.append(observation)
        evaluation.append({**observation, **{k: review[k] for k in ('binary_label', 'source_label', 'operation_status')},
                           'review_sha256': bytes_digest(canonical_json(review).encode('utf-8'))})
    expected_cells = matrix['families']
    for field in ('variants', 'optimizations', 'symbols'):
        expected_cells *= len(matrix[field])
    require(len(treatments) == expected_cells == matrix['observations'], 'Incomplete treatment matrix')
    require(Counter(r['binary_label'] for r in evaluation) == policy['evaluation']['expected_binary_label_counts'],
            'Parent truth inventory differs; documented repair required')
    return observations, evaluation


def read(parent, policy):
    """Validate the full parent release and load its accepted public bundles."""
    parent = Path(parent).resolve()
    freeze = verify(parent, policy)
    extraction = [n for n in freeze['files'] if n.endswith('/extraction-manifest.json')]
    require(len(extraction) == 1, 'Ambiguous parent extraction manifest')
    names = (*FILES, extraction[0])
    documents = {n: read_json(plain_file(parent, n)) for n in names}
    build_report = documents[FILES[2]]
    expected = generate(documents['config.json'], documents['corpus/manifest.json'], parent, 'final', True)
    require(expected == build_report['plan'], 'Frozen build plan differs from declared parent matrix')
    check_record_inventory(expected, parent)
    public = {}
    for row in expected['observations']:
        raw = plain_file(parent, row['record_path']).read_bytes()
        bundles.validate(strict_json(raw.decode('utf-8')), binary=plain_file(parent, row['analysis_path']),
                         schema=documents['schemas/bundle-v2.json'])
        public[row['observation_id']] = raw
    return {'documents': documents, 'bundles': public, 'freeze': freeze, 'staged_files': names}
