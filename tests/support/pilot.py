"""Synthetic pilot builders."""
from .parent import put
from optimization_vuln_analysis.studies.representation import pilot
from optimization_vuln_analysis.inputs.corpus import digest, generate, read_json


def build_accepted(parent_fixture):
    root, _, _ = parent_fixture
    plan = generate(read_json(root/'config.json'), read_json(root/'corpus/manifest.json'), root, 'pilot', True)
    bundle = next((root/'data/final/records').glob('*.json')).read_bytes()
    hashes, extracted = {}, []
    for row in plan['observations']:
        path = put(root, row['record_path'], bundle)
        hashes[row['observation_id']] = digest(path)
        extracted.append({**row, 'record_sha256': digest(path), 'status': 'available'})
    put(root, pilot.SOURCES[2], {'split': 'pilot', 'plan': plan,
        'config_sha256': digest(root/'config.json'), 'manifest_sha256': digest(root/'corpus/manifest.json')})
    put(root, pilot.SOURCES[3], {'split': 'pilot', 'plan': plan, 'observations': extracted,
                                'build_manifest_sha256': digest(root/pilot.SOURCES[2])})
    put(root, pilot.SOURCES[4], {'split': 'pilot', 'inputs': hashes})
    return root

