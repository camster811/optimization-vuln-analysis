"""Phase 1 matrix, isolation, and readiness regression checks."""
from copy import deepcopy
import json
import shutil
import subprocess

import pytest

from redesign.pipeline import inventory as inv


def declared():
    return inv.read_json(inv.ROOT / 'config.json'), inv.read_json(inv.ROOT / 'corpus/manifest.json')


@pytest.fixture
def tiny(tmp_path):
    config, _ = declared()
    config['splits'] = {
        split: {cwe: {'intraprocedural': int(cwe == 'CWE-121'), 'interprocedural': 0}
                for cwe in ('CWE-121', 'CWE-122')} for split in ('pilot', 'final')}
    pairs = []
    for split in config['splits']:
        names = [f'{split}/entry.c', f'{split}/helper.c', f'{split}/mapping.json', f'{split}/selection.json']
        for name in names:
            path = tmp_path / name
            path.parent.mkdir(exist_ok=True)
            path.write_text('{}' if name.endswith('.json') else 'int example(void) { return 0; }\n')
        pairs.append({'pair_id': f'example-{split}', 'split': split, 'cwe': 'CWE-121',
                      'structure': 'intraprocedural', 'status': 'assigned',
                      'family_id': f'family-{split}', 'upstream_case_id': f'fixture-{split}',
                      'sources': names[:2], 'support_sources': [],
                      'entries': {'vulnerable': 'entry_one', 'safe': 'entry_two'},
                      'variant_selection': {v: {'defines': [], 'driver_sources': []}
                                            for v in config['matrix']['variants']},
                      'sanitization_manifest': names[2], 'selection_record': names[3],
                      'file_sha256': {name: inv.digest(tmp_path / name) for name in names}})
    return config, {'schema_version': 2, 'pairs': pairs}, tmp_path


def test_shipped_matrix_and_readiness():
    config, manifest = declared()
    assert inv.generate(config, manifest, split='pilot')['counts'] == {
        'pairs': 2, 'reference_builds': 16, 'observations': 32, 'inference_slots': 96}
    assert inv.generate(config, manifest)['counts'] == {
        'pairs': 10, 'reference_builds': 80, 'observations': 160, 'inference_slots': 480}
    with pytest.raises(ValueError, match='Unassigned'):
        inv.generate(config, manifest, require_assigned=True)


def test_synthetic_complete_four_level_matrix(tiny):
    config, manifest, root = tiny
    result = inv.generate(config, manifest, root, require_assigned=True)
    assert result['counts'] == {'pairs': 1, 'reference_builds': 8, 'observations': 16, 'inference_slots': 48}
    assert {row['optimization'] for row in result['observations']} == {'O0', 'O1', 'O2', 'O3'}
    assert all(sum(r['build_id'] == b['build_id'] for r in result['observations']) == 2
               for b in result['builds'])
    assert inv.encode(result) == inv.encode(inv.generate(config, manifest, root))
    # Reordering manifests does not renumber observations or alter serialization.
    manifest['pairs'].reverse()
    assert inv.encode(result) == inv.encode(inv.generate(config, manifest, root))


@pytest.mark.parametrize('mutation', ['missing', 'duplicate', 'unexpected', 'altered'])
def test_matrix_rejects_invalid_cells(tiny, mutation):
    config, manifest, root = tiny
    expected = inv.generate(config, manifest, root)['observations']
    actual = deepcopy(expected)
    if mutation == 'missing':
        actual.pop()
    elif mutation == 'duplicate':
        actual.append(actual[0])
    elif mutation == 'unexpected':
        extra = deepcopy(actual[0]); extra['observation_id'] = 'unexpected'; actual.append(extra)
    else:
        actual[0]['optimization'] = 'O3'
    with pytest.raises(ValueError):
        inv.check_cells(expected, actual, 'observation_id')


def test_dynamic_dimensions_and_repetitions(tiny):
    config, manifest, root = tiny
    config['matrix']['optimizations'] = ['O0', 'O1', 'O3']
    config['compiler']['optimizations'] = ['O0', 'O1', 'O3']
    config['inference']['seeds'] = [99]
    result = inv.generate(config, manifest, root)
    assert result['counts']['observations'] == 12
    assert result['counts']['inference_slots'] == 12
    assert result['dimensions']['optimizations'] == ['O0', 'O1', 'O3']


def test_actual_loaded_records_checked(tiny):
    config, manifest, root = tiny
    result = inv.generate(config, manifest, root)
    for row in result['observations']:
        path = root / row['record_path']; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('{}')
    assert len(inv.check_record_inventory(result, root)) == 16
    with pytest.raises(ValueError):
        inv.check_record_inventory(result, root / 'different-inputs')
    extra = root / 'data/final/records/extra.txt'; extra.write_text('extra')
    with pytest.raises(ValueError):
        inv.check_record_inventory(result, root)
    extra.unlink()
    (root / result['observations'][0]['record_path']).unlink()
    with pytest.raises(ValueError):
        inv.check_record_inventory(result, root)


@pytest.mark.parametrize('mutation', ['family', 'path', 'hash', 'quota', 'pair', 'version'])
def test_manifest_rejects_invalid_assignments(tiny, mutation):
    config, manifest, root = tiny
    pair = manifest['pairs'][0]
    if mutation == 'family': manifest['pairs'][1]['family_id'] = pair['family_id']
    if mutation == 'path': pair['sanitization_manifest'] = '../outside.json'
    if mutation == 'hash': (root / pair['sources'][0]).write_text('changed')
    if mutation == 'quota': manifest['pairs'].pop()
    if mutation == 'pair': manifest['pairs'].append(deepcopy(pair))
    if mutation == 'version': manifest['schema_version'] = 1
    with pytest.raises(ValueError): inv.generate(config, manifest, root)


def test_pilot_assignment_does_not_require_final(tiny):
    config, manifest, root = tiny
    pair = manifest['pairs'][1]
    manifest['pairs'][1] = {key: pair[key] for key in ('pair_id', 'split', 'cwe', 'structure')}
    manifest['pairs'][1]['status'] = 'unassigned'
    inv.generate(config, manifest, root, split='pilot', require_assigned=True)
    with pytest.raises(ValueError, match='Unassigned'):
        inv.generate(config, manifest, root, require_assigned=True)


def test_strict_json_and_path_containment(tmp_path):
    for text in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}'):
        with pytest.raises(ValueError): inv.strict_json(text)
    for name in ('../escape', '/absolute', 'C:/external', 'folder\\file'):
        with pytest.raises(ValueError): inv.local_path(tmp_path, name)
    external = tmp_path.parent / 'external-target'
    external.mkdir(exist_ok=True)
    (tmp_path / 'link').symlink_to(external, target_is_directory=True)
    with pytest.raises(ValueError): inv.local_path(tmp_path, 'link/file.json')


def test_synthetic_builds_all_declared_treatments(tmp_path):
    """Exercise the declared flags and derivation on real GCC-produced artifacts."""
    config, _ = declared()
    compiler = shutil.which(config['compiler']['name'])
    if not compiler or not shutil.which('objcopy') or not shutil.which('strip'):
        pytest.skip('GCC/binutils integration tools unavailable')
    assert subprocess.check_output([compiler, '-dumpfullversion'], text=True).strip() == config['compiler']['expected_version']
    (tmp_path / 'entry.c').write_text('extern int helper(int); int main(void) { return helper(VALUE); }\n')
    (tmp_path / 'helper.c').write_text('int helper(int x) { return x + 1; }\n')
    flags = [flag.replace('{workspace}', str(tmp_path)) for flag in config['compiler']['common_flags']]
    artifacts = []
    for variant in config['matrix']['variants']:
        for opt in config['matrix']['optimizations']:
            directory = tmp_path / variant / opt
            directory.mkdir(parents=True)
            objects = []
            for source in ('entry', 'helper'):
                target = directory / f'{source}.o'
                subprocess.run([compiler, *flags, f'-{opt}', f'-DVALUE={int(variant == "safe")}',
                                '-c', str(tmp_path / f'{source}.c'), '-o', str(target)], check=True,
                               capture_output=True)
                objects.append(str(target))
            oracle = directory / 'oracle'
            subprocess.run([compiler, f'-{opt}', *objects, *config['compiler']['link_flags'],
                            '-o', str(oracle)], check=True, capture_output=True)
            retained, stripped = directory / 'retained', directory / 'stripped'
            subprocess.run(['objcopy', '--strip-debug', str(oracle), str(retained)], check=True)
            subprocess.run(['strip', '--strip-all', '-o', str(stripped), str(retained)], check=True)
            text_hashes = []
            for binary in (oracle, retained, stripped):
                output = directory / f'{binary.name}.text'
                subprocess.run(['objcopy', '--dump-section', f'.text={output}', str(binary)], check=True)
                text_hashes.append(inv.digest(output))
            assert len(set(text_hashes)) == 1
            artifacts.extend([retained, stripped])
    assert len(artifacts) == (len(config['matrix']['variants']) * len(config['matrix']['optimizations'])
                              * len(config['matrix']['symbols']))
