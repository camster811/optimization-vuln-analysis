"""Parent binding, condition isolation and label-independent preparation contracts."""
import hashlib
import io
from itertools import product
import tarfile

import pytest
from jsonschema import ValidationError

from optimization_vuln_analysis.studies.representation import inventory as study
from optimization_vuln_analysis.inputs import bundles
from optimization_vuln_analysis.inputs import parent as parent_input
from optimization_vuln_analysis.inputs.corpus import digest, read_json
from tests.support.parent import put, seal


def test_complete_deterministic_isolated_stage_and_offline_verify(parent_fixture, tmp_path, monkeypatch):
    parent, policy, policy_path = parent_fixture
    import requests
    monkeypatch.setattr(requests, 'Session', lambda: pytest.fail('Preparation attempted network access'))
    first, second = tmp_path/'one', tmp_path/'two'
    result = study.prepare(parent, first, policy_path)
    assert result['counts'] == dict(families=2, reference_builds=16, observations=32,
                                  observation_condition_units=96, final_slots=288)
    study.prepare(parent, second, policy_path)
    assert {p.relative_to(first): p.read_bytes() for p in first.rglob('*') if p.is_file()} == {
        p.relative_to(second): p.read_bytes() for p in second.rglob('*') if p.is_file()}
    observations = read_json(first/'coordinator/observations.json')
    assert {r['observation_id'] for r in observations} == {
        r['observation_id'] for r in read_json(parent/parent_input.FILES[2])['plan']['observations']}
    assert all('binary_label' not in row and 'source_label' not in row for row in observations)
    assert all(p.parts[-3] == 'public' for p in (first/'public/bundles').glob('*.json'))
    assert not list((first/'public').rglob('*oracle*'))
    assert all(not (p.stat().st_mode & 0o222) for p in first.rglob('*') if p.is_file())
    parent.rename(tmp_path/'parent-unavailable')
    assert study.verify(first, result['manifest_sha256']) == result
    with pytest.raises(ValueError, match='Preparation manifest changed'):
        study.verify(first, '0'*64)
    with pytest.raises(ValueError, match='destination already exists'):
        study.prepare(parent, first, policy_path)


def test_schedule_and_paths_are_condition_qualified(parent_fixture, tmp_path):
    parent, policy, policy_path = parent_fixture
    destination = tmp_path/'stage'
    study.prepare(parent, destination, policy_path)
    slots = read_json(destination/'coordinator/slots.json')
    conditions = read_json(destination/'coordinator/conditions.json')
    assert len({s['slot_id'] for s in slots}) == len({s['slot_path'] for s in slots}) == 288
    assert len({c['condition_id'] for c in conditions}) == len({c['view_path'] for c in conditions}) == 96
    for row in conditions:
        assert '/'+row['representation']+'/' in row['view_path']
        assert '/'+row['representation']+'/' in row['aggregate_path']
    # Independently specify the block shuffle instead of copying the stored order keys.
    ids = sorted({s['observation_id'] for s in slots})
    key = lambda obs, rep: f'20261121\n{obs}\n{rep}'
    sha = lambda text: hashlib.sha256(text.encode()).hexdigest()
    blocks = sorted(product(ids, (1, 2, 3)), key=lambda b: (sha(key(*b)), *b))
    expected = [(obs, condition, rep) for obs, rep in blocks for condition in sorted(
        ('assembly', 'decompilation', 'combined'), key=lambda c: (sha(key(obs, rep)+'\n'+c), c))]
    assert [(s['observation_id'], s['representation'], s['repetition']) for s in slots] == expected
    for s in slots:
        assert s['seed'] == (4101, 4102, 4103)[s['repetition']-1]
        assert '/'+s['representation']+'/' in s['slot_path']


@pytest.mark.parametrize('mutation', ['missing', 'changed', 'extra_record', 'symlink', 'archive'])
def test_untrusted_parent_fails_before_destination_creation(parent_fixture, tmp_path, mutation):
    parent, policy, policy_path = parent_fixture
    record = next((parent/'data/final/records').glob('*.json'))
    if mutation == 'missing': record.unlink()
    if mutation == 'changed': record.write_bytes(record.read_bytes()+b' ')
    if mutation == 'extra_record': put(parent, 'data/final/records/extra.json', {})
    if mutation == 'symlink':
        raw = record.read_bytes(); record.unlink()
        record.symlink_to(put(tmp_path, 'external.json', raw))
    if mutation == 'archive':
        with (parent/'release/inputs.tar.gz').open('ab') as stream: stream.write(b'changed')
    destination = tmp_path/'rejected'
    with pytest.raises(ValueError): study.prepare(parent, destination, policy_path)
    assert not destination.exists()


@pytest.mark.parametrize('mutation', ['missing', 'extra', 'duplicate', 'symlink', 'changed_content'])
def test_archive_membership_and_content_checked_even_with_pinned_archive(parent_fixture, tmp_path, mutation):
    parent, policy, policy_path = parent_fixture
    path = parent/'release/inputs.tar.gz'
    with tarfile.open(path) as stream:
        entries = [(member, stream.extractfile(member).read()) for member in stream.getmembers()]
    original = entries[0]
    if mutation == 'missing': entries.pop(0)
    if mutation == 'duplicate': entries.append(original)
    if mutation == 'extra':
        member = tarfile.TarInfo('unexpected.json'); member.size = 2
        entries.append((member, b'{}'))
    if mutation == 'changed_content':
        member, raw = entries[0]; raw += b'changed'; member.size = len(raw); entries[0] = (member, raw)
    if mutation == 'symlink':
        member, raw = entries[0]; member.type = tarfile.SYMTYPE; member.linkname = '/external'; member.size = 0
    with tarfile.open(path, 'w:gz') as stream:
        for member, raw in entries: stream.addfile(member, io.BytesIO(raw))
    freeze = read_json(parent/'release/freeze.json'); freeze['archive_sha256'] = digest(path)
    put(parent, 'release/freeze.json', freeze)
    policy['parent'].update(input_archive_sha256=digest(path),
                            freeze_manifest_sha256=digest(parent/'release/freeze.json'))
    put(policy_path.parent, policy_path.name, policy)
    with pytest.raises(ValueError, match='archive|Archive'):
        study.prepare(parent, tmp_path/'rejected', policy_path)
    assert not (tmp_path/'rejected').exists()


@pytest.mark.parametrize('mutation', ['instruction_bytes', 'noncanonical_bytes', 'nested_private_field'])
def test_public_validation_is_reused_after_hash_binding(parent_fixture, tmp_path, mutation):
    parent, policy, policy_path = parent_fixture
    record = next((parent/'data/final/records').glob('*.json'))
    if mutation == 'noncanonical_bytes': record.write_bytes(record.read_bytes()+b' ')
    else:
        value = read_json(record)
        if mutation == 'instruction_bytes': value['functions'][0]['instructions'][0]['bytes'] = '90'
        else: value['functions'][0]['private_capacity'] = 100
        record.write_bytes(bundles.canonical(value).encode())
    seal(parent, policy, policy_path)
    with pytest.raises((ValueError, ValidationError)):
        study.prepare(parent, tmp_path/'rejected', policy_path)
    assert not (tmp_path/'rejected').exists()


@pytest.mark.parametrize('mutation', ['duplicate_observation', 'altered_treatment', 'duplicate_review',
                                     'stale_reference', 'stale_evidence', 'judgment', 'extraction'])
def test_semantically_inconsistent_bound_metadata_rejected(parent_fixture, tmp_path, mutation):
    parent, policy, policy_path = parent_fixture
    builds = read_json(parent/parent_input.FILES[2])
    oracle = read_json(parent/parent_input.FILES[3])
    if mutation == 'duplicate_observation': builds['plan']['observations'].append(builds['plan']['observations'][0])
    if mutation == 'altered_treatment': builds['plan']['observations'][0]['optimization'] = 'O3'
    if mutation == 'duplicate_review': oracle['reviews'].append(oracle['reviews'][0])
    if mutation == 'stale_reference': oracle['reviews'][0]['reference_sha256'] = '0'*64
    if mutation == 'stale_evidence': oracle['reviews'][0]['evidence_sha256'] = {'assembly.txt': '0'*64}
    if mutation == 'judgment':
        value = read_json(parent/parent_input.FILES[4]); value['observations'][0]['binary_label'] = 'not_vulnerable'
        put(parent, parent_input.FILES[4], value)
    if mutation == 'extraction':
        name = 'build/final/context/fixture/extraction-manifest.json'
        value = read_json(parent/name); value['observations'][0]['analysis_sha256'] = '0'*64
        put(parent, name, value)
    put(parent, parent_input.FILES[2], builds)
    put(parent, parent_input.FILES[3], oracle)
    seal(parent, policy, policy_path)
    with pytest.raises(ValueError): study.prepare(parent, tmp_path/'rejected', policy_path)
    assert not (tmp_path/'rejected').exists()


def test_private_truth_changes_cannot_change_inputs_or_schedule(parent_fixture, tmp_path):
    parent, policy, policy_path = parent_fixture
    first, second = tmp_path/'before', tmp_path/'after'
    study.prepare(parent, first, policy_path)
    oracle = read_json(parent/parent_input.FILES[3])
    a = next(r for r in oracle['reviews'] if r['binary_label'] == 'vulnerable_CWE-121')
    b = next(r for r in oracle['reviews'] if r['binary_label'] == 'not_vulnerable' and r['cwe'] == 'CWE-121')
    a['binary_label'], b['binary_label'] = b['binary_label'], a['binary_label']
    put(parent, parent_input.FILES[3], oracle)
    reviews = {r['build_id']: r for r in oracle['reviews']}
    judgments = read_json(parent/parent_input.FILES[4])
    for row in judgments['observations']: row['binary_label'] = reviews[row['build_id']]['binary_label']
    put(parent, parent_input.FILES[4], judgments)
    # A changed oracle requires explicit rebinding; silently editing private truth fails first.
    with pytest.raises(ValueError, match='Changed parent input'):
        study.prepare(parent, second, policy_path)
    seal(parent, policy, policy_path)
    study.prepare(parent, second, policy_path)
    for name in ('observations', 'conditions', 'slots'):
        assert (first/f'coordinator/{name}.json').read_bytes() == (second/f'coordinator/{name}.json').read_bytes()
    for record in (first/'public/bundles').glob('*.json'):
        assert record.read_bytes() == (second/'public/bundles'/record.name).read_bytes()
    assert (first/'private/evaluation.json').read_bytes() != (second/'private/evaluation.json').read_bytes()


def test_parent_can_be_relocated_before_preparation(parent_fixture, tmp_path):
    parent, _, policy_path = parent_fixture
    policy = policy_path.read_bytes()
    relocated = parent.rename(tmp_path/'relocated-parent')
    assert not parent.exists()
    relocated_policy = put(tmp_path, 'relocated-policy.json', policy)
    staged = tmp_path/'staged'
    result = study.prepare(relocated, staged, relocated_policy)
    relocated.rename(tmp_path/'parent-no-longer-present')
    assert study.verify(staged) == result


@pytest.mark.parametrize('mutation', ['changed_bundle', 'missing_ledger', 'extra_file', 'symlink',
                                     'ledger_rehashed', 'missing_count'])
def test_offline_verifier_rejects_tampering(parent_fixture, tmp_path, mutation):
    parent, _, policy_path = parent_fixture
    stage = tmp_path/'stage'
    study.prepare(parent, stage, policy_path)
    if mutation == 'changed_bundle':
        p = next((stage/'public/bundles').glob('*.json')); put(p.parent, p.name, b'{}')
    if mutation == 'missing_ledger': (stage/'coordinator/slots.json').unlink()
    if mutation == 'extra_file': put(stage, 'public/bundles/extra.json', {})
    if mutation == 'symlink':
        p = next((stage/'public/bundles').glob('*.json')); raw = p.read_bytes(); p.unlink()
        p.symlink_to(put(tmp_path, 'external.json', raw))
    if mutation == 'ledger_rehashed':
        rows = read_json(stage/'coordinator/slots.json'); rows[0]['representation'] = 'combined'
        rows[0]['seed'] = 123
        p = put(stage, 'coordinator/slots.json', rows)
        manifest = read_json(stage/study.MANIFEST); manifest['files']['coordinator/slots.json'] = digest(p)
        put(stage, study.MANIFEST, manifest)
    if mutation == 'missing_count':
        manifest = read_json(stage/study.MANIFEST); del manifest['counts']['families']
        put(stage, study.MANIFEST, manifest)
    before = {p.relative_to(stage): p.read_bytes() for p in stage.rglob('*') if p.is_file()}
    with pytest.raises(ValueError): study.verify(stage)
    assert {p.relative_to(stage): p.read_bytes() for p in stage.rglob('*') if p.is_file()} == before


def test_incomplete_preparation_is_not_verifiable_and_never_overwritten(parent_fixture, tmp_path, monkeypatch):
    parent, _, policy_path = parent_fixture
    stage = tmp_path/'stage'
    original = study.write_new
    calls = []
    def crash(path, value):
        calls.append(path)
        if len(calls) == 3: raise RuntimeError('fixture publication interruption')
        return original(path, value)
    monkeypatch.setattr(study, 'write_new', crash)
    with pytest.raises(RuntimeError): study.prepare(parent, stage, policy_path)
    assert not (stage/study.MANIFEST).exists()
    with pytest.raises(ValueError, match='Missing input'): study.verify(stage)
    with pytest.raises(ValueError, match='destination already exists'): study.prepare(parent, stage, policy_path)
