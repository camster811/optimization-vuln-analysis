"""Offline contracts for the transport and identity helpers retained for reuse."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import requests

from optimization_vuln_analysis.inference import transport as run_llm, identity as runtime, launch as serve_llm
from optimization_vuln_analysis.inputs.corpus import ROOT, read_json
from optimization_vuln_analysis.inference import runtime as inference_runtime


@pytest.mark.parametrize('base_url', ['http://127.0.0.1:8081', 'http://127.0.0.1:8081/v1/'])
def test_transport_sends_exact_utf8_once_without_proxy_or_redirects(monkeypatch, base_url):
    calls = []
    response = object()

    class Session:
        trust_env = True

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def post(self, url, **kwargs):
            calls.append((self.trust_env, url, kwargs))
            return response

    monkeypatch.setattr(run_llm.requests, 'Session', Session)
    payload = {'z': 'λ', 'messages': [{'role': 'user', 'content': 'code\n'}]}
    assert run_llm.send_request(payload, {'base_url': base_url, 'request_timeout_seconds': 600}) is response
    assert calls == [(False, 'http://127.0.0.1:8081/v1/chat/completions', {
        'data': '{"messages":[{"content":"code\\n","role":"user"}],"z":"λ"}'.encode(),
        'headers': {'Content-Type': 'application/json'}, 'timeout': (5, 600), 'allow_redirects': False})]
    assert run_llm.canonical_json(payload) == run_llm.canonical_json(dict(reversed(list(payload.items()))))
    for value in (float('nan'), float('inf')):
        with pytest.raises(ValueError):
            run_llm.send_request({'value': value}, {'base_url': base_url, 'request_timeout_seconds': 600})
    assert len(calls) == 1


def test_transport_propagates_timeout_without_retry(monkeypatch):
    calls = []

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def post(self, *args, **kwargs):
            calls.append(1)
            raise requests.Timeout('fixture timeout')

    monkeypatch.setattr(run_llm.requests, 'Session', Session)
    with pytest.raises(requests.Timeout):
        run_llm.send_request({}, {'base_url': 'http://localhost:8081', 'request_timeout_seconds': 600})
    assert calls == [1]


@pytest.mark.parametrize('value,expected', [
    ({'usage': {'prompt_tokens': 0, 'completion_tokens': 4}}, (0, 4)),
    ({'usage': {'prompt_tokens': True, 'completion_tokens': -1}}, (None, None)),
    ({'usage': {'prompt_tokens': '4', 'completion_tokens': 1.5}}, (None, None)),
    ({'usage': []}, (None, None)), (None, (None, None)),
])
def test_usage_preserves_unknown_counts(value, expected):
    assert run_llm.usage_counts(value) == dict(zip(('prompt_tokens', 'completion_tokens'), expected))


@pytest.fixture
def local_config(tmp_path):
    config = read_json(ROOT/'llm_policy.json')
    (tmp_path/'build/bin').mkdir(parents=True)
    (tmp_path/'build/bin/llama-server').write_bytes(b'server')
    (tmp_path/'fixture.gguf').write_bytes(b'model')
    config['llama_cpp'].update(home=str(tmp_path), model='fixture.gguf',
                               model_sha256=hashlib.sha256(b'model').hexdigest())
    return config


def test_launch_model_and_environment_contract(local_config, monkeypatch):
    config = local_config
    command = serve_llm.server_command(config)
    assert command == [
        str(Path(config['llama_cpp']['home'])/'build/bin/llama-server'),
        '--model', str(Path(config['llama_cpp']['home'])/'fixture.gguf'),
        '--alias', 'deepseek-r1-distill-qwen-14b-q5_k_m', '--host', '127.0.0.1', '--port', '8081',
        '--ctx-size', '8192', '--parallel', '1', '--gpu-layers', 'all', '--flash-attn', 'on',
        '--batch-size', '512', '--ubatch-size', '128', '--threads', '12', '--threads-batch', '12',
        '--cache-type-k', 'f16', '--cache-type-v', 'f16', '--no-context-shift',
        '--reasoning-format', 'deepseek', '--fit', 'off', '--log-verbosity', '4']
    assert serve_llm.verify_model(config, command) == hashlib.sha256(b'model').hexdigest()
    monkeypatch.setenv('LD_LIBRARY_PATH', '/existing')
    environment = serve_llm.server_environment(command)
    assert environment['LD_LIBRARY_PATH'] == str(Path(command[0]).parent) + ':/existing'
    assert os.environ['LD_LIBRARY_PATH'] == '/existing'
    Path(command[2]).write_bytes(b'changed model')
    with pytest.raises(ValueError, match='SHA-256'):
        serve_llm.verify_model(config, command)


@pytest.mark.parametrize('endpoint', ['https://localhost:8081', 'http://example.com',
    'http://user@localhost', 'http://localhost/other', 'http://localhost?query=1', 'http://localhost/#fragment'])
def test_launch_rejects_nonlocal_or_ambiguous_endpoints(local_config, endpoint):
    local_config['llm']['base_url'] = endpoint
    with pytest.raises(ValueError, match='local HTTP endpoint'):
        serve_llm.server_command(local_config)


def test_launch_rejects_model_outside_runtime_home(local_config, tmp_path):
    external = tmp_path.parent/'external-model.gguf'
    external.write_bytes(b'external')
    local_config['llama_cpp']['model'] = str(external)
    with pytest.raises(ValueError, match='Missing local'):
        serve_llm.server_command(local_config)


def test_process_identity_binds_real_command_start_and_executable():
    command = [sys.executable, '-c', 'import sys; sys.stdin.buffer.read()']
    process = subprocess.Popen(command, stdin=subprocess.PIPE)
    try:
        identity = runtime.process_identity(process.pid, command)
        assert identity['pid'] == process.pid and int(identity['start_ticks']) > 0
        assert identity['binary_sha256'] == runtime.digest(sys.executable)
        assert runtime.process_identity(process.pid, command) == identity
        with pytest.raises(ValueError, match='command differs'):
            runtime.process_identity(process.pid, [*command, 'changed'])
    finally:
        process.communicate(timeout=10)


def test_model_stat_and_source_identity_bind_changes(tmp_path, monkeypatch):
    path = tmp_path/'src/model.cpp'
    path.parent.mkdir()
    path.write_bytes(b'first')
    before = runtime.model_stat(path)
    assert before['st_size'] == 5
    # This fixture models a pinned source tree without Git metadata.
    def no_git(*args, **kwargs):
        raise subprocess.CalledProcessError(1, args[0])
    monkeypatch.setattr(runtime.subprocess, 'check_output', no_git)
    identity = runtime.source_identity(tmp_path)
    files = {'src/model.cpp': hashlib.sha256(b'first').hexdigest()}
    expected = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    assert identity == {'git_revision': None, 'git_dirty': None, 'source_tree_sha256': expected, 'source_files': 1}
    path.write_bytes(b'second version')
    assert runtime.model_stat(path) != before
    assert runtime.source_identity(tmp_path)['source_tree_sha256'] != expected


def test_props_identity_keeps_template_and_generation_settings():
    props = dict(model_alias='fixture', model_path='/fixture', build_info='commit', total_slots=1,
                 default_generation_settings={'n_ctx': 12288}, chat_template='template', transient='ignored')
    identity = runtime.props_identity(props)
    assert identity == {k: v for k, v in props.items() if k != 'transient'}
    changed = deepcopy(props)
    changed['chat_template'] = 'changed'
    assert runtime.props_identity(changed) != identity


@pytest.mark.parametrize('count,status', [(4096, 'available'), (4097, 'context_unavailable')])
def test_exact_budget(monkeypatch, local_config, count, status):
    calls = []
    def query(policy, method, path, payload):
        calls.append((path, payload))
        return {'prompt': 'rendered'} if path == '/apply-template' else {'tokens': [1] * count}
    monkeypatch.setattr(inference_runtime, 'query', query)
    result = inference_runtime.budget({'messages': []}, local_config)
    assert result['status'] == status
    assert calls[-1][1] == {'content': 'rendered', 'add_special': True, 'parse_special': True}

@pytest.mark.parametrize('field', ['process', 'model_stat', 'libraries', 'props'])
def test_live_identity_mutations(monkeypatch, local_config, field):
    policy = local_config
    evidence = {'policy_sha256': inference_runtime.sha(policy), 'process': {'pid': 1}, 'model_stat': {}, 'libraries': {}, 'props': {}}
    monkeypatch.setattr(inference_runtime, 'process_identity', lambda *a: evidence['process'])
    monkeypatch.setattr(inference_runtime, 'model_stat', lambda *a: {})
    monkeypatch.setattr(inference_runtime, 'libraries', lambda *a: {})
    monkeypatch.setattr(inference_runtime, 'owns_listener', lambda *a: True)
    monkeypatch.setattr(inference_runtime, 'query', lambda *a: {})
    monkeypatch.setattr(inference_runtime, 'props_identity', lambda p: p)
    inference_runtime.verify_live(evidence, policy)
    function = {'process': 'process_identity', 'model_stat': 'model_stat', 'libraries': 'libraries', 'props': 'query'}[field]
    monkeypatch.setattr(inference_runtime, function, lambda *a: {'changed': True})
    with pytest.raises(ValueError): inference_runtime.verify_live(evidence, policy)
