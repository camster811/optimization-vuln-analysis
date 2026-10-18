#!/usr/bin/env python3
"""Capture local inference identity and token budgets without reading private truth."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import time

import requests

if __package__:
    from . import run_llm, serve_llm
else:
    import run_llm
    import serve_llm

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def request(root, method, path, payload=None):
    config = run_llm.strict_json((root / 'config.json').read_text())
    base = config['llm']['base_url'].removesuffix('/v1').rstrip('/')
    with requests.Session() as session:
        session.trust_env = False
        response = session.request(method, base + path, json=payload, timeout=20, allow_redirects=False)
        response.raise_for_status()
        return response.json()


def process_identity(pid, command):
    proc = Path('/proc') / str(pid)
    actual = (proc / 'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
    run_llm.require(actual == command, 'Live server command differs from the recorded command')
    # PID reuse and a replaced executable cannot silently pass as the same server.
    start = (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19]
    return {'pid': pid, 'start_ticks': start, 'binary_sha256': digest(proc / 'exe')}


def owns_listener(pid, port):
    sockets = set()
    for fd in (Path('/proc') / str(pid) / 'fd').iterdir():
        try:
            link = os.readlink(fd)
        except FileNotFoundError:
            continue
        if link.startswith('socket:['):
            sockets.add(link[8:-1])
    for filename in ('/proc/net/tcp', '/proc/net/tcp6'):
        for line in Path(filename).read_text().splitlines()[1:]:
            fields = line.split()
            if fields[3] == '0A' and int(fields[1].split(':')[-1], 16) == port and fields[9] in sockets:
                return True
    return False


def props_identity(props):
    return {key: props[key] for key in ('model_alias', 'model_path', 'build_info', 'total_slots',
                                       'default_generation_settings', 'chat_template')}


def verify_live(root=ROOT):
    root = Path(root)
    config = run_llm.strict_json((root / 'config.json').read_text())
    evidence = run_llm.strict_json((root / 'runtime/server.json').read_text())
    command = serve_llm.server_command(config)
    identity = process_identity(evidence['process']['pid'], command)
    run_llm.require(identity == evidence['process'], 'Server process identity changed')
    run_llm.require(model_stat(Path(command[2])) == evidence['model_stat'], 'Model file changed after preflight')
    from urllib.parse import urlsplit
    run_llm.require(owns_listener(identity['pid'], urlsplit(config['llm']['base_url']).port or 80),
                    'Recorded server does not own the configured listener')
    props = request(root, 'GET', '/props')
    run_llm.require(props_identity(props) == evidence['props'], 'Live server properties changed')
    return evidence


def model_stat(path):
    stat = path.stat()
    return {key: getattr(stat, key) for key in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}


def validate_evidence(root):
    """Offline validation: release regeneration does not need a live server."""
    config = run_llm.strict_json((root / 'config.json').read_text())
    evidence = run_llm.strict_json((root / 'runtime/server.json').read_text())
    preflight = run_llm.strict_json((root / 'runtime/preflight.json').read_text())
    run_llm.require(evidence['model_sha256'] == config['llama_cpp']['model_sha256'], 'Runtime model hash mismatch')
    run_llm.require(hashlib.sha256(evidence['props']['chat_template'].encode()).hexdigest()
                    == evidence['chat_template_sha256'], 'Chat template hash mismatch')
    run_llm.require(preflight['server_sha256'] == digest(root / 'runtime/server.json'), 'Preflight identity mismatch')
    llm = config['llm']
    run_llm.require(preflight['context_limit'] == llm['context_limit'] and preflight['max_tokens'] == llm['max_tokens']
                    and preflight['all_requests_fit'] is True and preflight['flash_attention'] == 'enabled'
                    and preflight['gpu_layers_offloaded'] == preflight['gpu_layers_total'] > 0,
                    'Incomplete runtime preflight')
    run_llm.require(preflight['effective_sampling'] == {**llm['sampling'], 'temperature': llm['temperature'], 'top_p': llm['top_p']},
                    'Effective sampling differs from configuration')
    budgets = {row['observation_id']: row for row in preflight['records']}
    records = dict(run_llm.list_records(root / 'data/records'))
    run_llm.require(len(budgets) == len(preflight['records']) == len(records) == 160 and set(budgets) == set(records),
                    'Incomplete preflight record inventory')
    prompt = (root / 'llm/prompt.md').read_text()
    schema = run_llm.strict_json((root / 'llm/response.schema.json').read_text())
    for identifier, record in records.items():
        budget = budgets[identifier]
        payload = run_llm.make_payload(record, prompt, schema, llm, 1)
        run_llm.require(budget['request_sha256'] == hashlib.sha256(run_llm.canonical_json(payload).encode()).hexdigest()
                        and type(budget['prompt_tokens']) is int and budget['prompt_tokens'] > 0
                        and budget['total_budget'] == budget['prompt_tokens'] + llm['max_tokens'] <= llm['context_limit'],
                        f'Invalid token preflight: {identifier}')


def source_identity(home):
    try:
        revision = subprocess.check_output(['git', '-C', str(home), 'rev-parse', 'HEAD'], text=True,
                                           stderr=subprocess.DEVNULL).strip()
        dirty = bool(subprocess.check_output(['git', '-C', str(home), 'status', '--porcelain'], text=True))
    except subprocess.CalledProcessError:
        revision, dirty = None, None
    files = {}
    for directory in ('src', 'common', 'tools/server', 'ggml/src', 'include'):
        for path in sorted((home / directory).rglob('*')):
            if path.is_file():
                files[path.relative_to(home).as_posix()] = digest(path)
    return {'git_revision': revision, 'git_dirty': dirty,
            'source_tree_sha256': hashlib.sha256(run_llm.canonical_json(files).encode()).hexdigest(),
            'source_files': len(files)}


def capture(pid, startup_log, root=ROOT):
    config = run_llm.strict_json((root / 'config.json').read_text())
    command = serve_llm.server_command(config)
    model_hash = serve_llm.verify_model(config, command)
    props = request(root, 'GET', '/props')
    run_llm.require(props['model_alias'] == config['llm']['model_id'] and props['model_path'] == command[2],
                    'Wrong live model alias or model path')
    run_llm.require(props['default_generation_settings']['n_ctx'] == config['llm']['context_limit']
                    and props['total_slots'] == 1, 'Wrong live context/slot configuration')
    gpu = subprocess.check_output(['nvidia-smi', '--query-gpu=name,driver_version,memory.total',
                                  '--format=csv,noheader'], text=True).strip()
    identity = {'process': process_identity(pid, command), 'model_sha256': model_hash,
                'model_stat': model_stat(Path(command[2])),
                'props': props_identity(props),
                'chat_template_sha256': hashlib.sha256(props['chat_template'].encode()).hexdigest(),
                'source': source_identity(Path(config['llama_cpp']['home'])),
                'hardware': {'gpu': gpu, 'cpu': platform.processor(), 'machine': platform.machine(),
                             'platform': platform.platform()}}
    directory = root / 'runtime'
    directory.mkdir(exist_ok=True)
    run_llm.write_run_atomically(directory / 'server.json', identity)
    startup = Path(startup_log).read_text(errors='replace')
    lines = [line for line in startup.splitlines() if re.search(r'offloaded .* layers|flash_attn|build:|commit', line)]
    sanitized = '\n'.join(lines).replace(str(root), '<campaign>').replace(config['llama_cpp']['home'], '<llama_cpp>')
    offload = re.search(r'offloaded (\d+)/(\d+) layers', sanitized)
    run_llm.require(offload is not None and offload[1] == offload[2], 'Full GPU offload not confirmed')
    run_llm.require(re.search(r'flash_attn\s*=\s*enabled', sanitized) is not None,
                    'Flash attention not confirmed')
    (directory / 'startup.txt').write_text(sanitized + '\n')
    llm, prompt, schema = config['llm'], (root / 'llm/prompt.md').read_text(), run_llm.strict_json((root / 'llm/response.schema.json').read_text())
    budgets = []
    for identifier, record in run_llm.list_records(root / 'data/records'):
        payload = run_llm.make_payload(record, prompt, schema, llm, 1)
        rendered = request(root, 'POST', '/apply-template', payload)['prompt']
        tokens = request(root, 'POST', '/tokenize', {'content': rendered, 'add_special': True, 'parse_special': True})['tokens']
        run_llm.require(len(tokens) + llm['max_tokens'] <= llm['context_limit'], f'Context overflow: {identifier}')
        budgets.append({'observation_id': identifier, 'prompt_tokens': len(tokens),
                        'total_budget': len(tokens) + llm['max_tokens'],
                        'request_sha256': hashlib.sha256(run_llm.canonical_json(payload).encode()).hexdigest()})
    result = {'all_requests_fit': True, 'records': budgets, 'context_limit': llm['context_limit'],
              'max_tokens': llm['max_tokens'], 'gpu_layers_offloaded': int(offload[1]),
              'gpu_layers_total': int(offload[2]), 'flash_attention': 'enabled',
              'effective_sampling': {**llm['sampling'], 'temperature': llm['temperature'], 'top_p': llm['top_p']},
              'server_sha256': digest(directory / 'server.json')}
    run_llm.write_run_atomically(directory / 'preflight.json', result)
    validate_evidence(root)
    verify_live(root)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--startup-log', type=Path, required=True)
    args = parser.parse_args()
    capture(args.pid, args.startup_log)


if __name__ == '__main__':
    main()
