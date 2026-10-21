"""Owned local runtime and exact llama.cpp chat-template token accounting."""
import argparse
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

import requests
from pipeline.runtime import digest, model_stat, owns_listener, process_identity, props_identity, source_identity
from pipeline.serve_llm import server_command, server_environment, verify_model
from .inventory import ROOT, read_json, require, strict_json
from .llm import settings, sha
from .bundles import canonical


def write_new(path, value):
    """Publish a complete immutable file, then sync its containing directory."""
    import tempfile
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = value if isinstance(value, str) else canonical(value)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.pending-')
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.link(temporary, path)  # atomic, fails if destination already exists
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        os.unlink(temporary)


def query(policy, method, path, payload=None):
    base = policy['llm']['base_url'].rstrip('/').removesuffix('/v1')
    with requests.Session() as session:
        session.trust_env = False
        response = session.request(method, base + path, json=payload, timeout=30, allow_redirects=False)
        require(response.status_code == 200, f'Runtime HTTP {response.status_code}: {path}')
        return strict_json(response.text)


def budget(request, policy):
    rendered = query(policy, 'POST', '/apply-template', request)['prompt']
    require(isinstance(rendered, str), 'Invalid rendered prompt')
    tokens = query(policy, 'POST', '/tokenize',
                   {'content': rendered, 'add_special': True, 'parse_special': True})['tokens']
    require(isinstance(tokens, list) and tokens and all(type(t) is int for t in tokens), 'Invalid tokenizer response')
    total = len(tokens) + policy['llm']['max_tokens']
    return {'status': 'available' if total <= policy['llm']['context_limit'] else 'context_unavailable',
            'prompt_tokens': len(tokens), 'reserved_completion_tokens': policy['llm']['max_tokens'],
            'total_budget': total, 'rendered_prompt': rendered, 'token_ids': tokens}


def libraries(command):
    return {str(p.resolve()): digest(p) for p in sorted(Path(command[0]).parent.glob('*.so*')) if p.is_file()}


def verify_live(evidence, policy):
    command = server_command(policy)
    require(sha(policy) == evidence['policy_sha256'], 'Runtime policy changed')
    require(process_identity(evidence['process']['pid'], command) == evidence['process'], 'Server identity changed')
    require(model_stat(Path(command[2])) == evidence['model_stat'], 'Model file changed')
    require(libraries(command) == evidence['libraries'], 'Runtime libraries changed')
    require(owns_listener(evidence['process']['pid'], urlsplit(policy['llm']['base_url']).port or 80), 'Server listener changed')
    require(props_identity(query(policy, 'GET', '/props')) == evidence['props'], 'Server properties changed')


def capture(pid, log, policy):
    command = server_command(policy)
    props = props_identity(query(policy, 'GET', '/props'))
    require(props['model_alias'] == policy['llm']['model_id'] and props['model_path'] == command[2], 'Wrong model')
    require(props['total_slots'] == 1 and props['default_generation_settings']['n_ctx'] == policy['llm']['context_limit'], 'Wrong context/slots')
    startup = Path(log).read_text(errors='replace')
    offload = re.search(r'offloaded (\d+)/(\d+) layers', startup)
    require(offload and offload[1] == offload[2] and int(offload[1]) > 0, 'Full GPU offload not confirmed')
    require(re.search(r'flash_attn\s*=\s*enabled', startup), 'Flash attention not confirmed')
    evidence = {'policy_sha256': sha(policy), 'process': process_identity(pid, command),
                'model_sha256': verify_model(policy, command), 'model_stat': model_stat(Path(command[2])),
                'props': props, 'libraries': libraries(command),
                'source': source_identity(Path(policy['llama_cpp']['home'])),
                'gpu_layers': int(offload[1]), 'flash_attention': 'enabled'}
    verify_live(evidence, policy)
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['serve', 'capture'])
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    policy, _, _ = settings()
    directory = args.directory.resolve()
    if args.action == 'serve':
        command = server_command(policy)
        verify_model(policy, command)
        directory.mkdir(parents=True, exist_ok=False)
        write_new(directory/'launch.json', {'pid': os.getpid(), 'command': command})
        log = os.open(directory/'startup.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.dup2(log, 1); os.dup2(log, 2); os.close(log)
        os.execve(command[0], command, server_environment(command))
    else:
        launch = read_json(directory/'launch.json')
        write_new(directory/'server.json', capture(launch['pid'], directory/'startup.log', policy))
        print('Runtime captured:', directory/'server.json')


if __name__ == '__main__': main()
