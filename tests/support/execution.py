"""Synthetic execution builders."""
from .parent import build_parent, put
import json
import pytest
from types import SimpleNamespace
from optimization_vuln_analysis.studies.representation import adapter, inventory, runner, views
from optimization_vuln_analysis.inference import attempts as llm, runtime
from optimization_vuln_analysis.inputs.corpus import read_json


def build_projection(root):
    # Reuse the existing complete parent factory once; each execution gets its own packet.
    parent, _, policy_path = build_parent(root)
    inputs, projection, protocol = root/'inputs', root/'projection', root/'protocol'
    inventory.prepare(parent, inputs, policy_path)
    views.prepare(inputs, projection)
    put(protocol, 'policy.json', policy_path.read_bytes())
    put(protocol, 'prompt.md', (adapter.HERE/'prompt.md').read_bytes())
    put(protocol, 'schemas/response.json', (adapter.HERE/'schemas/response.json').read_bytes())
    return projection, protocol


def fake_runtime(policy, pid=11):
    return {'policy_sha256': inventory.identity(policy), 'model_sha256': policy['llama_cpp']['model_sha256'],
            'process': {'pid': pid, 'start_ticks': str(pid*10), 'binary_sha256': 'a'*64},
            'model_stat': {'st_ino': pid}, 'libraries': {'/fake/lib.so': 'b'*64},
            'source': {'git_revision': 'fixture', 'git_dirty': False, 'source_tree_sha256': 'c'*64, 'source_files': 1},
            'props': {'model_alias': policy['llm']['model_id'], 'model_path': '/fake/model.gguf',
                      'build_info': 'fixture-build', 'total_slots': 1,
                      'default_generation_settings': {'n_ctx': policy['llm']['context_limit']},
                      'chat_template': 'fixture chat template'},
            'gpu_layers': 49, 'flash_attention': 'enabled'}


def accounting(policy, count=5):
    return {'status': 'available' if count+policy['llm']['max_tokens'] <= policy['llm']['context_limit']
            else 'context_unavailable', 'prompt_tokens': count, 'token_ids': [1]*count,
            'rendered_prompt': 'synthetic rendered prompt', 'reserved_completion_tokens': policy['llm']['max_tokens'],
            'total_budget': count+policy['llm']['max_tokens']}


def build_packet(tmp_path, projection_setup, monkeypatch):
    projection, protocol = projection_setup
    directory = tmp_path/'run'
    runner.prepare(projection, directory, protocol_root=protocol)
    policy = read_json(directory/'protocol/policy.json')
    control = {'evidence': fake_runtime(policy), 'calls': [], 'policy': policy}
    def live(evidence, actual_policy):
        assert actual_policy == policy
        if evidence != control['evidence']: raise ValueError('Live server identity changed')
    monkeypatch.setattr(runtime, 'verify_live', live)
    monkeypatch.setattr(runtime, 'budget', lambda request, actual_policy: accounting(actual_policy))
    def transport(request, actual_policy):
        # Dispatch must already be durable, and in the prepared schedule's next slot.
        slots = read_json(directory/'coordinator/schedule.json')
        dispatches = [s for s in slots if (directory/s['slot_path']/'dispatch.json').exists()]
        slot = dispatches[-1]
        assert read_json(directory/slot['request_path']) == request
        assert not (directory/slot['slot_path']/'response.json').exists()
        control['calls'].append(slot['slot_id'])
        content = {'decision': 'uncertain', 'confidence': .5, 'evidence': [], 'summary': 'Synthetic response.'}
        body = json.dumps({'choices': [{'message': {'content': json.dumps(content), 'reasoning_content': 'fake reasoning'},
                                        'finish_reason': 'stop'}], 'usage': {'prompt_tokens': 5, 'completion_tokens': 2}})
        return SimpleNamespace(text=body, status_code=200)
    monkeypatch.setattr(llm, 'send_request', transport)
    return directory, control


def bind(packet):
    directory, control = packet
    runner.preflight(directory, control['evidence'])
    return directory, control



def build_reporting_study(root):
    """A small study with one input-blocked observation, without publication tooling."""
    projection, protocol = build_projection(root)
    execution = root/'execution'
    runner.prepare(projection, execution, protocol_root=protocol, purpose='final')
    policy = read_json(execution/'protocol/policy.json')
    calls = []
    def budget(request, policy):
        calls.append(True)
        count = policy['llm']['context_limit']-policy['llm']['max_tokens']+1 if len(calls) == 1 else 5
        return accounting(policy, count)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(runtime, 'verify_live', lambda *a: None)
        patch.setattr(runtime, 'budget', budget)
        runner.preflight(execution, fake_runtime(policy))
    return SimpleNamespace(inputs=root/'inputs', projection=projection, execution=execution)
