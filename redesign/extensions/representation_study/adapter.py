"""Common stateless requests, strict visible-line responses and reused vote aggregation."""
from functools import partial
import math
from pathlib import Path
from urllib.parse import urlsplit

from jsonschema import Draft7Validator, ValidationError

from redesign.pipeline import bundles, llm
from redesign.pipeline.inventory import read_json, require, strict_json
from pipeline.run_llm import canonical_json, usage_counts
from . import inventory, views


HERE = Path(__file__).parent
aggregate = llm.aggregate
wire = canonical_json


def policy_check(policy):
    inventory.policy_check(policy)
    config = policy['llm']
    llm.sampling_check(config)
    require(type(config['context_limit']) is int and type(config['max_tokens']) is int
            and 0 < config['max_tokens'] < config['context_limit'], 'Invalid context reservation')
    require(type(config['request_timeout_seconds']) is int and config['request_timeout_seconds'] > 0,
            'Invalid request timeout')
    require(type(config['temperature']) in (int, float) and 0 <= config['temperature'] <= 2
            and type(config['top_p']) in (int, float) and 0 < config['top_p'] <= 1, 'Invalid sampling')
    require(isinstance(config['model_id'], str) and config['model_id'].strip()
            and config['reasoning_format'] == 'deepseek', 'Invalid model/reasoning configuration')
    endpoint = urlsplit(config['base_url'])
    require(endpoint.scheme == 'http' and endpoint.hostname in {'127.0.0.1', 'localhost', '::1'}
            and not endpoint.username and not endpoint.password and not endpoint.query and not endpoint.fragment
            and endpoint.path.rstrip('/') in {'', '/v1'}
            and (endpoint.port is None or 0 < endpoint.port <= 65535), 'Expected local HTTP inference endpoint')
    return policy


def settings(root=HERE):
    """Offline protocol settings; runtime/model identities are bound in later phases."""
    root = Path(root)
    policy = policy_check(read_json(root/'policy.json'))
    prompt = (root/'prompt.md').read_text(encoding='utf-8')
    require(prompt.count('{{VIEW_JSON}}') == 1, 'Expected exactly one view placeholder')
    schema = read_json(root/'schemas/response.json')
    Draft7Validator.check_schema(schema)
    return policy, prompt, schema


def payload(view, prompt, schema, policy, repetition, *, view_schema=None, parent_schema=None):
    views.validate(view, schema=view_schema, parent_schema=parent_schema)
    policy_check(policy)
    require(prompt.count('{{VIEW_JSON}}') == 1, 'Expected exactly one view placeholder')
    Draft7Validator.check_schema(schema)
    require(type(repetition) is int and 1 <= repetition <= 3, 'Invalid repetition')
    config = policy['llm']
    return {**config['sampling'], 'model': config['model_id'],
            'messages': [{'role': 'user', 'content': prompt.replace('{{VIEW_JSON}}', bundles.canonical(view))}],
            'temperature': config['temperature'], 'top_p': config['top_p'], 'max_tokens': config['max_tokens'],
            'seed': config['seeds'][repetition-1], 'n': 1, 'stream': False, 'cache_prompt': False,
            'reasoning_format': config['reasoning_format'],
            'response_format': {'type': 'json_schema', 'json_schema': {
                'name': 'representation_analysis', 'strict': True, 'schema': schema}}}


class OutputError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def validate_output(output, view, schema):
    """The caller supplies a validated view; no hidden bundle or oracle is consulted."""
    Draft7Validator(schema).validate(output)
    if type(output['confidence']) not in (int, float) or not math.isfinite(output['confidence']):
        raise OutputError('invalid_confidence', 'Confidence must be a finite number')
    if not output['summary'].strip():
        raise OutputError('blank_summary', 'Blank explanation')
    if any(reference not in views.visible_references(view) for reference in output['evidence']):
        raise OutputError('nonvisible_reference', 'Evidence reference is not visible in the supplied view')
    return output


def decode(body, http_status, view, schema, *, view_schema=None, parent_schema=None):
    # Invalid input/schema is an engineering error, not a model-output failure.
    views.validate(view, schema=view_schema, parent_schema=parent_schema)
    Draft7Validator.check_schema(schema)
    result = {'status': 'transport_error', 'parsed': None, 'error': None, 'validation_failure': None,
              'finish_reason': None, 'usage': {'prompt_tokens': None, 'completion_tokens': None},
              'raw_content': '', 'raw_reasoning': None}

    def failed(status, stage, code, error, path=()):
        result.update(status=status, error=str(error), validation_failure={
            'stage': stage, 'code': code, 'path': list(path)})
        return result

    if http_status != 200:
        return failed('transport_error', 'transport', 'http_status', f'HTTP {http_status}')
    try:
        require(isinstance(body, str), 'Nontext response body')
        envelope = strict_json(body)
    except (TypeError, ValueError) as error:
        return failed('invalid_json', 'envelope_json', 'invalid_envelope_json', error)
    result['usage'] = usage_counts(envelope)
    try:
        require(isinstance(envelope, dict) and isinstance(envelope.get('choices'), list)
                and len(envelope['choices']) == 1, 'Expected exactly one choice')
        choice = envelope['choices'][0]
        require(isinstance(choice, dict) and isinstance(choice.get('message'), dict), 'Invalid choice/message')
        message = choice['message']
        finish = choice.get('finish_reason')
        content, reasoning = message.get('content'), message.get('reasoning_content')
        result.update(finish_reason=finish if isinstance(finish, str) else None,
                      raw_content=content if isinstance(content, str) else '',
                      raw_reasoning=reasoning if isinstance(reasoning, str) else None)
        require(content is None or isinstance(content, str), 'Nontext answer')
        require(reasoning is None or isinstance(reasoning, str), 'Nontext reasoning')
        require(message.get('role', 'assistant') == 'assistant', 'Unexpected response role')
        require(message.get('tool_calls') in (None, []) and message.get('function_call') is None,
                'Unexpected tool/function call')
        require('index' not in choice or type(choice['index']) is int and choice['index'] == 0,
                'Unexpected choice index')
        if finish == 'length':
            return failed('length_limit', 'completion', 'length_termination', 'Completion reservation exhausted')
        require(finish == 'stop', 'Unsupported finish reason')
        if not result['raw_content'].strip():
            return failed('empty_response', 'answer_json', 'empty_answer', 'No answer content')
    except (KeyError, TypeError, ValueError) as error:
        return failed('schema_invalid', 'envelope', 'invalid_envelope', error)
    try:
        output = strict_json(result['raw_content'])
    except ValueError as error:
        return failed('invalid_json', 'answer_json', 'invalid_answer_json', error)
    try:
        validate_output(output, view, schema)
    except ValidationError as error:
        code = 'duplicate_reference' if error.validator == 'uniqueItems' else 'response_schema'
        return failed('schema_invalid', 'answer_schema', code, error, error.absolute_path)
    except OutputError as error:
        return failed('schema_invalid', 'answer_validation', error.code, error)
    result.update(status='valid', parsed=output)
    return result


def attempt(request, view, policy, schema, *, view_schema=None, parent_schema=None):
    """One transport attempt; the runner must publish durable dispatch before calling this."""
    views.validate(view, schema=view_schema, parent_schema=parent_schema)
    policy_check(policy)
    Draft7Validator.check_schema(schema)
    result = llm.attempt(request, view, policy, schema, decoder=partial(
        decode, view_schema=view_schema, parent_schema=parent_schema))
    if 'validation_failure' not in result:
        result['validation_failure'] = {'stage': 'transport', 'code': result['status'], 'path': []}
    return result
