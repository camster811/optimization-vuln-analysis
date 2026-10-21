"""Stateless public-bundle adapter and strict response validation.

Generic transport/usage primitives are reused from the predecessor. Its input
discovery, prompt, scheduling, schema and recovery behavior are not used.
"""
from collections import Counter
import hashlib
import math
import statistics
import time

from jsonschema import Draft7Validator, ValidationError
import requests
from urllib3.exceptions import ReadTimeoutError

from pipeline.run_llm import send_request, usage_counts
from pipeline.serve_llm import server_command
from .bundles import canonical, evidence_addresses, validate
from .inventory import ROOT, read_json, require, strict_json


def sha(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def settings(root=ROOT):
    policy=read_json(root/'llm_policy.json');llm=policy['llm']
    require(policy['schema_version']==1 and policy['method_id']=='public-bundle-llm-v1','Unknown LLM policy')
    server_command(policy)  # validates local endpoint and model/server paths
    runtime=policy['llama_cpp']
    require(runtime['gpu_layers']=='all' and runtime['flash_attention']=='on' and runtime['fit']=='off'
            and runtime['cache_type_k']==runtime['cache_type_v']=='f16','Unexpected runtime configuration')
    require(llm['seeds']==[4101,4102,4103] and llm['repetitions']==3
            and llm['schedule_seed']==20261019,'Unexpected repetition/schedule policy')
    require(type(llm['context_limit']) is int and type(llm['max_tokens']) is int
            and 0<llm['max_tokens']<llm['context_limit'],'Invalid context reservation')
    require(type(llm['request_timeout_seconds']) is int and llm['request_timeout_seconds']>0,'Invalid timeout')
    require(llm['reasoning_format']=='deepseek','Expected separate DeepSeek reasoning')
    require(type(llm['temperature']) in (int,float) and 0<=llm['temperature']<=2
            and type(llm['top_p']) in (int,float) and 0<llm['top_p']<=1,'Invalid sampling')
    allowed={'top_k','min_p','typical_p','repeat_penalty','repeat_last_n','presence_penalty',
             'frequency_penalty','dry_multiplier','dry_base','dry_allowed_length','dry_penalty_last_n',
             'dynatemp_range','dynatemp_exponent','xtc_probability','xtc_threshold','mirostat',
             'mirostat_eta','mirostat_tau','top_n_sigma','adaptive_target','adaptive_decay','min_keep',
             'samplers','ignore_eos'}
    require(set(llm['sampling'])==allowed,'Unexpected or incomplete sampler settings')
    for k,v in llm['sampling'].items():
        if k not in ('samplers','ignore_eos'):require(type(v) in (int,float) and math.isfinite(v),'Invalid sampler value')
    require(llm['sampling']['ignore_eos'] is False and isinstance(llm['sampling']['samplers'],list),'Invalid sampler chain')
    prompt=(root/'llm/prompt.md').read_text()
    require(prompt.count('{{BUNDLE_JSON}}')==1,'Expected exactly one bundle placeholder')
    schema=read_json(root/'llm/response.schema.json');Draft7Validator.check_schema(schema)
    return policy,prompt,schema


def payload(bundle,prompt,schema,policy,repetition):
    validate(bundle)
    require(type(repetition) is int and 1<=repetition<=3,'Invalid repetition')
    llm=policy['llm']
    return {**llm['sampling'],'model':llm['model_id'],
            'messages':[{'role':'user','content':prompt.replace('{{BUNDLE_JSON}}',canonical(bundle))}],
            'temperature':llm['temperature'],'top_p':llm['top_p'],'max_tokens':llm['max_tokens'],
            'seed':llm['seeds'][repetition-1],'n':1,'stream':False,'cache_prompt':False,
            'reasoning_format':llm['reasoning_format'],
            'response_format':{'type':'json_schema','json_schema':{'name':'scope_analysis','strict':True,'schema':schema}}}


def validate_output(output,bundle,schema):
    Draft7Validator(schema).validate(output)
    require(type(output['confidence']) in (int,float) and math.isfinite(output['confidence']),'Invalid confidence')
    require(output['summary'].strip(),'Blank explanation')
    evidence_addresses(bundle,output['evidence'])
    return output


def decode(body,http_status,bundle,schema):
    result={'status':'transport_error','parsed':None,'error':None,'finish_reason':None,
            'usage':{'prompt_tokens':None,'completion_tokens':None},'raw_content':'','raw_reasoning':None}
    if http_status!=200:
        result['error']=f'HTTP {http_status}';return result
    try:envelope=strict_json(body)
    except ValueError as error:
        result.update(status='invalid_json',error=str(error));return result
    result['usage']=usage_counts(envelope)
    try:
        require(isinstance(envelope,dict) and len(envelope.get('choices',[]))==1,'Expected exactly one choice')
        choice=envelope['choices'][0];message=choice['message'];finish=choice['finish_reason']
        result.update(finish_reason=finish,raw_reasoning=message.get('reasoning_content'))
        content=message.get('content');require(content is None or isinstance(content,str),'Nontext answer')
        result['raw_content']=content or ''
        if finish=='length':result.update(status='length_limit',error='Completion reservation exhausted');return result
        require(finish=='stop','Unsupported finish reason')
        if not result['raw_content'].strip():result.update(status='empty_response',error='No answer content');return result
    except (AttributeError,KeyError,TypeError,ValueError) as error:
        result.update(status='schema_invalid',error=str(error));return result
    try:output=strict_json(result['raw_content'])
    except ValueError as error:result.update(status='invalid_json',error=str(error));return result
    try:validate_output(output,bundle,schema)
    except (ValueError,KeyError,TypeError,ValidationError) as error:
        result.update(status='schema_invalid',error=str(error));return result
    result.update(status='valid',parsed=output)
    return result


def attempt(request,bundle,policy,schema):
    started=time.monotonic();body=None;http=None
    try:
        response=send_request(request,policy['llm']);body=response.text;http=response.status_code
        result=decode(body,http,bundle,schema)
    except requests.RequestException as error:
        timed_out=isinstance(error,requests.Timeout) or any(isinstance(c,ReadTimeoutError) for c in (error.__context__,*error.args))
        result={'status':'timeout' if timed_out else 'transport_error','parsed':None,'error':str(error),
                'finish_reason':None,'usage':{'prompt_tokens':None,'completion_tokens':None},'raw_content':'','raw_reasoning':None}
    return {**result,'response_body':body,'http_status':http,'elapsed_seconds':round(time.monotonic()-started,6)}


def aggregate(attempts):
    require(len(attempts)==3,'Expected every repetition slot')
    valid=[a for a in attempts if a['status']=='valid'];votes=Counter(a['parsed']['decision'] for a in valid)
    winner=next((label for label,n in votes.items() if n>=2),None)
    return {'decision':winner if winner is not None else 'uncertain' if valid else None,
            'status':('abstained' if winner=='uncertain' or winner is None and valid else
                      'classified' if winner else 'unavailable'),
            'reason':'majority' if winner else 'no_agreement' if valid else 'no_valid_votes',
            'valid_votes':len(valid),'votes':dict(sorted(votes.items())),
            'confidence':statistics.median(a['parsed']['confidence'] for a in valid) if valid else None,
            'attempt_statuses':dict(sorted(Counter(a['status'] for a in attempts).items()))}
