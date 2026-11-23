"""One explicit transport attempt, sampler validation and three-attempt voting."""
from collections import Counter
import math
import statistics
import time

import requests
from urllib3.exceptions import ReadTimeoutError

from optimization_vuln_analysis.inference.transport import send_request
from optimization_vuln_analysis.common import require


def sampling_check(llm):
    """Validate the complete sampler chain without method IDs or runtime-file lookup."""
    allowed={'top_k','min_p','typical_p','repeat_penalty','repeat_last_n','presence_penalty',
             'frequency_penalty','dry_multiplier','dry_base','dry_allowed_length','dry_penalty_last_n',
             'dynatemp_range','dynatemp_exponent','xtc_probability','xtc_threshold','mirostat',
             'mirostat_eta','mirostat_tau','top_n_sigma','adaptive_target','adaptive_decay','min_keep',
             'samplers','ignore_eos'}
    require(set(llm['sampling'])==allowed,'Unexpected or incomplete sampler settings')
    for k,v in llm['sampling'].items():
        if k not in ('samplers','ignore_eos'):require(type(v) in (int,float) and math.isfinite(v),'Invalid sampler value')
    require(llm['sampling']['ignore_eos'] is False and isinstance(llm['sampling']['samplers'],list),'Invalid sampler chain')

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


def attempt(request, evidence, policy, schema, *, decoder, transport=None):
    """Send once using the supplied policy and decoder; never repair or retry."""
    started=time.monotonic();body=None;http=None
    try:
        response=(send_request if transport is None else transport)(request,policy['llm'])
        body=response.text;http=response.status_code
        result=decoder(body,http,evidence,schema)
    except requests.RequestException as error:
        timed_out=isinstance(error,requests.Timeout) or any(isinstance(c,ReadTimeoutError) for c in (error.__context__,*error.args))
        result={'status':'timeout' if timed_out else 'transport_error','parsed':None,'error':str(error),
                'finish_reason':None,'usage':{'prompt_tokens':None,'completion_tokens':None},'raw_content':'','raw_reasoning':None}
    return {**result,'response_body':body,'http_status':http,'elapsed_seconds':round(time.monotonic()-started,6)}
