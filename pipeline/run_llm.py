"""Explicit-argument JSON transport and usage helpers for local inference."""
import json

import requests

def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def send_request(payload, config):
    url = config["base_url"].rstrip("/")
    if not url.endswith("/v1"):
        url += "/v1"
    # No retries, redirects, proxy inheritance, prior messages, or KV reuse.
    with requests.Session() as session:
        session.trust_env = False
        return session.post(url + "/chat/completions",
                            data=canonical_json(payload).encode("utf-8"),
                            headers={"Content-Type": "application/json"},
                            timeout=(5, config["request_timeout_seconds"]), allow_redirects=False)


def usage_counts(response):
    usage = response.get("usage") if isinstance(response, dict) else None
    if not isinstance(usage, dict):
        return {"prompt_tokens": None, "completion_tokens": None}
    return {key: usage.get(key) if type(usage.get(key)) is int and usage[key] >= 0 else None
            for key in ("prompt_tokens", "completion_tokens")}
