#!/usr/bin/env python3
"""One schema-constrained llama.cpp attempt per shuffled observation/repetition.

Only exported records, the frozen prompt/schema, and inference configuration are
read. No corpus, observation table, source, or build artifact supplies model input.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import sys
import tempfile
import time
from urllib.parse import urlsplit

from jsonschema import Draft7Validator
import requests
from urllib3.exceptions import ReadTimeoutError

if __package__:
    from .extract import validate_record, scan_record_for_leaks
else:
    from extract import validate_record, scan_record_for_leaks


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROMPT_PATH = PROJECT_ROOT / "llm/prompt.md"
SCHEMA_PATH = PROJECT_ROOT / "llm/response.schema.json"
FAILURES = {"transport_error", "timeout", "invalid_json", "schema_invalid",
            "length_limit", "empty_response"}
RUN_KEYS = {"observation_id", "repetition", "seed", "status", "request_sha256",
            "started_at_utc", "elapsed_seconds", "usage", "raw_response", "parsed",
            "error", "response_body", "http_status"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def strict_json(text):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    def invalid(value):
        raise ValueError(f"Nonstandard JSON number: {value}")

    return json.loads(text, object_pairs_hook=unique, parse_constant=invalid)


def load_config():
    config = strict_json((PROJECT_ROOT / "config.json").read_text(encoding="utf-8"))["llm"]
    require(isinstance(config, dict), "Missing llm configuration")
    require(isinstance(config["model_id"], str) and config["model_id"].strip(), "Missing model ID")
    url = urlsplit(config["base_url"])
    require(url.scheme == "http" and url.hostname in {"localhost", "127.0.0.1", "::1"}
            and not url.username and not url.password and not url.query and not url.fragment
            and url.path.rstrip("/") in {"", "/v1"}
            and (url.port is None or 0 < url.port <= 65535),
            "base_url must be a local llama.cpp HTTP endpoint")
    for key in ("max_tokens", "context_limit", "request_timeout_seconds"):
        require(type(config[key]) is int and config[key] > 0, f"llm.{key} must be a positive integer")
    require(config["max_tokens"] < config["context_limit"], "max_tokens must be below context_limit")
    require(config["repetitions"] == 3 and type(config["repetitions"]) is int,
            "Exactly three repetitions are required")
    require(isinstance(config["seeds"], list) and len(config["seeds"]) == 3
            and all(type(seed) is int and 0 <= seed < 2**32 - 1 for seed in config["seeds"])
            and len(set(config["seeds"])) == 3, "Expected three distinct fixed uint32 seeds")
    require(type(config["schedule_seed"]) is int, "schedule_seed must be an integer")
    for key, low, high in (("temperature", 0, 2), ("top_p", 0, 1)):
        value = config[key]
        require(type(value) in (int, float) and math.isfinite(value) and low <= value <= high,
                f"Invalid llm.{key}")
    require(config["reasoning_format"] == "deepseek", "Use deepseek to preserve reasoning separately from JSON content")
    return config


def load_prompt():
    prompt = PROMPT_PATH.read_text(encoding="utf-8")
    require(prompt.count("{{RECORD_JSON}}") == 1, "Prompt must contain exactly one RECORD_JSON placeholder")
    return prompt


def load_schema():
    schema = strict_json(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft7Validator.check_schema(schema)
    return schema


def list_records(directory):
    require(directory.is_dir(), f"Missing input record directory: {directory}")
    paths = sorted(directory.glob("*.json"))
    require(paths, f"No input records in {directory}")
    records = []
    for path in paths:
        require(re.fullmatch(r"r[0-9]{4}\.json", path.name), f"Unexpected record filename: {path.name}")
        record = strict_json(path.read_text(encoding="utf-8"))
        validate_record(record)
        scan_record_for_leaks(record)
        records.append((path.stem, record))
    return records


def make_schedule(records, repetitions, schedule_seed):
    tasks = [(identifier, repetition) for identifier, _ in sorted(records)
             for repetition in range(1, repetitions + 1)]
    random.Random(schedule_seed).shuffle(tasks)
    return tasks


def render_request(record, prompt):
    # The ID is only an output filename; it is never inserted into model input.
    return prompt.replace("{{RECORD_JSON}}", canonical_json(record))


def make_payload(record, prompt, schema, config, repetition):
    return {
        "model": config["model_id"],
        "messages": [{"role": "user", "content": render_request(record, prompt)}],
        "temperature": config["temperature"], "top_p": config["top_p"],
        "max_tokens": config["max_tokens"], "seed": config["seeds"][repetition - 1],
        "n": 1, "stream": False, "cache_prompt": False,
        "reasoning_format": config["reasoning_format"],
        # This nested wrapper is consumed by llama.cpp's chat parser; an
        # unwrapped response_format.schema is ignored by some server versions.
        "response_format": {"type": "json_schema", "json_schema": {
            "name": "function_analysis", "strict": True, "schema": schema,
        }},
    }


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


def extract_json(text):
    # No fence removal, substring extraction, reasoning removal, or repair.
    # Those would hide invalid outputs rather than measure their frequency.
    return strict_json(text)


def validate_model_output(output, record, schema=None):
    schema = load_schema() if schema is None else schema
    errors = sorted(Draft7Validator(schema).iter_errors(output), key=lambda item: str(list(item.path)))
    require(not errors, "Model output violates schema: " + (errors[0].message if errors else ""))
    require(type(output["confidence"]) in (int, float) and math.isfinite(output["confidence"]),
            "Confidence must be a finite number")
    require(output["summary"].strip(), "Summary cannot be blank")
    addresses = {instruction["address"] for instruction in record["instructions"]}
    require(all(address in addresses for address in output["evidence"]),
            "Evidence includes an address absent from the input instructions")


def usage_counts(response):
    usage = response.get("usage") if isinstance(response, dict) else None
    if not isinstance(usage, dict):
        return {"prompt_tokens": None, "completion_tokens": None}
    return {key: usage.get(key) if type(usage.get(key)) is int and usage[key] >= 0 else None
            for key in ("prompt_tokens", "completion_tokens")}


def run_attempt(identifier, repetition, record, payload, config, schema):
    run = {
        "observation_id": identifier, "repetition": repetition, "seed": payload["seed"],
        "status": None, "request_sha256": hashlib.sha256(canonical_json(payload).encode()).hexdigest(),
        "started_at_utc": datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "elapsed_seconds": 0.0, "usage": {"prompt_tokens": None, "completion_tokens": None},
        "raw_response": "", "parsed": None, "error": None, "response_body": None, "http_status": None,
    }
    started = time.monotonic()
    try:
        try:
            response = send_request(payload, config)
        except requests.Timeout as error:
            run.update(status="timeout", error=str(error) or type(error).__name__)
            return run
        except requests.RequestException as error:
            # requests wraps a timeout while reading a response body in
            # ConnectionError rather than its Timeout subclass.
            timed_out = any(isinstance(cause, ReadTimeoutError)
                            for cause in (error.__context__, *error.args))
            run.update(status="timeout" if timed_out else "transport_error",
                       error=str(error) or type(error).__name__)
            return run
        run["http_status"] = response.status_code
        run["response_body"] = response.text
        if response.status_code != 200:
            # HTTP errors, including context rejection, retain the exact body.
            run.update(status="transport_error", error=f"HTTP {response.status_code}")
            return run
        try:
            envelope = strict_json(response.text)
        except ValueError as error:
            run.update(status="invalid_json", error=f"Response envelope: {error}")
            return run
        run["usage"] = usage_counts(envelope)
        try:
            require(isinstance(envelope, dict) and isinstance(envelope.get("choices"), list)
                    and len(envelope["choices"]) == 1, "Expected exactly one response choice")
            choice = envelope["choices"][0]
            require(isinstance(choice, dict) and isinstance(choice.get("message"), dict), "Missing response message")
            content = choice["message"].get("content")
            require(content is None or isinstance(content, str), "Response content must be text")
            run["raw_response"] = content or ""
            finish = choice.get("finish_reason")
            if finish == "length":
                run.update(status="length_limit", error="Generation reached its token limit")
                return run
            if not run["raw_response"].strip():
                run.update(status="empty_response", error="No answer content returned")
                return run
            require(finish == "stop", f"Unexpected finish reason: {finish!r}")
        except ValueError as error:
            run.update(status="schema_invalid", error=str(error))
            return run
        try:
            output = extract_json(run["raw_response"])
        except ValueError as error:
            run.update(status="invalid_json", error=str(error))
            return run
        try:
            validate_model_output(output, record, schema)
        except ValueError as error:
            run.update(status="schema_invalid", error=str(error))
            return run
        run.update(status="valid", parsed=output)
        return run
    finally:
        run["elapsed_seconds"] = round(time.monotonic() - started, 6)


def validate_saved_run(run, identifier, repetition, record, schema):
    require(isinstance(run, dict) and set(run) == RUN_KEYS, "Invalid saved run fields")
    require(run["observation_id"] == identifier and type(run["repetition"]) is int
            and run["repetition"] == repetition and type(run["seed"]) is int, "Invalid saved run identity")
    require(isinstance(run["request_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", run["request_sha256"]),
            "Invalid saved request hash")
    require(isinstance(run["started_at_utc"], str) and run["started_at_utc"].endswith("Z")
            and datetime.fromisoformat(run["started_at_utc"].replace("Z", "+00:00")).utcoffset().total_seconds() == 0,
            "Invalid saved start time")
    elapsed = run["elapsed_seconds"]
    require(type(elapsed) in (int, float) and math.isfinite(elapsed) and elapsed >= 0, "Invalid saved duration")
    require(isinstance(run["usage"], dict) and set(run["usage"]) == {"prompt_tokens", "completion_tokens"}
            and all(value is None or type(value) is int and value >= 0 for value in run["usage"].values()),
            "Invalid saved usage")
    require(isinstance(run["raw_response"], str)
            and (run["response_body"] is None or isinstance(run["response_body"], str))
            and (run["http_status"] is None or type(run["http_status"]) is int), "Invalid saved raw response")
    if run["status"] == "valid":
        require(run["error"] is None and run["http_status"] == 200, "Invalid successful run metadata")
        validate_model_output(run["parsed"], record, schema)
        require(extract_json(run["raw_response"]) == run["parsed"], "Saved raw/parsed answers disagree")
    else:
        require(run["status"] in FAILURES and run["parsed"] is None
                and isinstance(run["error"], str) and run["error"].strip(), "Invalid saved failure")


def write_run_atomically(path, run):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".pending-", suffix=".json", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(json.dumps(run, indent=2, ensure_ascii=False, allow_nan=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, default=PROJECT_ROOT / "data/records")
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "results/llm_runs")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--force", action="store_true", help="Explicitly replace all scheduled run files")
    args = parser.parse_args(argv)
    require(not (args.resume and args.force), "Choose either --resume or --force")
    inputs, output = args.inputs.resolve(), args.output.resolve()
    require(not output.is_relative_to(inputs) and not inputs.is_relative_to(output),
            "Input and output directories must be separate")
    config, prompt, schema = load_config(), load_prompt(), load_schema()
    records = dict(list_records(inputs))
    schedule = make_schedule(list(records.items()), config["repetitions"], config["schedule_seed"])
    payloads = {(identifier, repetition): make_payload(records[identifier], prompt, schema, config, repetition)
                for identifier, repetition in schedule}
    request_hashes = {task: hashlib.sha256(canonical_json(payload).encode()).hexdigest()
                      for task, payload in payloads.items()}
    campaign = {
        "schema_version": 1, "inference_config": config,
        "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
        "schema_sha256": hashlib.sha256(canonical_json(schema).encode()).hexdigest(),
        "schedule": [{"observation_id": identifier, "repetition": repetition,
                      "request_sha256": request_hashes[identifier, repetition]}
                     for identifier, repetition in schedule],
    }
    output.mkdir(parents=True, exist_ok=True)
    # Keep simultaneous invocations from duplicating attempts or replacing runs.
    with (output / ".runner.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError(f"Another runner holds {output}") from None
        campaign_path = output / "campaign.json"
        if campaign_path.exists() and not args.force:
            require(strict_json(campaign_path.read_text(encoding="utf-8")) == campaign,
                    "Campaign inputs/settings changed; choose a new output directory or use --force")
        existing = set(output.glob("r*/rep*.json"))
        expected = {output / identifier / f"rep{repetition}.json" for identifier, repetition in schedule}
        require(existing <= expected, "Output contains unexpected run files; choose a separate output directory")
        if existing and not (args.resume or args.force):
            raise ValueError("Run files already exist; use --resume or explicitly --force")
        skip = set()
        for identifier, repetition in schedule:
            path = output / identifier / f"rep{repetition}.json"
            if not path.exists() or args.force:
                continue
            try:
                run = strict_json(path.read_text(encoding="utf-8"))
                validate_saved_run(run, identifier, repetition, records[identifier], schema)
            except (ValueError, KeyError, TypeError, OverflowError) as error:
                print(f"Incomplete run {path}: {error}; scheduling one attempt", file=sys.stderr)
                continue
            require(run["request_sha256"] == request_hashes[identifier, repetition]
                    and run["seed"] == payloads[identifier, repetition]["seed"],
                    f"Completed run differs from current request: {path}; use a new output or --force")
            skip.add((identifier, repetition))  # Saved failures are completed, too.
        write_run_atomically(campaign_path, campaign)
        print(f"Scheduled {len(schedule)} tasks; {len(skip)} completed runs skipped", flush=True)
        counts = Counter()
        for identifier, repetition in schedule:
            if (identifier, repetition) in skip:
                continue
            run = run_attempt(identifier, repetition, records[identifier], payloads[identifier, repetition], config, schema)
            validate_saved_run(run, identifier, repetition, records[identifier], schema)
            write_run_atomically(output / identifier / f"rep{repetition}.json", run)
            counts[run["status"]] += 1
            print(f"{identifier}/rep{repetition}: {run['status']}", flush=True)
        print(f"Saved {sum(counts.values())} new runs: {dict(sorted(counts.items()))}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError) as error:
        print(f"LLM run failed: {error}", file=sys.stderr)
        sys.exit(1)
