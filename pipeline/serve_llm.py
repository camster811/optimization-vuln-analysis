#!/usr/bin/env python3
"""Launch the local llama.cpp server with the explicit frozen runtime settings."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import sys
from urllib.parse import urlsplit


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load_config():
    with (PROJECT_ROOT / "config.json").open(encoding="utf-8") as stream:
        config = json.load(stream)
    runtime, llm = config["llama_cpp"], config["llm"]
    require(runtime["gpu_layers"] == "all" and runtime["flash_attention"] == "on"
            and runtime["fit"] == "off", "Full GPU offload, flash attention, and fit=off are required")
    require(runtime["cache_type_k"] == runtime["cache_type_v"] == "f16", "Expected f16 KV caches")
    for field in ("batch_size", "ubatch_size", "threads", "threads_batch"):
        require(type(runtime[field]) is int and runtime[field] > 0, f"Invalid runtime {field}")
    require(runtime["ubatch_size"] <= runtime["batch_size"], "Microbatch exceeds batch size")
    require(type(runtime["log_verbosity"]) is int and runtime["log_verbosity"] >= 4,
            "Trace-level startup logging is required to verify GPU offload and flash attention")
    require(type(llm["context_limit"]) is int and type(llm["max_tokens"]) is int
            and 0 < llm["max_tokens"] < llm["context_limit"], "Invalid context/output budget")
    require(isinstance(runtime["model_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", runtime["model_sha256"]),
            "Invalid model SHA-256")
    return config


def server_command(config):
    runtime, llm = config["llama_cpp"], config["llm"]
    home = Path(runtime["home"]).resolve()
    binary = home / "build/bin/llama-server"
    model = (home / runtime["model"]).resolve()
    require(binary.is_file() and model.is_file() and model.is_relative_to(home),
            "Missing local llama.cpp server or model")
    endpoint = urlsplit(llm["base_url"])
    require(endpoint.scheme == "http" and endpoint.hostname in {"127.0.0.1", "localhost", "::1"}
            and not endpoint.username and not endpoint.password and not endpoint.query and not endpoint.fragment
            and endpoint.path.rstrip("/") in {"", "/v1"}, "Expected a local HTTP endpoint")
    return [str(binary), "--model", str(model), "--alias", llm["model_id"],
            "--host", endpoint.hostname, "--port", str(endpoint.port or 80),
            "--ctx-size", str(llm["context_limit"]), "--parallel", "1",
            "--gpu-layers", runtime["gpu_layers"], "--flash-attn", runtime["flash_attention"],
            "--batch-size", str(runtime["batch_size"]), "--ubatch-size", str(runtime["ubatch_size"]),
            "--threads", str(runtime["threads"]), "--threads-batch", str(runtime["threads_batch"]),
            "--cache-type-k", runtime["cache_type_k"], "--cache-type-v", runtime["cache_type_v"],
            "--no-context-shift", "--reasoning-format", llm["reasoning_format"],
            "--fit", runtime["fit"], "--log-verbosity", str(runtime["log_verbosity"])]


def server_environment(command):
    environment = dict(os.environ)
    directory = str(Path(command[0]).parent)
    environment["LD_LIBRARY_PATH"] = directory + (":" + environment["LD_LIBRARY_PATH"]
                                                  if environment.get("LD_LIBRARY_PATH") else "")
    return environment


def verify_model(config, command):
    model = Path(command[command.index("--model") + 1])
    with model.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    require(actual == config["llama_cpp"]["model_sha256"], "Local model differs from the frozen model SHA-256")
    return actual


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--print-command", action="store_true")
    args = parser.parse_args(argv)
    config = load_config()
    command = server_command(config)
    if args.print_command:
        print(shlex.join(command))
        return
    verify_model(config, command)
    os.execve(command[0], command, server_environment(command))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f"Server launch failed: {error}", file=sys.stderr)
        sys.exit(1)
