"""Explicit-configuration llama.cpp launch and model verification helpers."""
import hashlib
import os
from pathlib import Path
from urllib.parse import urlsplit

def require(condition, message):
    if not condition:
        raise ValueError(message)


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
    require(actual == config["llama_cpp"]["model_sha256"], "Local model differs from the configured model SHA-256")
    return actual
