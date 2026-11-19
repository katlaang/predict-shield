"""Language-model interface for the decision layer.

The engine talks to a model through one method, so the model is a deployment
choice. Implementations:

    OllamaModel       a model served on this machine by Ollama (open weights,
                      no data leaves the host, no API key)
    HostedChatModel   a model served by a remote, OpenAI-compatible API
                      (Featherless, Together, or another provider with the
                      same request shape). Advisory and inventory data leaves
                      this host for the provider; the API key leaves this
                      process only as the Authorization header of that request.
    RecordingModel    wraps another model and saves every exchange to a file
    RecordedModel     replays a saved file, so a run can be repeated exactly
                      and audited without the model, or the key, present

Model output is untrusted text. Nothing in this module interprets it; callers
parse it with `parse_json_object` and validate every field before use.

An API key is read only from an environment variable, named for the provider
(`FEATHERLESS_API_KEY`, `TOGETHER_API_KEY`). It is never written to a
recording, logged, or accepted as a command-line argument, where it would
appear in shell history and process listings.
"""
from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Protocol


class ModelUnavailable(RuntimeError):
    """The model could not be reached or has no reply for this request."""


class LanguageModel(Protocol):
    name: str

    def complete(self, system: str, prompt: str) -> str:
        """Return the model's reply to one request. Raises ModelUnavailable."""


def request_key(system: str, prompt: str) -> str:
    return hashlib.sha256((system + "\x00" + prompt).encode("utf-8")).hexdigest()


def parse_json_object(text: str) -> dict:
    """Parse a reply that should be one JSON object. Raises ValueError otherwise."""
    if not isinstance(text, str):
        raise ValueError("model reply is not text")
    body = text.strip()
    if body.startswith("```"):                      # tolerate a fenced reply
        body = body.strip("`")
        body = body[4:] if body.lower().startswith("json") else body
    start, end = body.find("{"), body.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("model reply contains no JSON object")
    value = json.loads(body[start:end + 1])
    if not isinstance(value, dict):
        raise ValueError("model reply is not a JSON object")
    return value


class OllamaModel:
    """A locally served model. Temperature 0 and a fixed seed for repeatable runs."""

    def __init__(self, model: str, *, host: str = "http://127.0.0.1:11434",
                 timeout: float = 300.0, seed: int = 0, context_tokens: int = 8192,
                 think: bool | None = None, max_output_tokens: int | None = None,
                 format_schema: dict | None = None):
        if not model:
            raise ValueError("model name required")
        self.name, self.host, self.timeout = f"ollama:{model}", host.rstrip("/"), timeout
        self.model, self.seed, self.context_tokens = model, seed, context_tokens
        # think=False turns off the hidden reasoning pass of models that have one
        # (qwen3 and others); None leaves the model's default.
        self.think, self.max_output_tokens = think, max_output_tokens
        # Optional provider-side constrained decoding, not a security boundary.
        # Parsed output must still satisfy the project's closed rule grammar.
        self.format_schema = format_schema

    def complete(self, system: str, prompt: str) -> str:
        payload = {"model": self.model, "stream": False,
                   "format": self.format_schema if self.format_schema is not None else "json",
                   "messages": [{"role": "system", "content": system},
                                {"role": "user", "content": prompt}],
                   "options": {"temperature": 0, "seed": self.seed, "num_ctx": self.context_tokens}}
        if self.think is not None:
            payload["think"] = self.think
        if self.max_output_tokens:
            payload["options"]["num_predict"] = self.max_output_tokens
        request = urllib.request.Request(self.host + "/api/chat",
                                         data=json.dumps(payload).encode("utf-8"),
                                         headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                reply = json.loads(response.read().decode("utf-8"))
            return reply["message"]["content"]
        except (urllib.error.URLError, TimeoutError, OSError, KeyError, ValueError) as error:
            raise ModelUnavailable(f"{self.name}: {error}") from error


#: provider name -> (base URL, environment variable holding the API key)
HOSTED_PROVIDERS: dict[str, tuple[str, str]] = {
    "featherless": ("https://api.featherless.ai/v1", "FEATHERLESS_API_KEY"),
    "together": ("https://api.together.ai/v1", "TOGETHER_API_KEY"),
}


class HostedChatModel:
    """A model served by a remote OpenAI-compatible chat-completions API."""

    def __init__(self, provider: str, model: str, *, base_url: str | None = None,
                timeout: float = 300.0, seed: int = 0):
        if provider not in HOSTED_PROVIDERS:
            raise ValueError(f"unknown hosted provider {provider!r}; known: {sorted(HOSTED_PROVIDERS)}")
        if not model:
            raise ValueError("model name required")
        default_url, key_variable = HOSTED_PROVIDERS[provider]
        api_key = os.environ.get(key_variable)
        if not api_key:
            raise ModelUnavailable(f"{key_variable} is not set; export it before using {provider}:{model}")
        self.name = f"{provider}:{model}"
        self.base_url, self.api_key, self.timeout = (base_url or default_url).rstrip("/"), api_key, timeout
        self.model, self.seed = model, seed

    def complete(self, system: str, prompt: str) -> str:
        payload = {"model": self.model, "temperature": 0, "seed": self.seed,
                   "response_format": {"type": "json_object"},
                   "messages": [{"role": "system", "content": system},
                                {"role": "user", "content": prompt}]}
        request = urllib.request.Request(
            self.base_url + "/chat/completions", data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                reply = json.loads(response.read().decode("utf-8"))
            return reply["choices"][0]["message"]["content"]
        except (urllib.error.URLError, TimeoutError, OSError, KeyError, IndexError, ValueError) as error:
            raise ModelUnavailable(f"{self.name}: {error}") from error


class RecordingModel:
    """Pass requests to `inner` and keep every exchange for later replay."""

    def __init__(self, inner: LanguageModel, path: str | Path):
        self.inner, self.path, self.name = inner, Path(path), inner.name
        self.exchanges: dict[str, dict] = {}
        if self.path.exists():
            self.exchanges = json.loads(self.path.read_text(encoding="utf-8"))["exchanges"]

    def complete(self, system: str, prompt: str) -> str:
        reply = self.inner.complete(system, prompt)
        self.exchanges[request_key(system, prompt)] = {"system": system, "prompt": prompt, "reply": reply}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"schema": "predict-shield/model-recording/1",
                                         "model": self.name, "exchanges": self.exchanges},
                                        indent=1, sort_keys=True) + "\n", encoding="utf-8")
        return reply


class RecordedModel:
    """Replay a recording. A request that was never recorded is an error, not a guess."""

    def __init__(self, path: str | Path):
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if data.get("schema") != "predict-shield/model-recording/1":
            raise ValueError("unsupported model recording")
        self.name, self.exchanges = "recorded:" + str(data["model"]), data["exchanges"]

    def complete(self, system: str, prompt: str) -> str:
        exchange = self.exchanges.get(request_key(system, prompt))
        if exchange is None:
            raise ModelUnavailable(f"{self.name}: no recorded reply for this request")
        return exchange["reply"]


def open_model(spec: str, *, record_to: str | Path | None = None) -> LanguageModel:
    """`ollama:<model>`, `<hosted provider>:<model>`, or `recorded:<path>`.

    Hosted providers are the keys of `HOSTED_PROVIDERS` (currently `featherless`
    and `together`); each needs its API key in the matching environment
    variable.
    """
    kind, _, value = spec.partition(":")
    if kind == "ollama" and value:
        model: LanguageModel = OllamaModel(value)
    elif kind in HOSTED_PROVIDERS and value:
        model = HostedChatModel(kind, value)
    elif kind == "recorded" and value:
        model = RecordedModel(value)
    else:
        raise ValueError("model must be 'ollama:<name>', "
                         f"one of {sorted(HOSTED_PROVIDERS)}:<name>, or 'recorded:<path>'")
    return RecordingModel(model, record_to) if record_to else model
