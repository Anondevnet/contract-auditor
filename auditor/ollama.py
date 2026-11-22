"""Ollama health and model discovery.

Safety properties:

* Only loopback endpoints are permitted. An unrecognised host is refused
  rather than contacted, so a stray config value cannot turn this into an
  outbound data leak.
* Read-only endpoints only: ``/api/tags`` for listing and ``/api/show`` for
  per-model metadata. Neither generates a completion, so no audit content
  leaves the machine during a status check.
* Nothing is pulled, deleted, or modified.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import urlparse

__all__ = [
    "ALLOWED_HOSTS",
    "DEFAULT_ENDPOINT",
    "OllamaModel",
    "OllamaStatus",
    "check_endpoint_allowed",
    "generate_completion",
    "parse_tags_payload",
    "probe_ollama",
]

DEFAULT_ENDPOINT = "http://localhost:11434"

#: Loopback only. Anything else is refused, not merely warned about.
ALLOWED_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})

DEFAULT_TIMEOUT_SECONDS = 3.0
MAX_RESPONSE_BYTES = 1_048_576


class OllamaEndpointRefused(ValueError):
    """Raised when a non-loopback endpoint is requested."""


def check_endpoint_allowed(endpoint: str) -> str:
    """Validate that ``endpoint`` points at loopback. Returns the normalized URL."""
    parsed = urlparse(endpoint)
    if parsed.scheme not in ("http", "https"):
        raise OllamaEndpointRefused(f"unsupported scheme: {parsed.scheme!r}")
    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        raise OllamaEndpointRefused(
            f"host {host!r} is not loopback; only {sorted(ALLOWED_HOSTS)} are permitted"
        )
    return endpoint.rstrip("/")


def _http_json(url: str, payload: dict[str, Any] | None = None, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> tuple[Any, str | None]:
    """GET or POST JSON. Returns (data, error).

    Defense in depth: the loopback check is repeated here rather than trusted
    from the caller, so a future call site that forgets to validate cannot
    reach urlopen with a remote host.
    """
    try:
        check_endpoint_allowed(url)
    except OllamaEndpointRefused as exc:
        return None, str(exc)

    try:
        if payload is None:
            req = urlrequest.Request(url, method="GET")
        else:
            req = urlrequest.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
        with urlrequest.urlopen(req, timeout=timeout) as response:  # noqa: S310 - loopback-verified URL
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                return None, f"response exceeded {MAX_RESPONSE_BYTES} bytes; not parsed"
            return json.loads(raw.decode("utf-8")), None
    except urlerror.HTTPError as exc:
        return None, f"HTTP {exc.code} {exc.reason}"
    except urlerror.URLError as exc:
        return None, f"connection failed: {exc.reason}"
    except (TimeoutError, OSError) as exc:
        return None, f"connection failed: {type(exc).__name__}: {exc}"
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON response: {exc}"


def _extract_context_length(entry: dict[str, Any], details: dict[str, Any]) -> int | None:
    """Find the context window.

    Ollama's /api/tags has carried this field both at the top level and nested
    inside "details" across versions. Check both rather than reporting an
    unknown for a value that is present.
    """
    for candidate in (entry.get("context_length"), details.get("context_length")):
        if isinstance(candidate, int) and candidate > 0:
            return candidate
    return None


@dataclass
class OllamaModel:
    name: str
    size_bytes: int | None = None
    digest: str | None = None
    family: str | None = None
    parameter_size: str | None = None
    quantization: str | None = None
    context_length: int | None = None
    capabilities: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def size_human(self) -> str | None:
        if self.size_bytes is None:
            return None
        gib = self.size_bytes / (1024**3)
        return f"{gib:.2f} GiB"

    @property
    def supports_tools(self) -> bool:
        return "tools" in self.capabilities

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "size_bytes": self.size_bytes,
            "size_human": self.size_human,
            "digest": self.digest,
            "family": self.family,
            "parameter_size": self.parameter_size,
            "quantization": self.quantization,
            "context_length": self.context_length,
            "capabilities": list(self.capabilities),
            "supports_tools": self.supports_tools,
        }


def parse_tags_payload(payload: Any) -> list[OllamaModel]:
    """Parse ``/api/tags`` JSON into models. Pure function, unit tested.

    Tolerant by design: a model with unexpected or missing fields still yields
    a record, because an entry that exists but is thin is a fact, while a
    silently dropped entry is not.
    """
    if not isinstance(payload, dict):
        return []
    entries = payload.get("models")
    if not isinstance(entries, list):
        return []

    models: list[OllamaModel] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            continue
        details = entry.get("details") if isinstance(entry.get("details"), dict) else {}
        capabilities = entry.get("capabilities")
        models.append(
            OllamaModel(
                name=name,
                size_bytes=entry.get("size") if isinstance(entry.get("size"), int) else None,
                digest=entry.get("digest") if isinstance(entry.get("digest"), str) else None,
                family=details.get("family") if isinstance(details.get("family"), str) else None,
                parameter_size=(
                    details.get("parameter_size") if isinstance(details.get("parameter_size"), str) else None
                ),
                quantization=(
                    details.get("quantization_level") if isinstance(details.get("quantization_level"), str) else None
                ),
                context_length=_extract_context_length(entry, details),
                capabilities=[str(c) for c in capabilities] if isinstance(capabilities, list) else [],
                details={k: v for k, v in details.items() if isinstance(v, (str, int, float, bool))},
            )
        )
    return models


@dataclass
class OllamaStatus:
    endpoint: str
    reachable: bool
    error: str | None = None
    models: list[OllamaModel] = field(default_factory=list)
    selected_model: str | None = None
    selected_resolves: bool | None = None
    selected_loadable: bool | None = None
    selected_error: str | None = None
    probe_performed: bool = False
    probe_skipped_reason: str | None = None

    @property
    def total_size_bytes(self) -> int:
        return sum(model.size_bytes or 0 for model in self.models)

    @property
    def total_size_human(self) -> str:
        return f"{self.total_size_bytes / (1024**3):.2f} GiB"

    def model_names(self) -> list[str]:
        return [model.name for model in self.models]

    def observations(self) -> list[str]:
        notes: list[str] = []
        if not self.reachable:
            notes.append(
                "Ollama unreachable; AI reasoning is unavailable. Deterministic "
                "tooling is unaffected."
            )
            return notes
        if self.selected_model and self.selected_resolves is False:
            notes.append(
                f"configured model {self.selected_model!r} is not installed locally; "
                "no pull will be attempted"
            )
        if self.selected_model and self.selected_loadable is True:
            notes.append(
                f"model {self.selected_model!r} responded to metadata probe "
                "(/api/show); generation capability not exercised in Phase 1"
            )
        return notes

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "reachable": self.reachable,
            "error": self.error,
            "model_count": len(self.models),
            "total_size_bytes": self.total_size_bytes,
            "total_size_human": self.total_size_human,
            "selected_model": self.selected_model,
            "selected_resolves": self.selected_resolves,
            "selected_loadable": self.selected_loadable,
            "selected_error": self.selected_error,
            "probe_performed": self.probe_performed,
            "probe_skipped_reason": self.probe_skipped_reason,
            "models": [model.to_dict() for model in self.models],
            "observations": self.observations(),
        }


def probe_ollama(
    endpoint: str = DEFAULT_ENDPOINT,
    selected_model: str | None = None,
    probe_model: bool = True,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> OllamaStatus:
    """Check reachability and list installed models. Read-only."""
    # Decide probe intent up front so the reason survives an unreachable daemon.
    if not probe_model:
        skip_reason = "model metadata probe disabled (--no-probe-model)"
    elif not selected_model:
        skip_reason = "no --model selected; nothing to probe"
    else:
        skip_reason = None

    try:
        safe_endpoint = check_endpoint_allowed(endpoint)
    except OllamaEndpointRefused as exc:
        return OllamaStatus(
            endpoint=endpoint, reachable=False, error=str(exc), probe_skipped_reason=skip_reason
        )

    payload, error = _http_json(f"{safe_endpoint}/api/tags", timeout=timeout)
    if error is not None:
        return OllamaStatus(
            endpoint=safe_endpoint,
            reachable=False,
            error=error,
            selected_model=selected_model,
            probe_skipped_reason=skip_reason,
        )

    models = parse_tags_payload(payload)
    status = OllamaStatus(
        endpoint=safe_endpoint,
        reachable=True,
        models=models,
        selected_model=selected_model,
        probe_skipped_reason=skip_reason,
    )

    if selected_model:
        status.selected_resolves = selected_model in {model.name for model in models}

    if skip_reason is not None:
        return status

    if status.selected_resolves is False:
        status.selected_error = "selected model is not installed; not probing"
        return status

    # /api/show returns metadata only. No prompt content is transmitted and no
    # generation is requested.
    show_payload, show_error = _http_json(
        f"{safe_endpoint}/api/show",
        payload={"model": selected_model},
        timeout=timeout,
    )
    status.probe_performed = True
    if show_error is not None:
        status.selected_loadable = False
        status.selected_error = show_error
    else:
        status.selected_loadable = True
        if isinstance(show_payload, dict):
            caps = show_payload.get("capabilities")
            if isinstance(caps, list):
                for model in models:
                    if model.name == selected_model:
                        model.capabilities = [str(c) for c in caps]
    return status

def generate_completion(
    prompt: str,
    model: str,
    endpoint: str = DEFAULT_ENDPOINT,
    timeout: float = 60.0,
    max_tokens: int = 700,
    system: str | None = None,
    think: bool | None = None,
) -> tuple[str | None, str | None]:
    """Request one completion from the local Ollama daemon.

    This is the only function in this module that submits audit content, and
    it is still loopback-only: ``_http_json`` re-validates the endpoint, so
    the prompt cannot leave this machine. Returns ``(text, error)`` — exactly
    one of the two is ``None``.
    """
    if not prompt.strip():
        return None, "empty prompt"
    if not model or not model.strip():
        return None, "no model configured"

    try:
        safe_endpoint = check_endpoint_allowed(endpoint)
    except OllamaEndpointRefused as exc:
        return None, str(exc)

    payload: dict[str, Any] = {
        "model": model.strip(),
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_predict": max(1, int(max_tokens)),
            "temperature": 0.2,
        },
        "keep_alive": "5m",
    }
    if system:
        payload["system"] = system
    if think is not None:  # reasoning models: False keeps the budget for the answer
        payload["think"] = bool(think)

    data, error = _http_json(f"{safe_endpoint}/api/generate", payload=payload, timeout=timeout)
    if error is not None:
        return None, error
    if not isinstance(data, dict):
        return None, "unexpected response shape from /api/generate"
    text = data.get("response")
    if not isinstance(text, str) or not text.strip():
        return None, "model returned an empty response"
    return text.strip(), None
