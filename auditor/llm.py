"""LLM provider switch: ollama | openai_compatible | none.

The existing Ollama client (``auditor.ollama``) is unchanged and stays
loopback-only. OpenAI-compatible providers read the API key from
``AUDITOR_LLM_API_KEY`` only — never from config files or source.
AI text is always labeled ``AI_OPINION``.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

from auditor.mode import is_public, public_limits
from auditor.spend import (
    DEFAULT_INPUT_PER_M,
    DEFAULT_OUTPUT_PER_M,
    SpendCapExceeded,
    assert_can_spend,
    cost_usd,
    record as record_spend,
)

PROVIDER_OLLAMA = "ollama"
PROVIDER_OPENAI_COMPATIBLE = "openai_compatible"
PROVIDER_NONE = "none"
ALLOWED_PROVIDERS = (PROVIDER_NONE, PROVIDER_OLLAMA, PROVIDER_OPENAI_COMPATIBLE)


class ProviderError(RuntimeError):
    pass


class ProviderDisabled(ProviderError):
    pass


@dataclass
class LLMResult:
    text: str
    provider: str
    model: str | None
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    epistemic: str = "AI_OPINION"
    error: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "provider": self.provider,
            "model": self.model,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cost_usd": round(self.cost_usd, 6),
            "epistemic": self.epistemic,
            "error": self.error,
        }


def configured_provider(settings_provider: str | None = None) -> str:
    env = (os.environ.get("AUDITOR_LLM_PROVIDER") or "").strip().lower()
    if env in ALLOWED_PROVIDERS:
        return env
    if is_public():
        # Public demo defaults to none even if default.json still says ollama.
        if settings_provider in (PROVIDER_OPENAI_COMPATIBLE, PROVIDER_NONE, PROVIDER_OLLAMA):
            if settings_provider == PROVIDER_OLLAMA and not env:
                return PROVIDER_NONE
            return settings_provider
        return PROVIDER_NONE
    return (settings_provider or PROVIDER_OLLAMA).strip().lower() or PROVIDER_OLLAMA


def _api_key() -> str:
    return (os.environ.get("AUDITOR_LLM_API_KEY") or "").strip()


def _normalize_base_url(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    if not url:
        raise ProviderError("openai_compatible provider requires model.base_url or AUDITOR_LLM_BASE_URL")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ProviderError(f"invalid openai-compatible base_url: {url!r}")
    return url


def _chat_url(base: str) -> str:
    if base.endswith("/chat/completions"):
        return base
    if base.endswith("/v1"):
        return base + "/chat/completions"
    return base + "/v1/chat/completions"


def _post_json(url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - caller supplies base_url
            raw = resp.read(2_000_000)
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read(500).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        raise ProviderError(f"HTTP {exc.code} from LLM provider") from exc
    except urllib.error.URLError as exc:
        raise ProviderError(f"LLM connection failed: {exc.reason}") from exc


def complete_openai_compatible(
    prompt: str,
    *,
    base_url: str,
    model: str,
    api_key: Optional[str] = None,
    max_tokens: Optional[int] = None,
    timeout: float = 60.0,
    input_per_m: float = DEFAULT_INPUT_PER_M,
    output_per_m: float = DEFAULT_OUTPUT_PER_M,
    cap_usd: Optional[float] = None,
    spend_path=None,
    http_post=_post_json,
) -> LLMResult:
    """Chat-completions call. Tests inject ``http_post``; no live HTTP in unit tests."""
    key = (api_key if api_key is not None else _api_key())
    if not key:
        raise ProviderError("AUDITOR_LLM_API_KEY is not set")
    limits = public_limits()
    max_out = int(max_tokens if max_tokens is not None else limits["max_output_tokens"])
    # Rough preflight: prompt chars/4 + max_out.
    est_in = max(1, len(prompt) // 4)
    estimated = cost_usd(est_in, max_out, input_per_m, output_per_m)
    assert_can_spend(estimated, cap_usd=cap_usd, path=spend_path)

    url = _chat_url(_normalize_base_url(base_url))
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_out,
        "temperature": 0,
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {key}",
    }
    data = http_post(url, payload, headers, timeout)
    choices = data.get("choices") or []
    text = ""
    if choices:
        msg = (choices[0] or {}).get("message") or {}
        text = str(msg.get("content") or "")
    usage = data.get("usage") or {}
    inp = int(usage.get("prompt_tokens") or est_in)
    out = int(usage.get("completion_tokens") or max(1, len(text) // 4))
    spent = cost_usd(inp, out, input_per_m, output_per_m)
    record_spend(inp, out, spent, path=spend_path)
    return LLMResult(
        text=text,
        provider=PROVIDER_OPENAI_COMPATIBLE,
        model=model,
        input_tokens=inp,
        output_tokens=out,
        cost_usd=spent,
        epistemic="AI_OPINION",
        raw={"usage": usage},
    )


def complete(
    prompt: str,
    *,
    provider: Optional[str] = None,
    settings: Any = None,
    max_tokens: Optional[int] = None,
    spend_path=None,
    http_post=_post_json,
) -> LLMResult:
    """Dispatch to the configured provider. ``none`` returns an empty result."""
    settings_provider = None
    model_name = None
    endpoint = None
    base_url = None
    if settings is not None:
        settings_provider = settings.get("model.provider") if hasattr(settings, "get") else None
        model_name = getattr(settings, "model_name", None) or (settings.get("model.name") if hasattr(settings, "get") else None)
        endpoint = getattr(settings, "endpoint", None)
        base_url = settings.get("model.base_url") if hasattr(settings, "get") else None
    kind = configured_provider(provider or settings_provider)
    if kind == PROVIDER_NONE:
        return LLMResult(text="", provider=PROVIDER_NONE, model=None, error="provider is none")
    if kind == PROVIDER_OLLAMA:
        from auditor.ollama import generate_completion
        # Existing loopback-only client, unchanged.
        model = model_name or "llama3"
        kwargs = {}
        if endpoint:
            kwargs["endpoint"] = endpoint
        if max_tokens is not None:
            kwargs["max_tokens"] = max_tokens
        text, err = generate_completion(prompt, model=model, **kwargs)
        return LLMResult(text=text or "", provider=PROVIDER_OLLAMA, model=model,
                         epistemic="AI_OPINION", error=err)
    if kind == PROVIDER_OPENAI_COMPATIBLE:
        base = base_url or os.environ.get("AUDITOR_LLM_BASE_URL") or ""
        model = model_name or os.environ.get("AUDITOR_LLM_MODEL") or "gpt-4o-mini"
        return complete_openai_compatible(
            prompt,
            base_url=base,
            model=model,
            max_tokens=max_tokens,
            spend_path=spend_path,
            http_post=http_post,
        )
    raise ProviderError(f"unknown provider: {kind!r}")
