"""LLM provider switch: mocked HTTP only, spend cap, AI_OPINION label."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from auditor.llm import (
    PROVIDER_NONE,
    ProviderError,
    complete,
    complete_openai_compatible,
    configured_provider,
)
from auditor.spend import SpendCapExceeded, assert_can_spend, cost_usd, record, status


class ProviderConfigTests(unittest.TestCase):
    def test_public_defaults_to_none(self) -> None:
        with mock.patch.dict(os.environ, {"AUDITOR_MODE": "public"}, clear=False):
            os.environ.pop("AUDITOR_LLM_PROVIDER", None)
            self.assertEqual(configured_provider("ollama"), PROVIDER_NONE)

    def test_env_override(self) -> None:
        with mock.patch.dict(os.environ, {"AUDITOR_LLM_PROVIDER": "openai_compatible", "AUDITOR_MODE": "public"}):
            self.assertEqual(configured_provider("none"), "openai_compatible")

    def test_none_provider_returns_empty(self) -> None:
        with mock.patch.dict(os.environ, {"AUDITOR_LLM_PROVIDER": "none"}):
            result = complete("hello")
            self.assertEqual(result.provider, "none")
            self.assertEqual(result.text, "")
            self.assertEqual(result.epistemic, "AI_OPINION")


class SpendAndHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "spend.sqlite"
        self._data = os.environ.get("AUDITOR_PUBLIC_DATA_DIR")
        os.environ["AUDITOR_PUBLIC_DATA_DIR"] = self.tmp.name
        os.environ["AUDITOR_DAILY_SPEND_USD"] = "1.0"
        os.environ["AUDITOR_LLM_API_KEY"] = "sk-test-not-real"

    def tearDown(self) -> None:
        if self._data is None:
            os.environ.pop("AUDITOR_PUBLIC_DATA_DIR", None)
        else:
            os.environ["AUDITOR_PUBLIC_DATA_DIR"] = self._data
        os.environ.pop("AUDITOR_DAILY_SPEND_USD", None)
        os.environ.pop("AUDITOR_LLM_API_KEY", None)
        self.tmp.cleanup()

    def test_cost_math(self) -> None:
        self.assertEqual(cost_usd(1_000_000, 1_000_000, 2.0, 10.0), 12.0)

    def test_cap_refuses_before_http(self) -> None:
        os.environ["AUDITOR_DAILY_SPEND_USD"] = "0"
        called = {"n": 0}

        def http_post(*args, **kwargs):
            called["n"] += 1
            return {"choices": [{"message": {"content": "should not happen"}}], "usage": {}}

        with self.assertRaises(SpendCapExceeded):
            complete_openai_compatible(
                "hello world",
                base_url="https://example.invalid/v1",
                model="demo",
                cap_usd=0.0,
                spend_path=self.db,
                http_post=http_post,
            )
        self.assertEqual(called["n"], 0)

    def test_mocked_http_is_ai_opinion_and_records_tokens(self) -> None:
        def http_post(url, payload, headers, timeout):
            self.assertIn("chat/completions", url)
            self.assertEqual(headers["Authorization"], "Bearer sk-test-not-real")
            self.assertNotIn("sk-test-not-real", url)
            self.assertEqual(payload["max_tokens"], 1500)
            return {
                "choices": [{"message": {"content": "Looks like reentrancy."}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            }

        result = complete_openai_compatible(
            "triage this finding",
            base_url="https://example.invalid/v1",
            model="demo-model",
            cap_usd=1.0,
            spend_path=self.db,
            http_post=http_post,
        )
        self.assertEqual(result.text, "Looks like reentrancy.")
        self.assertEqual(result.epistemic, "AI_OPINION")
        self.assertEqual(result.input_tokens, 100)
        self.assertEqual(result.output_tokens, 20)
        self.assertGreater(result.cost_usd, 0)
        st = status(cap_usd=1.0, path=self.db)
        self.assertEqual(st.input_tokens, 100)

    def test_missing_key_fails(self) -> None:
        os.environ.pop("AUDITOR_LLM_API_KEY", None)
        with self.assertRaises(ProviderError):
            complete_openai_compatible(
                "hi",
                base_url="https://example.invalid/v1",
                model="demo",
                api_key="",
                cap_usd=1.0,
                spend_path=self.db,
                http_post=lambda *a, **k: {},
            )
