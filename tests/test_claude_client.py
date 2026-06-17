"""Tests for the Claude boundary with a faked Anthropic client.

No network: we inject a stand-in client so we exercise the response-handling and
degraded-fallback logic without an API key.
"""

from __future__ import annotations

import types

import anthropic
import httpx

from analysis import claude_client
from analysis.schema import IncidentBrief, Technique


def _usage():
    return types.SimpleNamespace(
        input_tokens=1234,
        output_tokens=210,
        cache_read_input_tokens=0,
        cache_creation_input_tokens=4096,
    )


def _brief():
    return IncidentBrief(
        summary="Instance role credentials used off-AWS.",
        severity="HIGH",
        confidence="high",
        attack_techniques=[Technique(technique_id="T1552.005", name="IMDS theft", rationale="x")],
        affected_resources=["arn:aws:iam::123456789012:role/app-server-role"],
        recommended_actions=["Revoke the role's sessions."],
    )


def _make_client(*, response=None, raise_exc=None):
    def parse(**_kwargs):
        if raise_exc is not None:
            raise raise_exc
        return response

    return types.SimpleNamespace(messages=types.SimpleNamespace(parse=parse))


def _response(*, parsed_output, stop_reason):
    resp = types.SimpleNamespace(
        parsed_output=parsed_output,
        stop_reason=stop_reason,
        usage=_usage(),
        model="claude-opus-4-8",
    )
    resp._request_id = "req_test123"
    return resp


def test_success_returns_brief(enrichment):
    client = _make_client(response=_response(parsed_output=_brief(), stop_reason="end_turn"))
    result = claude_client.analyze(enrichment, client=client)

    assert result.degraded is False
    assert isinstance(result.brief, IncidentBrief)
    assert result.request_id == "req_test123"
    assert result.usage["input_tokens"] == 1234


def test_refusal_is_degraded(enrichment):
    client = _make_client(response=_response(parsed_output=None, stop_reason="refusal"))
    result = claude_client.analyze(enrichment, client=client)

    assert result.degraded is True
    assert result.reason == "refusal"
    assert result.brief is None


def test_max_tokens_is_degraded(enrichment):
    client = _make_client(response=_response(parsed_output=None, stop_reason="max_tokens"))
    result = claude_client.analyze(enrichment, client=client)
    assert result.degraded is True
    assert result.reason == "max_tokens"


def test_api_error_is_degraded(enrichment):
    exc = anthropic.APIConnectionError(
        message="boom", request=httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    )
    client = _make_client(raise_exc=exc)
    result = claude_client.analyze(enrichment, client=client)

    assert result.degraded is True
    assert result.reason.startswith("api_error")
    assert result.brief is None
