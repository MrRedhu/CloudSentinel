"""The Claude (Opus 4.8) boundary: enrichment -> validated IncidentBrief.

API specifics (verified against the Anthropic API reference):
- ``client.messages.parse(output_format=IncidentBrief)`` -> ``parsed_output`` is a
  validated ``IncidentBrief`` (or ``None`` on refusal / parse failure).
- ``thinking={"type": "adaptive"}``; effort defaults to "high" (so we omit
  ``output_config`` entirely). ``budget_tokens``/``temperature``/``top_p`` would
  400 on Opus 4.8 — never sent.
- The system prompt is a cacheable block (``cache_control: ephemeral``).
- On ``stop_reason == "refusal"`` (rare on Opus 4.8 but possible), or any API
  error, we return a *degraded* result so the handler can still deliver the raw
  enriched context to Slack instead of going dark.

The API key is read from ``ANTHROPIC_API_KEY`` if set (local/CLI), otherwise from
Secrets Manager (Lambda) — it never lives in code, env files, or Terraform state.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from functools import lru_cache

import anthropic

from analysis.prompts import build_system, build_user_prompt
from analysis.schema import IncidentBrief
from security.sanitizer import sanitize

logger = logging.getLogger("cloudsentinel.claude")

MODEL = "claude-opus-4-8"
# Generous so adaptive thinking + the (small) JSON brief never truncate; still
# non-streaming-safe for a Lambda call.
MAX_TOKENS = 16_000

SECRET_ID_ENV = "CLOUDSENTINEL_SECRET_ID"
DEFAULT_SECRET_ID = "cloudsentinel/anthropic-api-key"


@dataclass
class AnalysisResult:
    """Outcome of one analysis attempt."""

    brief: IncidentBrief | None
    degraded: bool
    reason: str | None = None
    usage: dict | None = None
    request_id: str | None = None
    model: str | None = None


def _get_api_key() -> str:
    """Prefer the env var (local/CLI); fall back to Secrets Manager (Lambda)."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if key:
        return key
    import boto3  # local import: Lambda has boto3, CLI users may set the env var

    secret_id = os.environ.get(SECRET_ID_ENV, DEFAULT_SECRET_ID)
    client = boto3.client("secretsmanager")
    resp = client.get_secret_value(SecretId=secret_id)
    return resp["SecretString"]


@lru_cache(maxsize=1)
def get_client() -> anthropic.Anthropic:
    """Build (and cache, for Lambda warm reuse) the Anthropic client."""
    return anthropic.Anthropic(api_key=_get_api_key())


def _extract_usage(response) -> dict | None:
    usage = getattr(response, "usage", None)
    if usage is None:
        return None
    return {
        "input_tokens": getattr(usage, "input_tokens", None),
        "output_tokens": getattr(usage, "output_tokens", None),
        "cache_read_input_tokens": getattr(usage, "cache_read_input_tokens", None),
        "cache_creation_input_tokens": getattr(usage, "cache_creation_input_tokens", None),
    }


def analyze(
    enrichment: dict,
    *,
    client: anthropic.Anthropic | None = None,
    model: str = MODEL,
    max_tokens: int = MAX_TOKENS,
) -> AnalysisResult:
    """Run one Opus 4.8 structured-output analysis of an enrichment bundle."""
    client = client or get_client()
    sanitized = sanitize(enrichment)

    try:
        response = client.messages.parse(
            model=model,
            max_tokens=max_tokens,
            system=build_system(),
            messages=[{"role": "user", "content": build_user_prompt(sanitized)}],
            thinking={"type": "adaptive"},  # effort defaults to "high"
            output_format=IncidentBrief,
        )
    except (
        anthropic.RateLimitError,
        anthropic.APIStatusError,
        anthropic.APIConnectionError,
    ) as exc:
        logger.warning("Claude API error, falling back to degraded mode: %s", exc)
        return AnalysisResult(brief=None, degraded=True, reason=f"api_error:{type(exc).__name__}")

    usage = _extract_usage(response)
    request_id = getattr(response, "_request_id", None)
    stop_reason = getattr(response, "stop_reason", None)
    logger.info(
        "Claude response stop_reason=%s request_id=%s usage=%s", stop_reason, request_id, usage
    )

    if stop_reason == "refusal":
        return AnalysisResult(
            brief=None, degraded=True, reason="refusal", usage=usage, request_id=request_id
        )
    if stop_reason == "max_tokens":
        return AnalysisResult(
            brief=None, degraded=True, reason="max_tokens", usage=usage, request_id=request_id
        )

    brief = getattr(response, "parsed_output", None)
    if brief is None:
        return AnalysisResult(
            brief=None, degraded=True, reason="no_parsed_output", usage=usage, request_id=request_id
        )

    return AnalysisResult(
        brief=brief,
        degraded=False,
        usage=usage,
        request_id=request_id,
        model=getattr(response, "model", model),
    )
