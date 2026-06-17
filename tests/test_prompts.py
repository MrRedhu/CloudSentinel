"""Tests for the system prompt and its consistency with the allowlist."""

from __future__ import annotations

from analysis.attack import ATTACK_DESCRIPTIONS, ATTACK_TECHNIQUES
from analysis.prompts import SYSTEM_PROMPT, build_system, build_user_prompt


def test_system_block_is_cacheable():
    blocks = build_system()
    assert len(blocks) == 1
    assert blocks[0]["type"] == "text"
    assert blocks[0]["cache_control"] == {"type": "ephemeral"}
    assert blocks[0]["text"] == SYSTEM_PROMPT


def test_descriptions_cover_every_technique():
    # Prompt reference and validator allowlist must never drift apart.
    assert set(ATTACK_DESCRIPTIONS) == set(ATTACK_TECHNIQUES)


def test_prompt_states_the_untrusted_boundary():
    lowered = SYSTEM_PROMPT.lower()
    assert "<untrusted_data>" in SYSTEM_PROMPT
    assert "never instructions" in lowered or "not instructions" in lowered


def test_prompt_lists_allowlisted_techniques():
    # A representative technique id is present so the model can cite it.
    assert "T1552.005" in SYSTEM_PROMPT


def test_prompt_is_above_opus_cache_floor():
    # Opus 4.8 only caches prefixes >= ~4096 tokens. Use a conservative char
    # proxy (>= 14k chars ~= 3.5k+ tokens even at dense ~4 chars/token); runtime
    # usage.cache_creation_input_tokens is the real check.
    assert len(SYSTEM_PROMPT) >= 14_000


def test_user_prompt_wraps_the_block():
    block = "<untrusted_data>\n{}\n</untrusted_data>"
    out = build_user_prompt(block)
    assert block in out
    assert "evidence" in out.lower()
