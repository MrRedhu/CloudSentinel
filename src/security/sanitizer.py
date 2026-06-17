"""Neutralize untrusted telemetry before it reaches the LLM.

Every value in an enrichment bundle (CloudTrail event fields, IAM names, user
agents, request parameters) is attacker-influenceable: an attacker who can name
an S3 bucket ``ignore-previous-instructions`` or stuff a prompt into a
``userAgent`` is trying to make the triage model misclassify the incident.

The defense here is *containment*, not detection. We never try to guess whether
a string "is" an injection — we make it structurally impossible for any string
to escape the data region of the prompt:

1. Recursively walk the structure; for every string leaf, strip control /
   format characters (C0/C1, bidi overrides, line/paragraph separators) that are
   used to smuggle instructions past human review, and cap its length.
2. Serialize the whole bundle as compact, ``ensure_ascii`` JSON. This turns
   every quote, newline, and angle bracket inside a value into an escaped,
   inert character — a value can contain the text ``</untrusted_data>`` but it
   can no longer *be* a closing delimiter.
3. As belt-and-suspenders, strip any literal delimiter token from the JSON text
   and wrap the result in unambiguous ``<untrusted_data>`` fences.

The system prompt instructs the model that everything inside those fences is
data to be analyzed, never instructions to follow.
"""

from __future__ import annotations

import json
import unicodedata
from typing import Any

DELIM_OPEN = "<untrusted_data>"
DELIM_CLOSE = "</untrusted_data>"

# Per-string cap. Real CloudTrail fields are short; anything longer is either
# noise or an attempt to bury an instruction in a wall of text.
MAX_FIELD_LEN = 2_000
# Hard ceiling on the serialized block, so a pathological bundle can't blow up
# the prompt (and the token bill). Enrichment already caps event counts upstream.
MAX_BLOCK_LEN = 60_000
_TRUNCATION_MARK = "...[truncated]"

# Whitespace we deliberately keep (harmless once JSON-encoded).
_KEEP_WHITESPACE = frozenset("\t\n\r ")
# Line/paragraph separators (U+2028/U+2029, categories Zl/Zp) used to fake
# line breaks past a human reviewer.
_SEPARATORS = frozenset("  ")


def _strip_control_chars(text: str) -> str:
    """Remove Unicode control/format characters used to obfuscate injections.

    Keeps ordinary whitespace (space, tab, newline) — those are harmless once
    the value is JSON-encoded — but drops C0/C1 controls, bidi overrides,
    zero-width joiners, and line/paragraph separators.
    """
    out = []
    for ch in text:
        if ch in _KEEP_WHITESPACE:
            out.append(ch)
            continue
        if ch in _SEPARATORS:
            continue
        if unicodedata.category(ch)[0] == "C":  # Cc, Cf, Cs, Co, Cn
            continue
        out.append(ch)
    return "".join(out)


def _scrub(value: Any) -> Any:
    """Recursively clean a JSON-ish value: cap strings, strip control chars."""
    if isinstance(value, str):
        cleaned = _strip_control_chars(value)
        if len(cleaned) > MAX_FIELD_LEN:
            cleaned = cleaned[:MAX_FIELD_LEN] + _TRUNCATION_MARK
        return cleaned
    if isinstance(value, dict):
        return {str(_scrub(k)): _scrub(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_scrub(v) for v in value]
    if isinstance(value, int | float | bool) or value is None:
        return value
    # Unknown type (datetime, Decimal, ...) -> stringify, then scrub.
    return _scrub(str(value))


def sanitize(enrichment: dict) -> str:
    """Return a delimited, injection-safe text block for the enrichment bundle.

    The output is safe to interpolate directly into the user message inside the
    ``<untrusted_data>`` region the system prompt warns about.
    """
    scrubbed = _scrub(enrichment)
    # sort_keys keeps the serialization deterministic — important for prompt
    # caching (a stable prefix) and for reproducible tests.
    payload = json.dumps(scrubbed, ensure_ascii=True, sort_keys=True, separators=(",", ":"))

    # Defense in depth: even though JSON-encoding already inerts the delimiter,
    # remove any literal delimiter tokens that survived as text.
    payload = payload.replace(DELIM_OPEN, "").replace(DELIM_CLOSE, "")

    if len(payload) > MAX_BLOCK_LEN:
        payload = payload[:MAX_BLOCK_LEN] + _TRUNCATION_MARK

    return f"{DELIM_OPEN}\n{payload}\n{DELIM_CLOSE}"
