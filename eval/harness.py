"""Evaluation harness: measure triage quality on labeled findings.

Runs the real pipeline (enrich -> Claude -> validate -> re-score) over the
hand-labeled findings in ``eval/labeled_findings/`` and reports severity-match
accuracy and mean time-to-triage — the headline numbers for the README/resume.

Makes real Claude calls (reads the key from Secrets Manager via your AWS creds),
so run it manually, not in CI:

    python eval/harness.py [--detector-id <id>]

Drop real Stratus-derived findings into ``labeled_findings/`` to strengthen it.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from analysis import claude_client, severity_scorer, validator  # noqa: E402
from enrichment import enrich  # noqa: E402

LABELED_DIR = Path(__file__).resolve().parent / "labeled_findings"


def load_labeled(directory: Path = LABELED_DIR) -> list[tuple[str, dict, str]]:
    items = []
    for path in sorted(directory.glob("*.json")):
        obj = json.loads(path.read_text(encoding="utf-8"))
        items.append((path.stem, obj["finding"], obj["expected_severity"]))
    return items


def evaluate_one(name: str, finding: dict, expected: str, detector_id: str | None = None) -> dict:
    start = time.monotonic()
    bundle = enrich(finding, detector_id=detector_id)
    result = claude_client.analyze(bundle)
    ms = int((time.monotonic() - start) * 1000)

    if result.degraded:
        return {"name": name, "expected": expected, "model": None, "final": "DEGRADED",
                "match": False, "ms": ms, "degraded": True}

    v = validator.validate_and_ground(result.brief, bundle)
    final = severity_scorer.rescore(
        bundle["finding"].get("severity") or 0,
        bundle["iam_context"].get("blast_radius", "UNKNOWN"),
        bundle["related_findings"].get("count", 0),
        v.brief.severity,
    )
    return {"name": name, "expected": expected, "model": v.brief.severity, "final": final,
            "match": final == expected, "ms": ms, "degraded": False}


def summarize(results: list[dict]) -> dict:
    n = len(results)
    matches = sum(1 for r in results if r["match"])
    mean_ms = int(sum(r["ms"] for r in results) / n) if n else 0
    return {"count": n, "matches": matches, "accuracy": (matches / n if n else 0.0),
            "mean_ms": mean_ms}


def main() -> None:
    parser = argparse.ArgumentParser(description="CloudSentinel evaluation harness")
    parser.add_argument("--detector-id", default=os.environ.get("GUARDDUTY_DETECTOR_ID"))
    args = parser.parse_args()

    labeled = load_labeled()
    if not labeled:
        print("No labeled findings in eval/labeled_findings/.")
        return

    print(f"{'finding':32} {'expected':9} {'model':9} {'final':9} {'match':6} {'ms':>7}")
    print("-" * 80)
    results = []
    for name, finding, expected in labeled:
        r = evaluate_one(name, finding, expected, args.detector_id)
        results.append(r)
        print(f"{name[:32]:32} {r['expected']:9} {str(r['model']):9} {r['final']:9} "
              f"{'OK' if r['match'] else 'MISS':6} {r['ms']:>7}")

    s = summarize(results)
    print("-" * 80)
    print(f"severity-match accuracy: {s['matches']}/{s['count']} = {s['accuracy']:.0%}")
    print(f"mean time-to-triage:     {s['mean_ms']} ms")


if __name__ == "__main__":
    main()
