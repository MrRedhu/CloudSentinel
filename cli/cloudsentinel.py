"""CloudSentinel CLI — run the triage pipeline on demand.

The interview/demo path: point it at a GuardDuty finding id (or a finding JSON
file) and watch the same enrich -> Claude -> validate -> re-score pipeline the
Lambda runs, printed to your terminal in seconds.

    python cli/cloudsentinel.py analyze --finding-id <id>
    python cli/cloudsentinel.py analyze --file tests/sample_findings/x.json
    python cli/cloudsentinel.py analyze --finding-id <id> --deliver   # also Slack/S3/DDB

Reads the Anthropic key from Secrets Manager via your AWS creds (or
ANTHROPIC_API_KEY), so no key handling is needed locally.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import boto3
import click

# Make src/ importable when run directly (mirrors the Lambda's root = src/).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from analysis import claude_client, severity_scorer, validator  # noqa: E402
from enrichment import enrich  # noqa: E402

DEFAULT_REGION = "us-east-1"


def _load_finding(finding_id, file_path, detector_id, region):
    if file_path:
        obj = json.loads(Path(file_path).read_text(encoding="utf-8"))
        if isinstance(obj, dict) and "detail" in obj:
            return obj["detail"]
        if isinstance(obj, dict) and "Findings" in obj:
            return obj["Findings"][0]
        return obj
    if not detector_id:
        raise click.UsageError("--finding-id requires --detector-id (or GUARDDUTY_DETECTOR_ID).")
    client = boto3.client("guardduty", region_name=region)
    resp = client.get_findings(DetectorId=detector_id, FindingIds=[finding_id])
    findings = resp.get("Findings", [])
    if not findings:
        raise click.ClickException(f"No finding found for id {finding_id}")
    return findings[0]


def _print_brief(brief, final_severity, bundle, result, elapsed_ms):
    f = bundle["finding"]
    click.echo("=" * 72)
    sev_label = f"  {final_severity}  "
    click.secho(sev_label, bg=_sev_color(final_severity), fg="white", bold=True, nl=False)
    click.echo(f"  {f.get('type')}")
    click.echo("=" * 72)
    click.echo(f"finding:        {f.get('id')}")
    click.echo(f"confidence:     {brief.confidence}")
    click.echo(f"blast radius:   {bundle['iam_context'].get('blast_radius')}")
    click.echo(f"related:        {bundle['related_findings'].get('count')}")
    click.echo(f"cloudtrail:     {len(bundle.get('cloudtrail_events', []))} events")
    click.echo("")
    click.secho("Summary", bold=True)
    click.echo(_wrap(brief.summary))
    if brief.attack_techniques:
        click.echo("")
        click.secho("MITRE ATT&CK", bold=True)
        for t in brief.attack_techniques:
            click.echo(f"  {t.technique_id}  {t.name}")
    click.echo("")
    click.secho("Recommended actions", bold=True)
    for i, a in enumerate(brief.recommended_actions, 1):
        click.echo(f"  {i}. {a}")
    click.echo("")
    usage = result.usage or {}
    meta = (
        f"[{elapsed_ms} ms | in {usage.get('input_tokens')} "
        f"out {usage.get('output_tokens')} "
        f"cache_read {usage.get('cache_read_input_tokens')} | req {result.request_id}]"
    )
    click.secho(meta, dim=True)


def _sev_color(sev):
    colors = {"LOW": "blue", "MEDIUM": "yellow", "HIGH": "magenta", "CRITICAL": "red"}
    return colors.get(sev, "white")


def _wrap(text, width=72):
    import textwrap

    return "\n".join(textwrap.wrap(text, width=width))


@click.group()
def cli():
    """CloudSentinel — AI-powered GuardDuty triage."""


@cli.command()
@click.option("--finding-id", help="GuardDuty finding id to fetch and triage.")
@click.option("--file", "file_path", type=click.Path(exists=True), help="Finding JSON file.")
@click.option("--detector-id", envvar="GUARDDUTY_DETECTOR_ID", help="GuardDuty detector id.")
@click.option("--region", default=DEFAULT_REGION, show_default=True)
@click.option(
    "--deliver/--no-deliver",
    default=False,
    help="Send through the deployed Lambda (real Slack/S3/DDB) instead of printing locally.",
)
@click.option("--function-name", default="cloudsentinel-triage", show_default=True)
def analyze(finding_id, file_path, detector_id, region, deliver, function_name):
    """Run the triage pipeline on a finding and print the brief."""
    if not finding_id and not file_path:
        raise click.UsageError("Provide --finding-id or --file.")

    finding = _load_finding(finding_id, file_path, detector_id, region)

    if deliver:
        # Invoke the deployed Lambda so it runs the full pipeline with its own
        # secrets/permissions (and the EventBridge code path).
        client = boto3.client("lambda", region_name=region)
        resp = client.invoke(
            FunctionName=function_name, Payload=json.dumps({"detail": finding}).encode("utf-8")
        )
        click.echo(resp["Payload"].read().decode("utf-8"))
        return

    start = time.monotonic()
    bundle = enrich(finding, detector_id=detector_id)
    result = claude_client.analyze(bundle)
    elapsed_ms = int((time.monotonic() - start) * 1000)

    if result.degraded:
        click.secho(f"AI analysis unavailable (reason: {result.reason}).", fg="yellow")
        click.echo(f"blast radius:   {bundle['iam_context'].get('blast_radius')}")
        click.echo(f"cloudtrail:     {len(bundle.get('cloudtrail_events', []))} events")
        return

    v = validator.validate_and_ground(result.brief, bundle)
    final = severity_scorer.rescore(
        bundle["finding"].get("severity") or 0,
        bundle["iam_context"].get("blast_radius", "UNKNOWN"),
        bundle["related_findings"].get("count", 0),
        v.brief.severity,
    )
    _print_brief(v.brief, final, bundle, result, elapsed_ms)
    if v.dropped_techniques or v.dropped_resources:
        click.secho(
            f"(validator dropped techniques={v.dropped_techniques} "
            f"resources={v.dropped_resources})",
            dim=True,
        )


if __name__ == "__main__":
    cli()
