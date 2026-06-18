"""Best-effort CloudWatch custom metrics.

The Lambda role is scoped to ``cloudwatch:PutMetricData`` for the CloudSentinel
namespace only. Emitting metrics must never fail the triage, so every error here
is swallowed and logged.
"""

from __future__ import annotations

import logging

import boto3

logger = logging.getLogger("cloudsentinel.metrics")


def emit(namespace: str, metrics: dict[str, float], *, client=None, dimensions: dict | None = None):
    """Publish a batch of metric values to CloudWatch."""
    client = client or boto3.client("cloudwatch")
    dims = [{"Name": k, "Value": str(v)} for k, v in (dimensions or {}).items()]
    metric_data = [
        {"MetricName": name, "Value": float(value), "Dimensions": dims}
        for name, value in metrics.items()
    ]
    try:
        client.put_metric_data(Namespace=namespace, MetricData=metric_data)
    except Exception as exc:  # noqa: BLE001 - metrics are best-effort
        logger.warning("put_metric_data failed: %s", exc)
