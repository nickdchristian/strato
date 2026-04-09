import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from strato.core.aws import safe_aws_call

logger = logging.getLogger(__name__)


class EBSClient:
    def __init__(
        self, session: boto3.Session | None = None, account_id: str = "Unknown"
    ):
        self.retry_config = Config(retries={"mode": "adaptive", "max_attempts": 10})
        self.session = session or boto3.Session()
        self.account_id = account_id
        self._client = self.session.client("ec2", config=self.retry_config)
        self._cw_client = self.session.client("cloudwatch", config=self.retry_config)
        self._kms_client = self.session.client("kms", config=self.retry_config)
        self._optimizer_enrolled = None

    def list_volumes(self) -> list[dict[str, Any]]:
        logger.debug(f"[{self.account_id}] Paginating through all EBS volumes...")
        paginator = self._client.get_paginator("describe_volumes")
        volumes = []
        for page in paginator.paginate():
            volumes.extend(page.get("Volumes", []))
        logger.debug(
            f"[{self.account_id}] Successfully retrieved {len(volumes)} EBS volumes."
        )
        return volumes

    @safe_aws_call(
        default={}, context_key=["VolumeId", "volume_id", "SnapshotId", "snapshot_id"]
    )
    def get_all_snapshots(self) -> dict[str, list[dict]]:
        logger.debug(
            f"[{self.account_id}] Fetching all owned EBS snapshots to map to volumes..."
        )
        paginator = self._client.get_paginator("describe_snapshots")
        snapshot_map = {}
        for page in paginator.paginate(OwnerIds=["self"]):
            for snap in page.get("Snapshots", []):
                vol_id = snap["VolumeId"]
                snapshot_map.setdefault(vol_id, []).append(snap)
        logger.debug(
            f"[{self.account_id}] Mapped snapshots to "
            f"{len(snapshot_map)} unique volumes."
        )
        return snapshot_map

    @safe_aws_call(
        default={}, context_key=["VolumeId", "volume_id", "SnapshotId", "snapshot_id"]
    )
    def get_instance_states(self) -> dict[str, str]:
        logger.debug(
            f"[{self.account_id}] Fetching EC2 instance states "
            f"for volume attachment context..."
        )
        paginator = self._client.get_paginator("describe_instances")
        instance_map = {}
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_map[instance["InstanceId"]] = instance["State"]["Name"]
        return instance_map

    @safe_aws_call(
        default=None, context_key=["VolumeId", "volume_id", "SnapshotId", "snapshot_id"]
    )
    def get_kms_alias(self, key_id: str | None) -> str | None:
        if not key_id:
            return None

        paginator = self._kms_client.get_paginator("list_aliases")
        for page in paginator.paginate(KeyId=key_id):
            for alias in page.get("Aliases", []):
                return alias.get("AliasName")
        return None

    def check_optimizer_enrollment(self) -> str:
        if self._optimizer_enrolled is not None:
            return self._optimizer_enrolled

        logger.debug(
            f"[{self.account_id}] Checking AWS Compute Optimizer enrollment status..."
        )
        try:
            opt_client = self.session.client(
                "compute-optimizer", config=self.retry_config
            )
            resp = opt_client.get_enrollment_status()
            status = resp.get("status", "Inactive")
            self._optimizer_enrolled = "Active" if status == "Active" else "Disabled"
        except (ClientError, Exception):
            self._optimizer_enrolled = "Unavailable"
        return self._optimizer_enrolled

    @safe_aws_call(
        default={}, context_key=["VolumeId", "volume_id", "SnapshotId", "snapshot_id"]
    )
    def get_volume_recommendations(self, volume_arns: list[str]) -> dict[str, dict]:
        if not volume_arns or self.check_optimizer_enrollment() != "Active":
            logger.debug(
                f"[{self.account_id}] Compute Optimizer disabled or no ARNs provided. "
                "Skipping recommendations."
            )
            return {}

        logger.debug(
            f"[{self.account_id}] Fetching Compute Optimizer recommendations "
            f"for {len(volume_arns)} volumes"
        )
        opt_client = self.session.client("compute-optimizer", config=self.retry_config)
        results = {}

        def chunker(seq, size):
            return (seq[pos : pos + size] for pos in range(0, len(seq), size))

        for batch in chunker(volume_arns, 100):
            try:
                resp = opt_client.get_ebs_volume_recommendations(VolumeArns=batch)
                for rec in resp.get("volumeRecommendations", []):
                    results[rec["volumeArn"]] = rec
            except ClientError:
                continue
        return results

    def get_volume_metrics(self, volume_id: str, days: int = 30) -> dict[str, float]:
        start_time = datetime.now(UTC) - timedelta(days=days)
        end_time = datetime.now(UTC)
        metrics = {
            "VolumeReadOps": 0.0,
            "VolumeWriteOps": 0.0,
            "VolumeIdleTime": 0.0,
        }
        for metric in metrics.keys():
            val = self._get_metric_avg(
                "AWS/EBS", metric, "VolumeId", volume_id, start_time, end_time
            )
            if val is not None:
                metrics[metric] = val
        return metrics

    def _get_metric_avg(
        self,
        namespace: str,
        metric_name: str,
        dimension_name: str,
        dimension_value: str,
        start_time: datetime,
        end_time: datetime,
    ) -> float | None:
        logger.debug(
            f"[{self.account_id}][{dimension_value}]"
            f" Fetching CloudWatch metric '{metric_name}'"
        )
        try:
            response = self._cw_client.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                Dimensions=[{"Name": dimension_name, "Value": dimension_value}],
                StartTime=start_time,
                EndTime=end_time,
                Period=86400,
                Statistics=["Average", "Sum"],
            )
            datapoints = response.get("Datapoints", [])
            if not datapoints:
                return None
            stat_key = "Sum" if "Ops" in metric_name else "Average"
            return sum(d[stat_key] for d in datapoints) / len(datapoints)
        except ClientError:
            return None
