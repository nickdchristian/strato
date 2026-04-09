import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from strato.core.aws import safe_aws_call

logger = logging.getLogger(__name__)


class RDSClient:
    def __init__(
        self, session: boto3.Session | None = None, account_id: str = "Unknown"
    ):
        self.retry_config = Config(retries={"mode": "adaptive", "max_attempts": 10})
        self.session = session or boto3.Session()
        self.account_id = account_id
        self._client = self.session.client("rds", config=self.retry_config)
        self._cw_client = self.session.client("cloudwatch", config=self.retry_config)

    def list_instances(self) -> list[dict[str, Any]]:
        logger.debug(f"[{self.account_id}] Fetching all RDS instances...")
        paginator = self._client.get_paginator("describe_db_instances")
        instances = []
        for page in paginator.paginate():
            instances.extend(page.get("DBInstances", []))
        logger.debug(f"[{self.account_id}] Retrieved {len(instances)} RDS instances.")
        return instances

    def get_reserved_instances(self) -> list[dict[str, Any]]:
        logger.debug(f"[{self.account_id}] Fetching active RDS Reserved Instances...")
        paginator = self._client.get_paginator("describe_reserved_db_instances")
        ris = []
        for page in paginator.paginate():
            ris.extend(page.get("ReservedDBInstances", []))
        logger.debug(f"[{self.account_id}] Retrieved {len(ris)} Reserved DB instances.")
        return ris

    @safe_aws_call(default=(0.0, 0.0), context_key=["db_identifier"])
    def get_cpu_utilization(
        self, db_identifier: str, days: int = 90
    ) -> tuple[float, float]:
        return self._get_metric_stats(
            "AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", db_identifier, days
        )

    @safe_aws_call(default=(0.0, 0.0), context_key=["db_identifier"])
    def get_database_connections(
        self, db_identifier: str, days: int = 90
    ) -> tuple[float, float]:
        return self._get_metric_stats(
            "AWS/RDS",
            "DatabaseConnections",
            "DBInstanceIdentifier",
            db_identifier,
            days,
        )

    @safe_aws_call(default=(0.0, 0.0), context_key=["db_identifier"])
    def get_write_throughput(
        self, db_identifier: str, days: int = 90
    ) -> tuple[float, float]:
        return self._get_metric_stats(
            "AWS/RDS", "WriteThroughput", "DBInstanceIdentifier", db_identifier, days
        )

    @safe_aws_call(default=(0.0, 0.0), context_key=["db_identifier"])
    def get_read_throughput(
        self, db_identifier: str, days: int = 90
    ) -> tuple[float, float]:
        return self._get_metric_stats(
            "AWS/RDS", "ReadThroughput", "DBInstanceIdentifier", db_identifier, days
        )

    def _get_metric_stats(
        self,
        namespace: str,
        metric_name: str,
        dimension_name: str,
        dimension_value: str,
        days: int,
    ) -> tuple[float, float]:
        logger.debug(
            f"Fetching CloudWatch metric '{metric_name}' for {dimension_value}"
        )
        try:
            response = self._cw_client.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                Dimensions=[{"Name": dimension_name, "Value": dimension_value}],
                StartTime=datetime.now(UTC) - timedelta(days=days),
                EndTime=datetime.now(UTC),
                Period=86400,
                Statistics=["Maximum", "Average"],
            )
            datapoints = response.get("Datapoints", [])
            if not datapoints:
                return 0.0, 0.0

            peak = max(d["Maximum"] for d in datapoints)
            mean = sum(d["Average"] for d in datapoints) / len(datapoints)
            return round(peak, 2), round(mean, 2)
        except ClientError:
            return 0.0, 0.0
