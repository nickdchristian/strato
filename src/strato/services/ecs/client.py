import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Any, TypeVar, cast

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

T = TypeVar("T")


def safe_aws_call(default: Any, safe_error_codes: list[str] | None = None) -> Callable:
    if safe_error_codes is None:
        safe_error_codes = []

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            client_instance = args[0] if args else None
            acc = getattr(client_instance, "account_id", "Unknown")

            # Extract ECS-specific resource context
            context = (
                kwargs.get("cluster_arn")
                or kwargs.get("task_def_arn")
                or kwargs.get("cluster_name")
                or kwargs.get("service_name")
                or (args[1] if len(args) > 1 else "")
            )

            # Prevent massive log strings if a list of services is passed
            if isinstance(context, list):
                context = "Multiple-Services"

            func_name = getattr(func, "__name__", "unknown_callable")
            prefix = f"[{acc}]" + (f"[{context}]" if context else "")

            logger.debug(f"{prefix} {func_name}")

            try:
                return func(*args, **kwargs)
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "Unknown")

                if error_code in safe_error_codes:
                    logger.debug(f"{prefix} Safely caught expected: {error_code}")
                    return cast(T, default)

                if error_code not in ["AccessDeniedException", "InvalidParameter"]:
                    logger.warning(
                        "%s AWS Error in %s: %s - %s", prefix, func_name, error_code, e
                    )
                return cast(T, default)
            except Exception as e:
                logger.error("%s Unexpected error in %s: %s", prefix, func_name, e)
                return cast(T, default)

        return wrapper

    return decorator


class ECSClient:
    def __init__(
        self, session: boto3.Session | None = None, account_id: str = "Unknown"
    ):
        self.retry_config = Config(retries={"mode": "adaptive", "max_attempts": 10})
        self.session = session or boto3.Session()
        self.account_id = account_id
        self._client = self.session.client("ecs", config=self.retry_config)
        self._cw_client = self.session.client("cloudwatch", config=self.retry_config)
        self._app_autoscaling_client = self.session.client(
            "application-autoscaling", config=self.retry_config
        )

    @safe_aws_call(default=[])
    def list_clusters(self) -> list[str]:
        logger.debug(
            f"[{self.account_id}] Paginating through all ECS clusters in region..."
        )
        paginator = self._client.get_paginator("list_clusters")
        clusters = []
        for page in paginator.paginate():
            clusters.extend(page.get("clusterArns", []))
        logger.debug(f"[{self.account_id}] Retrieved {len(clusters)} ECS clusters.")
        return clusters

    @safe_aws_call(default=[])
    def list_services(self, cluster_arn: str) -> list[str]:
        paginator = self._client.get_paginator("list_services")
        services = []
        for page in paginator.paginate(cluster=cluster_arn):
            services.extend(page.get("serviceArns", []))
        return services

    @safe_aws_call(default=[])
    def describe_services(
        self, cluster_arn: str, service_arns: list[str]
    ) -> list[dict[str, Any]]:
        if not service_arns:
            return []

        all_services = []
        for i in range(0, len(service_arns), 10):
            chunk = service_arns[i : i + 10]
            response = self._client.describe_services(
                cluster=cluster_arn, services=chunk
            )
            all_services.extend(response.get("services", []))

        return all_services

    @safe_aws_call(default={})
    def describe_task_definition(self, task_def_arn: str) -> dict[str, Any]:
        """Fetches memory, cpu, and container details for rightsizing."""
        response = self._client.describe_task_definition(taskDefinition=task_def_arn)
        return response.get("taskDefinition", {})

    @safe_aws_call(default={"avg": 0.0, "max": 0.0})
    def get_service_metric(
        self, cluster_name: str, service_name: str, metric_name: str, days: int = 30
    ) -> dict[str, float]:
        end_time = datetime.now(UTC)
        start_time = end_time - timedelta(days=days)

        response = self._cw_client.get_metric_statistics(
            Namespace="AWS/ECS",
            MetricName=metric_name,
            Dimensions=[
                {"Name": "ClusterName", "Value": cluster_name},
                {"Name": "ServiceName", "Value": service_name},
            ],
            StartTime=start_time,
            EndTime=end_time,
            Period=86400,
            Statistics=["Average", "Maximum"],
        )

        datapoints = response.get("Datapoints", [])
        if not datapoints:
            return {"avg": 0.0, "max": 0.0}

        avg_val = sum(d["Average"] for d in datapoints) / len(datapoints)
        max_val = max(d["Maximum"] for d in datapoints)

        return {"avg": round(avg_val, 2), "max": round(max_val, 2)}

    @safe_aws_call(default=False)
    def is_autoscaling_enabled(self, cluster_name: str, service_name: str) -> bool:
        """Checks if the ECS service is registered as a scalable target."""
        resource_id = f"service/{cluster_name}/{service_name}"
        response = self._app_autoscaling_client.describe_scalable_targets(
            ServiceNamespace="ecs", ResourceIds=[resource_id]
        )
        return len(response.get("ScalableTargets", [])) > 0

    @safe_aws_call(default=0)
    def get_scaling_events_count(
        self, cluster_name: str, service_name: str, days: int = 30
    ) -> int:
        """Counts the number of scaling activities in the last X days."""
        resource_id = f"service/{cluster_name}/{service_name}"
        cutoff_date = datetime.now(UTC) - timedelta(days=days)

        paginator = self._app_autoscaling_client.get_paginator(
            "describe_scaling_activities"
        )
        event_count = 0

        for page in paginator.paginate(ServiceNamespace="ecs", ResourceId=resource_id):
            for activity in page.get("ScalingActivities", []):
                # Ensure we only count events within our 30-day lookback
                if (
                    activity.get("StartTime", datetime.min.replace(tzinfo=UTC))
                    >= cutoff_date
                ):
                    event_count += 1
                else:
                    return event_count

        return event_count
