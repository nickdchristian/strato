from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from typing import Any

from strato.core.models import AuditResult, BaseScanner
from strato.services.ecs.client import ECSClient


class ECSInventoryScanType(StrEnum):
    ALL = auto()
    INVENTORY = auto()


@dataclass
class ECSInventoryResult(AuditResult):
    """Lean, actionable container for ECS Inventory."""

    resource_arn: str = ""
    resource_id: str = ""
    resource_name: str = ""
    cluster_name: str = ""
    service_name: str = ""
    account_id: str = "Unknown"
    region: str = ""
    vpc_id: str | None = None
    tags: dict = field(default_factory=dict)

    task_definition: str = ""
    launch_type: str = "UNKNOWN"
    capacity_provider: str | None = None
    spot_usage_percentage: float | None = None
    cpu_allocated_vcpu: str | None = None
    memory_allocated_gb: str | None = None

    cpu_utilization_avg_30d: float = 0.0
    cpu_utilization_peak_30d: float = 0.0
    memory_utilization_avg_30d: float = 0.0
    memory_utilization_peak_30d: float = 0.0

    desired_tasks: int = 0
    running_tasks: int = 0
    task_restarts_30d: int | None = None
    last_deployment_days_ago: int | None = None

    total_cost_30d: float | None = None
    rightsizing_recommendation: str | None = None
    estimated_monthly_waste_usd: float | None = None
    fargate_savings_potential: str | None = None

    autoscaling_enabled: bool = False
    scaling_events_30d: int | None = None
    load_balancer_name: str | None = None
    internet_facing: bool | None = None

    security_findings_critical: int | None = None
    security_findings_high: int | None = None
    overly_permissive_iam_role: bool | None = None
    encryption_enabled: bool | None = None
    logging_enabled: bool = False
    health_check_grace_period_seconds: int | None = None

    check_type: str = ECSInventoryScanType.ALL

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for key in ["findings", "status_score", "status"]:
            data.pop(key, None)
        return data


class ECSInventoryScanner(BaseScanner[ECSInventoryResult]):
    def __init__(
        self,
        check_type: str = ECSInventoryScanType.ALL,
        session=None,
        account_id="Unknown",
    ):
        super().__init__(check_type, session, account_id)
        self.client = ECSClient(session=self.session)

    @property
    def service_name(self) -> str:
        return f"ECS Inventory ({self.check_type})"

    def fetch_resources(self) -> Iterable[dict]:
        clusters = self.client.list_clusters()
        for cluster_arn in clusters:
            services = self.client.list_services(cluster_arn)
            if services:
                service_details = self.client.describe_services(cluster_arn, services)
                for svc in service_details:
                    svc["_ClusterArn"] = cluster_arn
                    yield svc

    def analyze_resource(self, resource: dict) -> ECSInventoryResult:
        """
        Compiles the ECS Service/Cluster data.
        Parameter name 'resource' matches BaseScanner exactly to satisfy type checkers.
        """
        cluster_arn = resource.get("_ClusterArn", "")
        cluster_name = cluster_arn.split("/")[-1]

        service_arn = resource.get("serviceArn", "")
        service_name = resource.get("serviceName", "")
        service_id = service_arn.split("/")[-1] if service_arn else service_name

        raw_tags = resource.get("tags", [])
        tags_dict = {t["key"]: t["value"] for t in raw_tags} if raw_tags else {}

        lb_data = resource.get("loadBalancers", [])
        lb_names = [
            lb.get("targetGroupArn", "").split("/")[-2]
            for lb in lb_data
            if "targetGroupArn" in lb
        ]

        task_def_arn = resource.get("taskDefinition", "")
        task_def_details = self.client.describe_task_definition(task_def_arn)

        cpu_alloc = task_def_details.get("cpu")
        mem_alloc = task_def_details.get("memory")

        logging_enabled = False
        for container in task_def_details.get("containerDefinitions", []):
            if container.get("logConfiguration", {}).get("logDriver") == "awslogs":
                logging_enabled = True
                break

        deployments = resource.get("deployments", [])
        days_ago = None
        if deployments:
            latest_deploy = deployments[0].get("createdAt")
            if latest_deploy:
                days_ago = (datetime.now(UTC) - latest_deploy).days

        # Capacity Providers
        cp_strategy = resource.get("capacityProviderStrategy", [])
        primary_cp = cp_strategy[0].get("capacityProvider") if cp_strategy else None

        # Metrics
        cpu_metrics = self.client.get_service_metric(
            cluster_name, service_name, "CPUUtilization"
        )
        mem_metrics = self.client.get_service_metric(
            cluster_name, service_name, "MemoryUtilization"
        )

        autoscaling_enabled = self.client.is_autoscaling_enabled(
            cluster_name, service_name
        )
        scaling_events_30d = 0
        if autoscaling_enabled:
            scaling_events_30d = self.client.get_scaling_events_count(
                cluster_name, service_name, days=30
            )

        recommendation = "Optimized"
        if cpu_metrics["max"] < 30 and mem_metrics["max"] < 30:
            recommendation = "Underutilized (Scale In / Downsize)"
        elif cpu_metrics["max"] > 85 or mem_metrics["max"] > 85:
            recommendation = "Overutilized (Scale Out / Upsize)"

        return ECSInventoryResult(
            resource_arn=service_arn,
            resource_id=service_id,
            resource_name=service_name,
            cluster_name=cluster_name,
            service_name=service_name,
            account_id=self.account_id,
            region=cluster_arn.split(":")[3] if len(cluster_arn.split(":")) > 3 else "",
            tags=tags_dict,
            task_definition=task_def_arn.split("/")[-1],
            launch_type=resource.get("launchType", "CAPACITY_PROVIDER"),
            capacity_provider=primary_cp,
            cpu_allocated_vcpu=cpu_alloc,
            memory_allocated_gb=mem_alloc,
            cpu_utilization_avg_30d=cpu_metrics["avg"],
            cpu_utilization_peak_30d=cpu_metrics["max"],
            memory_utilization_avg_30d=mem_metrics["avg"],
            memory_utilization_peak_30d=mem_metrics["max"],
            desired_tasks=resource.get("desiredCount", 0),
            running_tasks=resource.get("runningCount", 0),
            last_deployment_days_ago=days_ago,
            rightsizing_recommendation=recommendation,
            load_balancer_name=";".join(lb_names) if lb_names else None,
            health_check_grace_period_seconds=resource.get(
                "healthCheckGracePeriodSeconds"
            ),
            logging_enabled=logging_enabled,
            autoscaling_enabled=autoscaling_enabled,
            scaling_events_30d=scaling_events_30d,
            check_type=self.check_type,
        )
