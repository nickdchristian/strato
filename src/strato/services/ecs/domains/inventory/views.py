from typing import Any, cast

from strato.core.models import AuditResult
from strato.core.presenter import GenericView
from strato.services.ecs.domains.inventory.checks import ECSInventoryResult


class ECSInventoryView(GenericView):
    @classmethod
    def get_headers(cls, check_type: str = "INVENTORY") -> list[str]:
        return cls.get_csv_headers(check_type)

    @classmethod
    def get_csv_headers(cls, check_type: str = "INVENTORY") -> list[str]:
        return [
            "cluster_name",
            "service_name",
            "account_id",
            "region",
            "vpc_id",
            "tags",
            "task_definition",
            "launch_type",
            "capacity_provider",
            "spot_usage_percentage",
            "cpu_allocated_vcpu",
            "memory_allocated_gb",
            "cpu_utilization_avg_30d",
            "cpu_utilization_peak_30d",
            "memory_utilization_avg_30d",
            "memory_utilization_peak_30d",
            "desired_tasks",
            "running_tasks",
            "task_restarts_30d",
            "last_deployment_days_ago",
            "total_cost_30d",
            "rightsizing_recommendation",
            "estimated_monthly_waste_usd",
            "fargate_savings_potential",
            "autoscaling_enabled",
            "scaling_events_30d",
            "load_balancer_name",
            "internet_facing",
            "security_findings_critical",
            "security_findings_high",
            "overly_permissive_iam_role",
            "encryption_enabled",
            "logging_enabled",
            "health_check_grace_period_seconds",
        ]

    @classmethod
    def format_row(cls, result: AuditResult) -> list[str]:
        return cls.format_csv_row(result)

    @classmethod
    def format_csv_row(cls, result: AuditResult) -> list[str]:
        ecs_result = cast(ECSInventoryResult, result)

        def fmt(val: Any) -> str:
            if val is None:
                return ""
            if isinstance(val, dict):
                return "; ".join(f"{k}={v}" for k, v in val.items())
            return str(val)

        return [
            fmt(ecs_result.cluster_name),
            fmt(ecs_result.service_name),
            fmt(ecs_result.account_id),
            fmt(ecs_result.region),
            fmt(ecs_result.vpc_id),
            fmt(ecs_result.tags),
            fmt(ecs_result.task_definition),
            fmt(ecs_result.launch_type),
            fmt(ecs_result.capacity_provider),
            fmt(ecs_result.spot_usage_percentage),
            fmt(ecs_result.cpu_allocated_vcpu),
            fmt(ecs_result.memory_allocated_gb),
            fmt(ecs_result.cpu_utilization_avg_30d),
            fmt(ecs_result.cpu_utilization_peak_30d),
            fmt(ecs_result.memory_utilization_avg_30d),
            fmt(ecs_result.memory_utilization_peak_30d),
            fmt(ecs_result.desired_tasks),
            fmt(ecs_result.running_tasks),
            fmt(ecs_result.task_restarts_30d),
            fmt(ecs_result.last_deployment_days_ago),
            fmt(ecs_result.total_cost_30d),
            fmt(ecs_result.rightsizing_recommendation),
            fmt(ecs_result.estimated_monthly_waste_usd),
            fmt(ecs_result.fargate_savings_potential),
            fmt(ecs_result.autoscaling_enabled),
            fmt(ecs_result.scaling_events_30d),
            fmt(ecs_result.load_balancer_name),
            fmt(ecs_result.internet_facing),
            fmt(ecs_result.security_findings_critical),
            fmt(ecs_result.security_findings_high),
            fmt(ecs_result.overly_permissive_iam_role),
            fmt(ecs_result.encryption_enabled),
            fmt(ecs_result.logging_enabled),
            fmt(ecs_result.health_check_grace_period_seconds),
        ]
