from typing import Any

from strato.services.ecs.domains.inventory.checks import ECSInventoryResult


class ECSInventoryView:
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
    def format_row(cls, result: ECSInventoryResult) -> list[str]:
        return cls.format_csv_row(result)

    @classmethod
    def format_csv_row(cls, result: ECSInventoryResult) -> list[str]:
        def fmt(val: Any) -> str:
            if val is None:
                return ""
            if isinstance(val, dict):
                return "; ".join(f"{k}={v}" for k, v in val.items())
            return str(val)

        return [
            fmt(result.cluster_name),
            fmt(result.service_name),
            fmt(result.account_id),
            fmt(result.region),
            fmt(result.vpc_id),
            fmt(result.tags),
            fmt(result.task_definition),
            fmt(result.launch_type),
            fmt(result.capacity_provider),
            fmt(result.spot_usage_percentage),
            fmt(result.cpu_allocated_vcpu),
            fmt(result.memory_allocated_gb),
            fmt(result.cpu_utilization_avg_30d),
            fmt(result.cpu_utilization_peak_30d),
            fmt(result.memory_utilization_avg_30d),
            fmt(result.memory_utilization_peak_30d),
            fmt(result.desired_tasks),
            fmt(result.running_tasks),
            fmt(result.task_restarts_30d),
            fmt(result.last_deployment_days_ago),
            fmt(result.total_cost_30d),
            fmt(result.rightsizing_recommendation),
            fmt(result.estimated_monthly_waste_usd),
            fmt(result.fargate_savings_potential),
            fmt(result.autoscaling_enabled),
            fmt(result.scaling_events_30d),
            fmt(result.load_balancer_name),
            fmt(result.internet_facing),
            fmt(result.security_findings_critical),
            fmt(result.security_findings_high),
            fmt(result.overly_permissive_iam_role),
            fmt(result.encryption_enabled),
            fmt(result.logging_enabled),
            fmt(result.health_check_grace_period_seconds),
        ]
