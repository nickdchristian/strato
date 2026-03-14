from typing import Any, cast

from strato.core.models import AuditResult
from strato.core.presenter import GenericView
from strato.services.rds.domains.inventory.checks import RDSInventoryResult


class RDSInventoryView(GenericView):
    @classmethod
    def get_headers(cls, check_type: str = "INVENTORY") -> list[str]:
        return cls.get_csv_headers(check_type)

    @classmethod
    def get_csv_headers(cls, check_type: str = "INVENTORY") -> list[str]:
        return [
            "account_id",
            "region",
            "db_identifier",
            "db_cluster_identifier",
            "status",
            "tags",
            "rds_extended_support",
            "engine",
            "engine_version",
            "availability_zone",
            "size",
            "publicly_accessible",
            "vpc",
            "port",
            "security_group_ids",
            "multi-az",
            "storage_type",
            "allocated_storage",
            "max_allocated_storage",
            "storage_encrypted",
            "provisioned_iops",
            "storage_throughput",
            "iam_auth_enabled",
            "ca_certificate_identifier",
            "parameter_groups",
            "option_groups",
            "enabled_cloudwatch_logs_exports",
            "peak_active_session_count_90_days",
            "mean_active_session_count_90_days",
            "peak_active_transactions_count_90_days",
            "mean_active_transactions_count_90_days",
            "peak_commit_throughput_90_days",
            "mean_commit_throughput_90_days",
            "peak_cpu_utilization_90_days",
            "mean_cpu_utilization_90_days",
            "peak_database_connections_90_days",
            "mean_database_connections_90_days",
            "peak_read_throughput_90_days",
            "mean_read_throughput_90_days",
            "peak_write_throughput_90_days",
            "mean_write_throughput_90_days",
            "backup_retention_period",
            "preferred_backup_window",
            "preferred_maintenance_window",
            "auto_minor_version_upgrade",
            "deletion_protection",
            "performance_insights_enabled",
            "monitoring_interval",
            "enhanced_monitoring_resource_arn",
            "license_model",
            "monthly_cost_estimate",
            "reserved_instance_coverage",
            "rightsizing_recommendation",
            "utilization_score",
            "cost_optimization_opportunity",
        ]

    @classmethod
    def format_row(cls, result: AuditResult) -> list[str]:
        return cls.format_csv_row(result)

    @classmethod
    def format_csv_row(cls, result: AuditResult) -> list[str]:
        rds_result = cast(RDSInventoryResult, result)
        tags_string = "; ".join(
            f"{key}={value}" for key, value in rds_result.tags.items()
        )

        def fmt(val: Any) -> str:
            if val is None:
                return ""
            if isinstance(val, list):
                return ";".join(str(x) for x in val)
            return str(val)

        return [
            rds_result.account_id,
            rds_result.region,
            rds_result.db_identifier,
            rds_result.db_cluster_identifier,
            rds_result.status,
            tags_string,
            fmt(rds_result.rds_extended_support),
            fmt(rds_result.engine),
            fmt(rds_result.engine_version),
            fmt(rds_result.availability_zone),
            fmt(rds_result.size),
            fmt(rds_result.publicly_accessible),
            fmt(rds_result.vpc),
            fmt(rds_result.port),
            fmt(rds_result.security_group_ids),
            fmt(rds_result.multi_az),
            fmt(rds_result.storage_type),
            fmt(rds_result.allocated_storage),
            fmt(rds_result.max_allocated_storage),
            fmt(rds_result.storage_encrypted),
            fmt(rds_result.provisioned_iops),
            fmt(rds_result.storage_throughput),
            fmt(rds_result.iam_auth_enabled),
            fmt(rds_result.ca_certificate_identifier),
            fmt(rds_result.parameter_groups),
            fmt(rds_result.option_groups),
            fmt(rds_result.enabled_cloudwatch_logs_exports),
            fmt(rds_result.peak_active_session_count_90_days),
            fmt(rds_result.mean_active_session_count_90_days),
            fmt(rds_result.peak_active_transactions_count_90_days),
            fmt(rds_result.mean_active_transactions_count_90_days),
            fmt(rds_result.peak_commit_throughput_90_days),
            fmt(rds_result.mean_commit_throughput_90_days),
            fmt(rds_result.peak_cpu_utilization_90_days),
            fmt(rds_result.mean_cpu_utilization_90_days),
            fmt(rds_result.peak_database_connections_90_days),
            fmt(rds_result.mean_database_connections_90_days),
            fmt(rds_result.peak_read_throughput_90_days),
            fmt(rds_result.mean_read_throughput_90_days),
            fmt(rds_result.peak_write_throughput_90_days),
            fmt(rds_result.mean_write_throughput_90_days),
            fmt(rds_result.backup_retention_period),
            fmt(rds_result.preferred_backup_window),
            fmt(rds_result.preferred_maintenance_window),
            fmt(rds_result.auto_minor_version_upgrade),
            fmt(rds_result.deletion_protection),
            fmt(rds_result.performance_insights_enabled),
            fmt(rds_result.monitoring_interval),
            fmt(rds_result.enhanced_monitoring_resource_arn),
            fmt(rds_result.license_model),
            fmt(rds_result.monthly_cost_estimate),
            fmt(rds_result.reserved_instance_coverage),
            fmt(rds_result.rightsizing_recommendation),
            fmt(rds_result.utilization_score),
            fmt(rds_result.cost_optimization_opportunity),
        ]
