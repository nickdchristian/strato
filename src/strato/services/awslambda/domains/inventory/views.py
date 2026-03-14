import json
from typing import Any, cast

from strato.core.models import AuditResult
from strato.core.presenter import GenericView
from strato.services.awslambda.domains.inventory.checks import LambdaInventoryResult


class LambdaInventoryView(GenericView):
    @classmethod
    def get_headers(cls, check_type: str) -> list[str]:
        return [
            "region",
            "account_id",
            "function_name",
            "function_aliases",
            "function_arn",
            "function_description",
            "function_url",
            "function_url_auth_type",
            "function_architecture",
            "runtime",
            "code_size",
            "memory_size",
            "last_modified",
            "architecture",
            "environment_variables",
            "vpc_config_vpcid",
            "vpc_config_subnetid",
            "timeout",
            "provisioned_concurrency_config",
            "reserved_concurrency_limit",
            "billing_duration_ms",
            "estimated_monthly_cost",
            "dead_letter_queue_config",
            "cold_start_count",
            "warm_start_count",
            "average_duration_ms",
            "p95_duration_ms",
            "throttle_count",
            "concurrent_executions_peak",
            "concurrent_executions_average",
            "memory_utilization_percentage",
            "cpu_utilization_percentage",
            "network_bytes_in",
            "network_bytes_out",
            "storage_bytes_used",
            "kms_key_arn",
            "execution_role_arn",
            "layers",
            "signing_profile_version_arn",
            "code_signing_config_arn",
            "event_source_mappings",
            "destinations_on_success",
            "destinations_on_failure",
            "file_system_configs",
            "image_config_entry_point",
            "package_type",
            "tracing_config_mode",
            "log_retention_days",
            "insights_enabled",
            "custom_metrics_count",
            "creation_date",
            "last_invocation_date",
            "version_count",
            "state",
            "state_reason",
            "invocation_count",
            "duration",
            "error_count",
            "success_percentage",
            "ephemeral_storage",
            "recursive_loop",
            "triggers",
            "tags",
        ]

    @classmethod
    def get_csv_headers(cls, check_type: str) -> list[str]:
        return cls.get_headers(check_type)

    @classmethod
    def format_csv_row(cls, result: AuditResult) -> list[str]:  #
        lambda_result = cast(LambdaInventoryResult, result)

        def fmt(val: Any) -> str:
            """
            Serializes lists/dicts to valid JSON strings for robustness.
            """
            if val is None:
                return ""
            if isinstance(val, (list, dict)):
                return json.dumps(val)
            return str(val)

        def fmt_tags(tags: dict[str, str] | None) -> str:
            """
            Formats tags as 'Key=Value; Key2=Value2' for CSV readability.
            """
            if not tags:
                return ""

            return "; ".join(f"{k}={v}" for k, v in sorted(tags.items()))

        return [
            fmt(lambda_result.region),
            fmt(lambda_result.account_id),
            fmt(lambda_result.resource_name),
            fmt(lambda_result.function_aliases),
            fmt(lambda_result.resource_arn),
            fmt(lambda_result.function_description),
            fmt(lambda_result.function_url),
            fmt(lambda_result.function_url_auth_type),
            fmt(lambda_result.function_architecture),
            fmt(lambda_result.runtime),
            fmt(lambda_result.code_size),
            fmt(lambda_result.memory_size),
            fmt(lambda_result.last_modified),
            fmt(lambda_result.architecture),
            fmt(lambda_result.environment_variables),
            fmt(lambda_result.vpc_config_vpcid),
            fmt(lambda_result.vpc_config_subnetid),
            fmt(lambda_result.timeout),
            fmt(lambda_result.provisioned_concurrency_config),
            fmt(lambda_result.reserved_concurrency_limit),
            fmt(lambda_result.billing_duration_ms),
            fmt(lambda_result.estimated_monthly_cost),
            fmt(lambda_result.dead_letter_queue_config),
            fmt(lambda_result.cold_start_count),
            fmt(lambda_result.warm_start_count),
            fmt(lambda_result.average_duration_ms),
            fmt(lambda_result.p95_duration_ms),
            fmt(lambda_result.throttle_count),
            fmt(lambda_result.concurrent_executions_peak),
            fmt(lambda_result.concurrent_executions_average),
            fmt(lambda_result.memory_utilization_percentage),
            fmt(lambda_result.cpu_utilization_percentage),
            fmt(lambda_result.network_bytes_in),
            fmt(lambda_result.network_bytes_out),
            fmt(lambda_result.storage_bytes_used),
            fmt(lambda_result.kms_key_arn),
            fmt(lambda_result.execution_role_arn),
            fmt(lambda_result.layers),
            fmt(lambda_result.signing_profile_version_arn),
            fmt(lambda_result.code_signing_config_arn),
            fmt(lambda_result.event_source_mappings),
            fmt(lambda_result.destinations_on_success),
            fmt(lambda_result.destinations_on_failure),
            fmt(lambda_result.file_system_configs),
            fmt(lambda_result.image_config_entry_point),
            fmt(lambda_result.package_type),
            fmt(lambda_result.tracing_config_mode),
            fmt(lambda_result.log_retention_days),
            fmt(lambda_result.insights_enabled),
            fmt(lambda_result.custom_metrics_count),
            fmt(lambda_result.creation_date),
            fmt(lambda_result.last_invocation_date),
            fmt(lambda_result.version_count),
            fmt(lambda_result.state),
            fmt(lambda_result.state_reason),
            fmt(lambda_result.invocation_count),
            fmt(lambda_result.duration),
            fmt(lambda_result.error_count),
            fmt(lambda_result.success_percentage),
            fmt(lambda_result.ephemeral_storage),
            fmt(lambda_result.recursive_loop),
            fmt(lambda_result.triggers),
            fmt_tags(lambda_result.tags),
        ]
