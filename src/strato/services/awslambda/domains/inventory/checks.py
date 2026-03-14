import logging
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from enum import StrEnum, auto
from typing import Any, cast

import boto3

from strato.core.models import AuditResult, BaseScanner
from strato.services.awslambda.client import LambdaClient

logger = logging.getLogger(__name__)


class LambdaInventoryScanType(StrEnum):
    ALL = auto()
    INVENTORY = auto()


@dataclass
class LambdaInventoryResult(AuditResult):
    resource_id: str = ""
    check_type: str = LambdaInventoryScanType.ALL

    function_aliases: list[str] = field(default_factory=list)
    function_description: str | None = None
    function_url: str | None = None
    function_url_auth_type: str | None = None
    function_architecture: str | None = None
    runtime: str | None = None
    code_size: int = 0
    memory_size: int = 0
    last_modified: str | None = None
    architecture: str | None = None
    environment_variables: dict[str, str] = field(default_factory=dict)
    vpc_config_vpcid: str | None = None
    vpc_config_subnetid: list[str] = field(default_factory=list)
    timeout: int = 0
    provisioned_concurrency_config: str | None = None
    reserved_concurrency_limit: int | None = None
    billing_duration_ms: float = 0.0
    estimated_monthly_cost: float = 0.0
    dead_letter_queue_config: str | None = None
    cold_start_count: int = 0
    warm_start_count: int = 0
    average_duration_ms: float = 0.0
    p95_duration_ms: float = 0.0
    throttle_count: int = 0
    concurrent_executions_peak: int = 0
    concurrent_executions_average: float = 0.0
    memory_utilization_percentage: float = 0.0
    cpu_utilization_percentage: float = 0.0
    network_bytes_in: int = 0
    network_bytes_out: int = 0
    storage_bytes_used: int = 0
    kms_key_arn: str | None = None
    execution_role_arn: str | None = None
    layers: list[str] = field(default_factory=list)
    signing_profile_version_arn: str | None = None
    code_signing_config_arn: str | None = None
    event_source_mappings: list[str] = field(default_factory=list)
    destinations_on_success: list[str] = field(default_factory=list)
    destinations_on_failure: list[str] = field(default_factory=list)
    file_system_configs: list[str] = field(default_factory=list)
    image_config_entry_point: list[str] = field(default_factory=list)
    package_type: str | None = None
    tracing_config_mode: str | None = None
    log_retention_days: int | None = None
    insights_enabled: bool = False
    custom_metrics_count: int = 0
    creation_date: str | None = None
    last_invocation_date: str | None = None
    version_count: int = 0
    state: str | None = None
    state_reason: str | None = None
    invocation_count: int = 0
    duration: float = 0.0
    error_count: int = 0
    success_percentage: float = 0.0
    ephemeral_storage: int = 0
    recursive_loop: str | None = None
    triggers: list[str] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        keys_to_remove = {"findings", "status_score", "status"}
        return {k: v for k, v in data.items() if k not in keys_to_remove}


class LambdaInventoryScanner(BaseScanner[LambdaInventoryResult]):
    @property
    def service_name(self) -> str:
        return f"Lambda Inventory ({self.check_type})"

    def __init__(
        self,
        check_type: str = LambdaInventoryScanType.ALL,
        session: boto3.Session | None = None,
        account_id: str = "Unknown",
    ):
        super().__init__(check_type, session, account_id)
        self.client = LambdaClient(session=self.session, account_id=self.account_id)

    def fetch_resources(self) -> Iterable[dict[str, Any]]:
        yield from self.client.list_functions()

    def _calculate_estimated_monthly_cost(
        self, memory_mb: int, duration_ms: float, invocations: int, arch: str
    ) -> float:
        if invocations == 0 or duration_ms == 0:
            return 0.0

        rate_x86 = 0.0000166667
        rate_arm = 0.0000133334
        rate = rate_arm if arch == "arm64" else rate_x86

        gb_seconds = (memory_mb / 1024.0) * (duration_ms / 1000.0) * invocations
        compute_cost = gb_seconds * rate
        request_cost = (invocations / 1_000_000.0) * 0.20

        return round(compute_cost + request_cost, 2)

    def analyze_resource(self, resource: Any) -> LambdaInventoryResult:
        function_data = cast(dict[str, Any], resource)
        function_name = str(function_data.get("FunctionName", ""))

        logger.debug(f"[{self.account_id}][{function_name}] Starting deep analysis...")

        region = str(self.session.region_name or "Unknown")
        function_arn = str(function_data.get("FunctionArn", ""))

        vpc_config = function_data.get("VpcConfig", {})
        env_vars = function_data.get("Environment", {}).get("Variables", {})
        architectures = function_data.get("Architectures", [])
        arch = architectures[0] if architectures else "x86_64"

        layers = [layer.get("Arn", "") for layer in function_data.get("Layers", [])]
        ephemeral_storage = function_data.get("EphemeralStorage", {}).get("Size", 0)

        url, auth_type = self.client.get_function_url_details(function_name)
        tags = self.client.get_tags(function_arn)
        aliases = self.client.get_function_aliases(function_name)
        mappings = self.client.get_event_source_mappings(function_name)
        log_retention = self.client.get_log_retention(f"/aws/lambda/{function_name}")

        # Retrieve CloudWatch Metrics
        invocations = int(self.client.get_metric_sum("Invocations", function_name))
        errors = int(self.client.get_metric_sum("Errors", function_name))
        throttles = int(self.client.get_metric_sum("Throttles", function_name))
        avg_duration = self.client.get_metric_avg("Duration", function_name)
        p95_duration = self.client.get_metric_max("Duration", function_name)

        # Retrieve Insights
        mem_util = self.client.get_lambda_insight_metric(
            "memory_utilization", function_name
        )
        insights_enabled = mem_util is not None

        # Calculate aggregations
        success_pct = 100.0
        if invocations > 0:
            success_pct = max(0.0, 100.0 - ((errors / invocations) * 100.0))

        memory_size = int(function_data.get("MemorySize", 128))
        est_cost = self._calculate_estimated_monthly_cost(
            memory_size, avg_duration, invocations, arch
        )

        logger.debug(f"[{self.account_id}][{function_name}] Analysis complete.")

        return LambdaInventoryResult(
            account_id=self.account_id,
            region=region,
            resource_id=function_name,
            resource_name=function_name,
            resource_arn=function_arn,
            check_type=self.check_type,
            function_aliases=aliases,
            function_description=function_data.get("Description"),
            function_url=url,
            function_url_auth_type=auth_type,
            function_architecture=arch,
            runtime=function_data.get("Runtime"),
            code_size=int(function_data.get("CodeSize", 0)),
            memory_size=memory_size,
            last_modified=function_data.get("LastModified"),
            architecture=arch,
            environment_variables=env_vars,
            vpc_config_vpcid=vpc_config.get("VpcId"),
            vpc_config_subnetid=vpc_config.get("SubnetIds", []),
            timeout=int(function_data.get("Timeout", 0)),
            execution_role_arn=function_data.get("Role"),
            kms_key_arn=function_data.get("KMSKeyArn"),
            package_type=function_data.get("PackageType"),
            tracing_config_mode=function_data.get("TracingConfig", {}).get("Mode"),
            state=function_data.get("State"),
            state_reason=function_data.get("StateReason"),
            layers=layers,
            ephemeral_storage=ephemeral_storage,
            tags=tags,
            event_source_mappings=mappings,
            log_retention_days=log_retention,
            invocation_count=invocations,
            error_count=errors,
            throttle_count=throttles,
            average_duration_ms=round(avg_duration, 2),
            p95_duration_ms=round(p95_duration, 2),
            success_percentage=round(success_pct, 2),
            estimated_monthly_cost=est_cost,
            memory_utilization_percentage=round(mem_util, 2) if mem_util else 0.0,
            insights_enabled=insights_enabled,
        )
