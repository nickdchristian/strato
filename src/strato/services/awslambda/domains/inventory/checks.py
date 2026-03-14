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

    def analyze_resource(self, resource: Any) -> LambdaInventoryResult:
        function_data = cast(dict[str, Any], resource)
        function_name = str(function_data.get("FunctionName", ""))

        logger.debug(f"[{self.account_id}][{function_name}] Starting deep analysis...")

        region = str(self.session.region_name or "Unknown")
        function_arn = str(function_data.get("FunctionArn", ""))

        vpc_config = function_data.get("VpcConfig", {})
        env_vars = function_data.get("Environment", {}).get("Variables", {})
        architectures = function_data.get("Architectures", [])
        arch = architectures[0] if architectures else None

        layers = [layer.get("Arn", "") for layer in function_data.get("Layers", [])]
        ephemeral_storage = function_data.get("EphemeralStorage", {}).get("Size", 0)

        logger.debug(f"[{self.account_id}][{function_name}] Analysis complete.")

        return LambdaInventoryResult(
            account_id=self.account_id,
            region=region,
            resource_id=function_name,
            resource_name=function_name,
            resource_arn=function_arn,
            check_type=self.check_type,
            function_description=function_data.get("Description"),
            runtime=function_data.get("Runtime"),
            code_size=int(function_data.get("CodeSize", 0)),
            memory_size=int(function_data.get("MemorySize", 0)),
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
        )
