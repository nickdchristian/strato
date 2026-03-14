from typing import Any, cast

from strato.core.models import AuditResult
from strato.core.presenter import GenericView
from strato.services.ec2.domains.inventory.checks import EC2InventoryResult


class EC2InventoryView(GenericView):
    @classmethod
    def get_headers(cls, check_type: str = "INVENTORY") -> list[str]:
        return cls.get_csv_headers(check_type)

    @classmethod
    def get_csv_headers(cls, check_type: str = "INVENTORY") -> list[str]:
        return [
            "name",
            "account_id",
            "region",
            "instance_id",
            "instance_type",
            "state",
            "tags",
            "availability_zone",
            "private_ip",
            "private_ip6",
            "public_ip4",
            "elastic_ip",
            "launch_time",
            "platform",
            "managed",
            "architecture",
            "instance_lifecycle",
            "reserved_instance",
            "image_id",
            "ami_name",
            "ami_owner_alias",
            "source_ami_id",
            "ami_create_date",
            "marketplace_ami",
            "vpc_id",
            "subnet_id",
            "root_device_type",
            "highest_cpu_14_days",
            "highest_cpu_percentage_last_90_days",
            "highest_memory_percentage_last_14_days",
            "highest_memory_percentage_last_90_days",
            "attached_volumes",
            "attached_volume_encryption_status",
            "delete_on_termination_status",
            "hourly_cost",
            "monthly_cost_estimate",
            "savings_plan_coverage",
            "spot_price",
            "ri_coverage",
            "network_utilization_last_14_days",
            "network_utilization_last_90_days",
            "idle_time_percentage",
            "rightsizing_recommendation",
            "cost_center",
            "environment",
            "owner",
            "backup_policy",
            "generation_age",
            "burstable_credit_balance",
            "placement_group",
            "tenancy",
            "hibernation_enabled",
            "security_groups_count",
            "security_group_list",
            "security_group_inbound_ports",
            "security_group_outbound_ports",
            "iam_instance_profile",
            "monitoring_enabled",
            "termination_protection",
            "last_stop_date",
        ]

    @classmethod
    def format_row(cls, result: AuditResult) -> list[str]:
        return cls.format_csv_row(result)

    @classmethod
    def format_csv_row(cls, result: AuditResult) -> list[str]:
        ec2_result = cast(EC2InventoryResult, result)

        tags_string = "; ".join(
            f"{key}={value}" for key, value in ec2_result.tags.items()
        )
        launch_string = (
            ec2_result.launch_time.isoformat() if ec2_result.launch_time else ""
        )

        def fmt(val: Any) -> str:
            if val is None:
                return ""
            if isinstance(val, list):
                return ";".join(str(x) for x in val)
            return str(val)

        return [
            ec2_result.resource_name,
            ec2_result.account_id,
            ec2_result.region,
            ec2_result.resource_id,
            fmt(ec2_result.instance_type),
            fmt(ec2_result.state),
            tags_string,
            fmt(ec2_result.availability_zone),
            fmt(ec2_result.private_ip),
            fmt(ec2_result.private_ip6),
            fmt(ec2_result.public_ip4),
            fmt(ec2_result.elastic_ip),
            launch_string,
            fmt(ec2_result.platform),
            fmt(ec2_result.managed),
            fmt(ec2_result.architecture),
            fmt(ec2_result.instance_lifecycle),
            "",
            fmt(ec2_result.image_id),
            fmt(ec2_result.ami_name),
            fmt(ec2_result.ami_owner_alias),
            "",
            fmt(ec2_result.ami_create_date),
            "False",
            fmt(ec2_result.vpc_id),
            fmt(ec2_result.subnet_id),
            fmt(ec2_result.root_device_type),
            fmt(ec2_result.highest_cpu_14_days),
            fmt(ec2_result.highest_cpu_90_days),
            fmt(ec2_result.highest_memory_14_days),
            fmt(ec2_result.highest_memory_90_days),
            fmt(ec2_result.attached_volumes),
            fmt(ec2_result.attached_volume_encryption_status),
            fmt(ec2_result.delete_on_termination_status),
            "",
            "",
            "",
            "",
            "",
            fmt(ec2_result.network_util_14_days),
            fmt(ec2_result.network_util_90_days),
            "",
            fmt(ec2_result.rightsizing_recommendation),
            ec2_result.tags.get("CostCenter", ""),
            ec2_result.tags.get("Environment", ""),
            ec2_result.tags.get("Owner", ""),
            "",
            "",
            "0",
            "",
            "default",
            "False",
            fmt(ec2_result.security_groups_count),
            fmt(ec2_result.security_group_list),
            fmt(ec2_result.security_group_inbound_ports),
            fmt(ec2_result.security_group_outbound_ports),
            fmt(ec2_result.iam_instance_profile),
            fmt(ec2_result.monitoring_enabled),
            fmt(ec2_result.termination_protection),
            "",
        ]
