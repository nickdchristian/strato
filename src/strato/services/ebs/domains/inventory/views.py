from datetime import datetime
from typing import Any, cast

from strato.core.models import AuditResult
from strato.core.presenter import GenericView
from strato.services.ebs.domains.inventory.checks import EBSInventoryResult


class EBSInventoryView(GenericView):
    @classmethod
    def get_headers(cls, check_type: str = "VOLUMES") -> list[str]:
        return [
            "account_id",
            "region",
            "name",
            "attached_resources",
            "instance_states",
            "volume_id",
            "type",
            "size",
            "iops",
            "throughput",
            "create_date",
            "availability_zone",
            "encryption",
            "kms_key_alias",
            "total_monthly_cost",
            "snapshot_count",
            "utilization_percentage_30_days",
            "last_accessed_date",
            "right_sizing_recommendation",
            "unused_volume_flag",
            "overprovisioned_flag",
        ]

    @classmethod
    def get_csv_headers(cls, check_type: str = "VOLUMES") -> list[str]:
        return cls.get_headers(check_type)

    @classmethod
    def format_row(cls, result: AuditResult) -> list[str]:
        ebs_result = cast(EBSInventoryResult, result)

        def fmt(val: Any) -> str:
            if val is None:
                return ""
            if isinstance(val, list):
                return ";".join(str(x) for x in val)
            if isinstance(val, bool):
                return str(val)
            if isinstance(val, datetime):
                return val.isoformat()
            return str(val)

        return [
            ebs_result.account_id,
            ebs_result.region,
            ebs_result.resource_name,
            fmt(ebs_result.attached_resources),
            fmt(ebs_result.instance_states),
            ebs_result.volume_id,
            fmt(ebs_result.type),
            fmt(ebs_result.size),
            fmt(ebs_result.iops),
            fmt(ebs_result.throughput),
            fmt(ebs_result.create_date),
            fmt(ebs_result.availability_zone),
            fmt(ebs_result.encrypted),
            fmt(ebs_result.kms_key_alias),
            fmt(ebs_result.total_monthly_cost),
            fmt(ebs_result.snapshot_count),
            fmt(ebs_result.utilization_percentage_30_days),
            fmt(ebs_result.last_accessed_date),
            fmt(ebs_result.right_sizing_recommendation),
            fmt(ebs_result.unused_volume_flag),
            fmt(ebs_result.overprovisioned_flag),
        ]

    @classmethod
    def format_csv_row(cls, result: AuditResult) -> list[str]:
        return cls.format_row(result)
