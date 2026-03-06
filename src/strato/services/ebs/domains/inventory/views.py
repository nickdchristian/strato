from datetime import datetime
from typing import Any

from strato.services.ebs.domains.inventory.checks import EBSInventoryResult


class EBSInventoryView:
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
    def format_row(cls, result: EBSInventoryResult) -> list[str]:
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
            result.account_id,
            result.region,
            result.resource_name,
            fmt(result.attached_resources),
            fmt(result.instance_states),
            result.volume_id,
            fmt(result.type),
            fmt(result.size),
            fmt(result.iops),
            fmt(result.throughput),
            fmt(result.create_date),
            fmt(result.availability_zone),
            fmt(result.encrypted),
            fmt(result.kms_key_alias),
            fmt(result.total_monthly_cost),
            fmt(result.snapshot_count),
            fmt(result.utilization_percentage_30_days),
            fmt(result.last_accessed_date),
            fmt(result.right_sizing_recommendation),
            fmt(result.unused_volume_flag),
            fmt(result.overprovisioned_flag),
        ]
