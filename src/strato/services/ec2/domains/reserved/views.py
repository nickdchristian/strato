from typing import Any, cast

from strato.core.models import AuditResult
from strato.services.ec2.domains.reserved.checks import EC2ReservedInstanceResult


class EC2ReservedInstanceView:
    @classmethod
    def get_headers(cls, check_type: str | None = None) -> list[str]:
        return [
            "account_id",
            "region",
            "id",
            "instance_type",
            "scope",
            "availability_zone",
            "instance_count",
            "start",
            "expires",
            "term_days",
            "payment_options",
            "offering_class",
            "upfront_price",
            "usage_price",
            "hourly_charges",
            "currency",
            "platform",
            "tenancy",
            "state",
            "remaining_days",
            "tags",
        ]

    @classmethod
    def format_row(cls, result: AuditResult) -> list[str]:
        ri_result = cast(EC2ReservedInstanceResult, result)

        def fmt(val: Any) -> str:
            return str(val) if val is not None else ""

        term_days = ri_result.term_seconds // 86400
        tags_str = "; ".join([f"{k}={v}" for k, v in ri_result.tags.items()])

        return [
            ri_result.account_id,
            ri_result.region,
            ri_result.ri_id,
            ri_result.instance_type,
            ri_result.scope,
            ri_result.availability_zone,
            fmt(ri_result.instance_count),
            ri_result.start,
            ri_result.expires,
            fmt(term_days),
            ri_result.payment_options,
            ri_result.offering_class,
            fmt(ri_result.upfront_price),
            fmt(ri_result.usage_price),
            ri_result.recurring_charges,
            ri_result.currency_code,
            ri_result.platform,
            ri_result.tenancy,
            ri_result.state,
            fmt(ri_result.remaining_days),
            tags_str,
        ]

    @classmethod
    def format_csv_row(cls, result: AuditResult) -> list[str]:
        return cls.format_row(result)
