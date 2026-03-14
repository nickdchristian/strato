from typing import Any, cast

from strato.core.models import AuditResult
from strato.core.presenter import GenericView
from strato.services.rds.domains.reserved.checks import RDSReservedInstanceResult


class RDSReservedInstanceView(GenericView):
    @classmethod
    def get_headers(cls, check_type: str | None = None) -> list[str]:
        return cls.get_csv_headers(check_type)

    @classmethod
    def get_csv_headers(cls, check_type: str | None = None) -> list[str]:
        return [
            "account_id",
            "region",
            "reservation_id",
            "lease_id",
            "product",
            "class",
            "offering_type",
            "status",
            "multi_az",
            "start_date",
            "remaining_days",
            "quantity",
        ]

    @classmethod
    def format_row(cls, result: AuditResult) -> list[str]:
        return cls.format_csv_row(result)

    @classmethod
    def format_csv_row(cls, result: AuditResult) -> list[str]:
        ri_result = cast(RDSReservedInstanceResult, result)

        def fmt(val: Any) -> str:
            return str(val) if val is not None else ""

        return [
            ri_result.account_id,
            ri_result.region,
            ri_result.reservation_id,
            ri_result.lease_id,
            ri_result.product,
            ri_result.class_type,
            ri_result.offering_type,
            ri_result.status,
            fmt(ri_result.multi_az),
            ri_result.start_date,
            fmt(ri_result.remaining_days),
            fmt(ri_result.quantity),
        ]
