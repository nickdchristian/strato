import json

from strato.core.models import InventoryRecord


class RDSReservedInstanceView:
    @classmethod
    def get_headers(cls, check_type: str | None = None) -> list[str]:
        return [
            "Account ID",
            "Region",
            "RI ID",
            "Class",
            "Product",
            "State",
            "Remaining Days",
        ]

    @classmethod
    def get_csv_headers(cls, check_type: str | None = None) -> list[str]:
        return [
            "Account ID",
            "Region",
            "RI ID",
            "Resource ARN",
            "Lease ID",
            "Product Description",
            "Instance Class",
            "Offering Type",
            "State",
            "Multi-AZ",
            "Start Time",
            "Term (Days)",
            "Remaining Days",
            "Instance Count",
            "Fixed Price",
            "Usage Price",
            "Currency",
            "Recurring Charges",
        ]

    @classmethod
    def format_row(cls, result: InventoryRecord) -> list[str]:
        d = result.details
        return [
            result.account_id,
            result.region,
            result.resource_name,
            str(d.get("DBInstanceClass", "-")),
            str(d.get("ProductDescription", "-")),
            str(d.get("State", "-")),
            str(d.get("RemainingDays", 0)),
        ]

    @classmethod
    def format_csv_row(cls, result: InventoryRecord) -> list[str]:
        d = result.details

        def fmt(val):
            return "" if val is None else str(val)

        term_days = d.get("DurationSeconds", 0) // 86400

        return [
            result.account_id,
            result.region,
            result.resource_name,
            result.resource_arn,
            fmt(d.get("LeaseId")),
            fmt(d.get("ProductDescription")),
            fmt(d.get("DBInstanceClass")),
            fmt(d.get("OfferingType")),
            fmt(d.get("State")),
            fmt(d.get("MultiAZ")),
            fmt(d.get("StartTime")),
            fmt(term_days),
            fmt(d.get("RemainingDays")),
            fmt(d.get("InstanceCount")),
            fmt(d.get("FixedPrice")),
            fmt(d.get("UsagePrice")),
            fmt(d.get("CurrencyCode")),
            json.dumps(d.get("RecurringCharges", [])),
        ]
