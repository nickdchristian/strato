import json

from strato.core.models import InventoryRecord


class EC2ReservedInstanceView:
    @classmethod
    def get_headers(cls, check_type: str | None = None) -> list[str]:
        return [
            "Account ID",
            "Region",
            "RI ID",
            "Instance Type",
            "Platform",
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
            "Instance Type",
            "Scope",
            "Availability Zone",
            "Instance Count",
            "Start Date",
            "End Date",
            "Term (Days)",
            "Payment Options",
            "Offering Class",
            "Upfront Price",
            "Usage Price",
            "Hourly Charges",
            "Currency",
            "Platform",
            "Tenancy",
            "State",
            "Remaining Days",
            "Tags",
        ]

    @classmethod
    def format_row(cls, result: InventoryRecord) -> list[str]:
        d = result.details
        return [
            result.account_id,
            result.region,
            result.resource_name,
            str(d.get("InstanceType", "")),
            str(d.get("Platform", "")),
            str(d.get("State", "")),
            str(d.get("RemainingDays", 0)),
        ]

    @classmethod
    def format_csv_row(cls, result: InventoryRecord) -> list[str]:
        d = result.details

        def fmt(val):
            return "" if val is None else str(val)

        term_days = d.get("TermSeconds", 0) // 86400

        return [
            result.account_id,
            result.region,
            result.resource_name,
            result.resource_arn,
            fmt(d.get("InstanceType")),
            fmt(d.get("Scope")),
            fmt(d.get("AvailabilityZone")),
            fmt(d.get("InstanceCount")),
            fmt(d.get("Start")),
            fmt(d.get("End")),
            fmt(term_days),
            fmt(d.get("PaymentOptions")),
            fmt(d.get("OfferingClass")),
            fmt(d.get("UpfrontPrice")),
            fmt(d.get("UsagePrice")),
            fmt(d.get("RecurringCharges")),
            fmt(d.get("CurrencyCode")),
            fmt(d.get("Platform")),
            fmt(d.get("Tenancy")),
            fmt(d.get("State")),
            fmt(d.get("RemainingDays")),
            json.dumps(d.get("Tags", {})),
        ]
