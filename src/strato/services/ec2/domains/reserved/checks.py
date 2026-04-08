import logging
from collections.abc import Iterable
from datetime import UTC, datetime
from enum import StrEnum, auto
from typing import Any, cast

import boto3

from strato.core.models import BaseScanner, InventoryRecord
from strato.services.ec2.client import EC2Client

logger = logging.getLogger(__name__)


class EC2ReservedScanType(StrEnum):
    RESERVED_INSTANCES = auto()


class EC2ReservedInstanceScanner(BaseScanner[InventoryRecord]):
    @property
    def service_name(self) -> str:
        return "EC2 Reserved Instances"

    def __init__(
        self,
        check_type: str = EC2ReservedScanType.RESERVED_INSTANCES,
        session: boto3.Session | None = None,
        account_id: str = "Unknown",
    ):
        super().__init__(check_type, session, account_id)
        self.client = EC2Client(session=self.session, account_id=self.account_id)

    def fetch_resources(self) -> Iterable[dict[str, Any]]:
        return self.client.get_reserved_instances()

    def analyze_resource(self, resource: Any) -> InventoryRecord:
        ri_data = cast(dict[str, Any], resource)
        ri_id = str(ri_data.get("ReservedInstancesId", ""))

        remaining_days = 0
        start_date = ri_data.get("Start")
        end_date = ri_data.get("End")

        if isinstance(start_date, datetime):
            duration = int(ri_data.get("Duration", 0))
            elapsed = (datetime.now(UTC) - start_date).days
            remaining_days = max(0, duration // 86400 - elapsed)

        charges = ri_data.get("RecurringCharges", [])
        charges_str = (
            ", ".join([f"{c.get('Amount')}/{c.get('Frequency')}" for c in charges])
            if charges
            else "None"
        )

        tags_list = ri_data.get("Tags", [])
        tags_dict = {str(t.get("Key", "")): str(t.get("Value", "")) for t in tags_list}

        region = str(self.client.session.region_name or "Unknown")

        start_str = start_date.isoformat() if isinstance(start_date, datetime) else ""
        end_str = end_date.isoformat() if isinstance(end_date, datetime) else ""

        details = {
            "InstanceType": str(ri_data.get("InstanceType", "")),
            "Scope": str(ri_data.get("Scope", "")),
            "AvailabilityZone": str(ri_data.get("AvailabilityZone", "Region")),
            "InstanceCount": int(ri_data.get("InstanceCount", 0)),
            "Start": start_str,
            "End": end_str,
            "TermSeconds": int(ri_data.get("Duration", 0)),
            "PaymentOptions": str(ri_data.get("OfferingType", "")),
            "OfferingClass": str(ri_data.get("OfferingClass", "")),
            "UpfrontPrice": float(ri_data.get("FixedPrice", 0.0)),
            "UsagePrice": float(ri_data.get("UsagePrice", 0.0)),
            "CurrencyCode": str(ri_data.get("CurrencyCode", "")),
            "RecurringCharges": charges_str,
            "Platform": str(ri_data.get("ProductDescription", "")),
            "Tenancy": str(ri_data.get("InstanceTenancy", "")),
            "State": str(ri_data.get("State", "")),
            "RemainingDays": int(remaining_days),
            "Tags": tags_dict,
        }

        return InventoryRecord(
            resource_arn=f"arn:aws:ec2:{region}:{self.account_id}:reserved-instances/{ri_id}",
            resource_name=ri_id,
            region=region,
            account_id=self.account_id,
            details=details,
        )
