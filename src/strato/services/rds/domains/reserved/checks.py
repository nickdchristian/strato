import logging
from collections.abc import Iterable
from datetime import UTC, datetime
from enum import StrEnum, auto
from typing import Any, cast

import boto3

from strato.core.models import BaseScanner, InventoryRecord
from strato.services.rds.client import RDSClient

logger = logging.getLogger(__name__)


class RDSReservedScanType(StrEnum):
    RESERVED_INSTANCES = auto()


class RDSReservedInstanceScanner(BaseScanner[InventoryRecord]):
    is_global_service = False

    def __init__(
        self,
        check_type: str = RDSReservedScanType.RESERVED_INSTANCES,
        session: boto3.Session | None = None,
        account_id: str = "Unknown",
    ):
        super().__init__(check_type, session, account_id)
        self.client = RDSClient(session=self.session, account_id=self.account_id)

    @property
    def service_name(self) -> str:
        return "RDS Reserved Instances"

    def fetch_resources(self) -> Iterable[dict[str, Any]]:
        return self.client.get_reserved_instances()

    def analyze_resource(self, resource: Any) -> InventoryRecord:
        ri_data = cast(dict[str, Any], resource)
        ri_id = str(ri_data.get("ReservedDBInstanceId", ""))
        arn = str(ri_data.get("ReservedDBInstanceArn", ""))

        start_date = ri_data.get("StartTime")
        remaining_days = 0
        if isinstance(start_date, datetime):
            duration = int(ri_data.get("Duration", 0))
            elapsed = (datetime.now(UTC) - start_date).days
            remaining_days = max(0, duration // 86400 - elapsed)

        region = str(self.session.region_name or "Unknown")
        start_str = start_date.isoformat() if isinstance(start_date, datetime) else ""

        details = {
            "LeaseId": str(ri_data.get("LeaseId", "")),
            "ProductDescription": str(ri_data.get("ProductDescription", "")),
            "DBInstanceClass": str(ri_data.get("DBInstanceClass", "")),
            "OfferingType": str(ri_data.get("OfferingType", "")),
            "State": str(ri_data.get("State", "")),
            "MultiAZ": bool(ri_data.get("MultiAZ", False)),
            "StartTime": start_str,
            "DurationSeconds": int(ri_data.get("Duration", 0)),
            "RemainingDays": int(remaining_days),
            "InstanceCount": int(ri_data.get("DBInstanceCount", 0)),
            "FixedPrice": float(ri_data.get("FixedPrice", 0.0)),
            "UsagePrice": float(ri_data.get("UsagePrice", 0.0)),
            "CurrencyCode": str(ri_data.get("CurrencyCode", "")),
            "RecurringCharges": ri_data.get("RecurringCharges", []),
        }

        return InventoryRecord(
            resource_arn=arn,
            resource_name=ri_id,
            region=region,
            account_id=self.account_id,
            details=details,
        )
