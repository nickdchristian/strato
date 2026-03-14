import logging
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum, auto
from typing import Any, cast

import boto3

from strato.core.models import AuditResult, BaseScanner
from strato.services.rds.client import RDSClient

logger = logging.getLogger(__name__)


class RDSReservedScanType(StrEnum):
    RESERVED_INSTANCES = auto()


@dataclass
class RDSReservedInstanceResult(AuditResult):
    """
    Data container for RDS Reserved Instances.
    """

    account_id: str = "Unknown"
    region: str = ""
    reservation_id: str = ""
    lease_id: str = ""
    product: str = ""
    class_type: str = ""
    offering_type: str = ""
    state: str = ""
    multi_az: bool = False
    start_date: str = ""
    remaining_days: int = 0
    quantity: int = 0

    resource_arn: str = ""
    resource_id: str = ""
    resource_name: str = ""

    check_type: str = RDSReservedScanType.RESERVED_INSTANCES

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        keys_to_remove = ["findings", "status_score", "status"]
        for key in keys_to_remove:
            data.pop(key, None)
        return data


class RDSReservedInstanceScanner(BaseScanner[RDSReservedInstanceResult]):
    def __init__(
        self,
        check_type: str = RDSReservedScanType.RESERVED_INSTANCES,
        session: boto3.Session | None = None,
        account_id: str = "Unknown",
    ):
        super().__init__(check_type, session, account_id)
        self.client = RDSClient(session=self.session, account_id=self.account_id)
        logger.debug(f"Initialized RDSReservedInstanceScanner for account {account_id}")

    @property
    def service_name(self) -> str:
        return "RDS Reserved Instances"

    def fetch_resources(self) -> Iterable[dict[str, Any]]:
        logger.debug("Requesting Reserved Instance list from AWS...")
        return self.client.get_reserved_instances()

    def analyze_resource(self, resource: Any) -> RDSReservedInstanceResult:
        ri_data = cast(dict[str, Any], resource)
        ri_id = str(ri_data.get("ReservedDBInstanceId", ""))

        logger.debug(f"[{ri_id}] Analyzing RI contract state and duration...")
        start_date = ri_data.get("StartTime")
        remaining_days = 0
        if isinstance(start_date, datetime):
            duration = int(ri_data.get("Duration", 0))
            elapsed = (datetime.now(UTC) - start_date).days
            remaining_days = max(0, duration // 86400 - elapsed)

        region = str(self.session.region_name or "Unknown")

        logger.debug(f"[{ri_id}] Analysis complete.")

        return RDSReservedInstanceResult(
            account_id=self.account_id,
            region=region,
            reservation_id=ri_id,
            lease_id=str(ri_data.get("LeaseId", "")),
            product=str(ri_data.get("ProductDescription", "")),
            class_type=str(ri_data.get("DBInstanceClass", "")),
            offering_type=str(ri_data.get("OfferingType", "")),
            state=str(ri_data.get("State", "")),
            multi_az=bool(ri_data.get("MultiAZ", False)),
            start_date=start_date.isoformat()
            if isinstance(start_date, datetime)
            else "",
            remaining_days=int(remaining_days),
            quantity=int(ri_data.get("DBInstanceCount", 0)),
            resource_id=ri_id,
            resource_name=ri_id,
            resource_arn=str(ri_data.get("ReservedDBInstanceArn", "")),
            check_type=self.check_type,
        )
