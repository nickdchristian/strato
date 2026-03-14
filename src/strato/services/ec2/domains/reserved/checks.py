import logging
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from typing import Any, cast

import boto3

from strato.core.models import AuditResult, BaseScanner
from strato.services.ec2.client import EC2Client

logger = logging.getLogger(__name__)


class EC2ReservedScanType(StrEnum):
    RESERVED_INSTANCES = auto()


@dataclass
class EC2ReservedInstanceResult(AuditResult):
    """
    Data container for EC2 Reserved Instances.
    """

    account_id: str = "Unknown"
    region: str = ""
    ri_id: str = ""
    instance_type: str = ""
    scope: str = ""
    availability_zone: str = ""
    instance_count: int = 0
    start: str = ""
    expires: str = ""
    term_seconds: int = 0
    payment_options: str = ""
    offering_class: str = ""
    upfront_price: float = 0.0
    usage_price: float = 0.0
    currency_code: str = ""
    recurring_charges: str = ""
    platform: str = ""
    tenancy: str = ""
    state: str = ""
    remaining_days: int = 0
    tags: dict[str, str] = field(default_factory=dict)

    resource_arn: str = ""
    resource_id: str = ""
    resource_name: str = ""

    check_type: str = EC2ReservedScanType.RESERVED_INSTANCES

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        keys_to_remove = ["findings", "status_score", "status"]
        for key in keys_to_remove:
            data.pop(key, None)
        return data


class EC2ReservedInstanceScanner(BaseScanner[EC2ReservedInstanceResult]):
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

    def analyze_resource(self, resource: Any) -> EC2ReservedInstanceResult:
        ri_data = cast(dict[str, Any], resource)
        ri_id = str(ri_data.get("ReservedInstancesId", ""))
        logger.debug(
            f"[{self.account_id}][{ri_id}] Analyzing RI contract state and duration..."
        )

        remaining_days = 0
        start_date = ri_data.get("Start")
        end_date = ri_data.get("End")

        if isinstance(start_date, datetime):
            duration = int(ri_data.get("Duration", 0))
            elapsed = (datetime.now(UTC) - start_date).days
            remaining_days = max(0, duration // 86400 - elapsed)

        # Format recurring charges if present
        charges = ri_data.get("RecurringCharges", [])
        charges_str = (
            ", ".join([f"{c.get('Amount')}/{c.get('Frequency')}" for c in charges])
            if charges
            else "None"
        )

        tags_list = ri_data.get("Tags", [])
        tags_dict = {str(t.get("Key", "")): str(t.get("Value", "")) for t in tags_list}

        region = str(self.client.session.region_name or "Unknown")

        logger.debug(f"[{self.account_id}][{ri_id}] Analysis complete.")

        return EC2ReservedInstanceResult(
            account_id=self.account_id,
            region=region,
            ri_id=ri_id,
            instance_type=str(ri_data.get("InstanceType", "")),
            scope=str(ri_data.get("Scope", "")),
            availability_zone=str(ri_data.get("AvailabilityZone", "Region")),
            instance_count=int(ri_data.get("InstanceCount", 0)),
            start=start_date.isoformat() if isinstance(start_date, datetime) else "",
            expires=end_date.isoformat() if isinstance(end_date, datetime) else "",
            term_seconds=int(ri_data.get("Duration", 0)),
            payment_options=str(ri_data.get("OfferingType", "")),
            offering_class=str(ri_data.get("OfferingClass", "")),
            upfront_price=float(ri_data.get("FixedPrice", 0.0)),
            usage_price=float(ri_data.get("UsagePrice", 0.0)),
            currency_code=str(ri_data.get("CurrencyCode", "")),
            recurring_charges=charges_str,
            platform=str(ri_data.get("ProductDescription", "")),
            tenancy=str(ri_data.get("InstanceTenancy", "")),
            state=str(ri_data.get("State", "")),
            remaining_days=int(remaining_days),
            tags=tags_dict,
            resource_id=ri_id,
            resource_name=ri_id,
            resource_arn=f"arn:aws:ec2:{region}:{self.account_id}:reserved-instances/{ri_id}",
            check_type=self.check_type,
        )
