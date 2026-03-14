import logging
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from typing import Any

import boto3

from strato.core.models import AuditResult, BaseScanner
from strato.services.ebs.client import EBSClient

logger = logging.getLogger(__name__)


class EBSInventoryScanType(StrEnum):
    ALL = auto()
    VOLUMES = auto()


@dataclass
class EBSInventoryResult(AuditResult):
    account_id: str = "Unknown"
    region: str = ""
    resource_name: str = ""
    resource_id: str = ""
    volume_id: str = ""
    type: str | None = None
    size: int = 0
    iops: int | None = None
    throughput: int | None = None
    availability_zone: str | None = None
    create_date: datetime | None = None
    multi_attach_enabled: bool = False
    outposts_arn: str | None = None
    encrypted: bool = False
    kms_key_id: str | None = None
    kms_key_alias: str | None = None
    attached_resources: list[str] = field(default_factory=list)
    instance_states: list[str] = field(default_factory=list)
    state: str = "available"
    owner: str = ""
    costcenter: str = ""
    environment: str = ""
    projectname: str = ""
    application: str = ""
    account_email: str = "Unknown"
    tags: dict[str, str] = field(default_factory=dict)
    utilization_percentage_30_days: float = 0.0
    iops_utilization_30_days: float = 0.0
    last_accessed_date: str | None = None
    stopped_instance_activity_90_days: bool = False
    managed: bool = False
    alarm_status: str = "Unknown"
    snapshot_count: int = 0
    snapshot_costs: float = 0.0
    cost_per_gb_month: float = 0.0
    total_monthly_cost: float = 0.0
    billing_mode: str = "provisioned"
    burst_credit_balance: str | None = None
    right_sizing_recommendation: str | None = None
    type_optimization_recommendation: str | None = None
    cost_optimization_potential: float = 0.0
    estimated_monthly_savings: float = 0.0
    unused_volume_flag: bool = False
    overprovisioned_flag: bool = False
    check_type: str = EBSInventoryScanType.ALL

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if self.create_date:
            data["create_date"] = self.create_date.isoformat()

        keys_to_remove = {"findings", "status_score", "status"}
        return {k: v for k, v in data.items() if k not in keys_to_remove}


class EBSInventoryScanner(BaseScanner[EBSInventoryResult]):
    PRICE_GP3_GB = 0.08
    PRICE_GP2_GB = 0.10
    GP3_FREE_IOPS = 3000
    GP3_FREE_THROUGHPUT = 125

    @property
    def service_name(self) -> str:
        return f"EBS Inventory ({self.check_type})"

    def __init__(
        self,
        check_type: str,
        session: boto3.Session,
        account_id: str,
    ):
        super().__init__(check_type, session, account_id)
        self.client = EBSClient(session=self.session, account_id=self.account_id)
        self.optimizer_status = self.client.check_optimizer_enrollment()
        self.snapshot_map: dict[str, list[Any]] = {}
        self.instance_map: dict[str, str] = {}
        self.recommendations: dict[str, dict[str, Any]] = {}

    def fetch_resources(self) -> Iterable[dict[str, Any]]:
        volumes = self.client.list_volumes()
        self.snapshot_map = self.client.get_all_snapshots()
        self.instance_map = self.client.get_instance_states()

        region = str(self.session.region_name or "Unknown")
        arns = [
            f"arn:aws:ec2:{region}:{self.account_id}:volume/{v.get('VolumeId', '')}"
            for v in volumes
        ]
        self.recommendations = self.client.get_volume_recommendations(arns)

        for v in volumes:
            v["Region"] = region
            yield v

    def _calculate_utilization(
        self, vol_id: str, create_date: datetime | Any | None
    ) -> tuple[float, str]:
        metrics = self.client.get_volume_metrics(vol_id, days=30)

        if isinstance(create_date, datetime):
            days_active = min(30, (datetime.now(UTC) - create_date).days)
        else:
            days_active = 30

        divisor = float(max(1, days_active) * 864.0)
        idle_time = float(metrics.get("VolumeIdleTime") or 0.0)
        util_pct = max(0.0, 100.0 - (idle_time / divisor))

        total_ops = int(metrics.get("VolumeReadOps") or 0) + int(
            metrics.get("VolumeWriteOps") or 0
        )
        last_accessed = (
            datetime.now(UTC).strftime("%Y-%m-%d") if total_ops > 0 else "Unknown"
        )

        return round(util_pct, 2), last_accessed

    def _calculate_monthly_cost(
        self, vol_type: str | None, size_gb: int, iops: int, throughput: int
    ) -> float:
        if not vol_type:
            return 0.0

        if vol_type == "gp3":
            cost = float(size_gb) * self.PRICE_GP3_GB
            cost += float(max(0, iops - self.GP3_FREE_IOPS)) * 0.005
            cost += float(max(0, throughput - self.GP3_FREE_THROUGHPUT)) * 0.04
            return round(cost, 2)
        if vol_type == "gp2":
            return round(float(size_gb) * self.PRICE_GP2_GB, 2)
        if "io" in vol_type:
            return round((float(size_gb) * 0.125) + (float(iops) * 0.065), 2)
        return 0.0

    def analyze_resource(self, resource: Any) -> EBSInventoryResult:
        vol_data = resource
        vol_id = str(vol_data.get("VolumeId", ""))
        region = str(vol_data.get("Region", "Unknown"))
        vol_arn = f"arn:aws:ec2:{region}:{self.account_id}:volume/{vol_id}"

        logger.debug(f"[{self.account_id}][{vol_id}] Starting analysis...")
        raw_vol_type = vol_data.get("VolumeType")
        vol_type = str(raw_vol_type) if raw_vol_type else None

        size_gb = int(vol_data.get("Size") or 0)
        iops = int(vol_data.get("Iops") or 0)
        throughput = int(vol_data.get("Throughput") or 0)

        raw_tags = vol_data.get("Tags") or []
        tags = {str(t.get("Key", "")): str(t.get("Value", "")) for t in raw_tags}

        raw_attachments = vol_data.get("Attachments") or []
        attached_ids = [str(a.get("InstanceId", "")) for a in raw_attachments]
        instance_states = [
            str(self.instance_map.get(iid, "Unknown")) for iid in attached_ids
        ]

        util_pct, last_accessed = self._calculate_utilization(
            vol_id, vol_data.get("CreateTime")
        )

        monthly_cost = self._calculate_monthly_cost(
            vol_type=vol_type, size_gb=size_gb, iops=iops, throughput=throughput
        )

        rec = self.recommendations.get(vol_arn) or {}

        logger.debug(f"[{self.account_id}][{vol_id}] Analysis complete.")

        return EBSInventoryResult(
            account_id=self.account_id,
            region=region,
            resource_id=vol_id,
            resource_name=tags.get("Name", vol_id),
            resource_arn=vol_arn,
            volume_id=vol_id,
            type=vol_type,
            size=size_gb,
            iops=vol_data.get("Iops"),
            throughput=vol_data.get("Throughput"),
            availability_zone=vol_data.get("AvailabilityZone"),
            create_date=vol_data.get("CreateTime"),
            encrypted=bool(vol_data.get("Encrypted", False)),
            kms_key_id=vol_data.get("KmsKeyId"),
            kms_key_alias=self.client.get_kms_alias(vol_data.get("KmsKeyId")),
            attached_resources=attached_ids,
            instance_states=instance_states,
            state=str(vol_data.get("State", "Unknown")),
            tags=tags,
            utilization_percentage_30_days=util_pct,
            last_accessed_date=last_accessed,
            snapshot_count=len(self.snapshot_map.get(vol_id, [])),
            total_monthly_cost=monthly_cost,
            billing_mode=vol_type or "provisioned",
            right_sizing_recommendation=rec.get("finding"),
            unused_volume_flag=(len(attached_ids) == 0),
            overprovisioned_flag=(util_pct < 1.0 and len(attached_ids) > 0),
            check_type=self.check_type,
        )
