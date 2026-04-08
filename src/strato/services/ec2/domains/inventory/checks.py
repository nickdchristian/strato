import logging
from collections.abc import Iterable
from datetime import datetime
from enum import StrEnum, auto
from typing import Any

import boto3

from strato.core.models import BaseScanner, InventoryRecord
from strato.services.ec2.client import EC2Client

logger = logging.getLogger(__name__)


class EC2InventoryScanType(StrEnum):
    ALL = auto()
    INVENTORY = auto()


class EC2InventoryScanner(BaseScanner[InventoryRecord]):
    is_global_service = False

    def __init__(
        self,
        check_type: str = EC2InventoryScanType.ALL,
        session: boto3.Session | None = None,
        account_id: str = "Unknown",
    ):
        super().__init__(check_type, session, account_id)
        self.client = EC2Client(session=self.session, account_id=self.account_id)
        self.optimizer_status = self.client.check_optimizer_enrollment()

    @property
    def service_name(self) -> str:
        return "EC2 Instances"

    def fetch_resources(self) -> Iterable[dict]:
        yield from self.client.list_instances()

    def analyze_resource(self, resource: Any) -> InventoryRecord:
        instance_data = resource
        instance_id = str(instance_data.get("InstanceId", ""))

        name_tag = next(
            (t["Value"] for t in instance_data.get("Tags", []) if t["Key"] == "Name"),
            instance_id,
        )
        tags = {t["Key"]: t["Value"] for t in instance_data.get("Tags", [])}

        az = instance_data.get("Placement", {}).get("AvailabilityZone")
        region = str(az[:-1] if az else (self.session.region_name or "Unknown"))

        logger.debug(f"[{self.account_id}][{instance_id}] Starting analysis...")

        mappings = instance_data.get("BlockDeviceMappings", [])
        volume_ids = [m["Ebs"]["VolumeId"] for m in mappings if "Ebs" in m]
        vol_details = self.client.get_volume_details(volume_ids)
        encryption_statuses = [v["Encrypted"] for v in vol_details.values()]

        enc_str = (
            "Encrypted"
            if all(encryption_statuses) and encryption_statuses
            else "Unencrypted"
            if not any(encryption_statuses)
            else "Mixed"
        )

        img_info = self.client.get_image_details(instance_data.get("ImageId"))

        cpu_14 = self.client.get_cpu_utilization(instance_id, days=14)
        cpu_90 = self.client.get_cpu_utilization(instance_id, days=90)
        mem_14 = self.client.get_memory_utilization(instance_id, days=14)
        mem_90 = self.client.get_memory_utilization(instance_id, days=90)
        net_14 = self.client.get_network_utilization(instance_id, days=14)
        net_90 = self.client.get_network_utilization(instance_id, days=90)

        rightsizing = None
        if self.optimizer_status != "Active":
            rightsizing = f"Optimizer{self.optimizer_status}"

        sgs = instance_data.get("SecurityGroups", [])
        sg_ids = [sg["GroupId"] for sg in sgs]
        sg_rules = self.client.get_security_group_rules(sg_ids)

        iam_profile_arn = instance_data.get("IamInstanceProfile", {}).get("Arn")
        iam_profile = iam_profile_arn.split("/")[-1] if iam_profile_arn else None

        launch_time = instance_data.get("LaunchTime")
        launch_time_str = (
            launch_time.isoformat()
            if isinstance(launch_time, datetime)
            else str(launch_time)
        )

        logger.debug(f"[{self.account_id}][{instance_id}] Analysis complete.")

        details = {
            "InstanceType": instance_data.get("InstanceType"),
            "State": instance_data.get("State", {}).get("Name"),
            "AvailabilityZone": az,
            "PrivateIpAddress": instance_data.get("PrivateIpAddress"),
            "PublicIpAddress": instance_data.get("PublicIpAddress"),
            "LaunchTime": launch_time_str,
            "Platform": instance_data.get("Platform", "linux"),
            "Architecture": instance_data.get("Architecture"),
            "InstanceLifecycle": instance_data.get("InstanceLifecycle", "on-demand"),
            "ManagedBySSM": self.client.is_instance_managed(instance_id),
            "ImageId": instance_data.get("ImageId"),
            "AmiName": img_info.get("Name"),
            "AmiOwnerAlias": img_info.get("OwnerAlias"),
            "AmiCreateDate": img_info.get("CreationDate"),
            "VpcId": instance_data.get("VpcId"),
            "SubnetId": instance_data.get("SubnetId"),
            "RootDeviceType": instance_data.get("RootDeviceType"),
            "HighestCpu14d": cpu_14,
            "HighestCpu90d": cpu_90,
            "HighestMem14d": mem_14,
            "HighestMem90d": mem_90,
            "NetworkUtil14d": net_14,
            "NetworkUtil90d": net_90,
            "RightsizingRecommendation": rightsizing,
            "AttachedVolumeCount": len(volume_ids),
            "AttachedVolumeEncryption": enc_str,
            "SecurityGroupCount": len(sgs),
            "SecurityGroupIds": sg_ids,
            "SecurityGroupInboundPorts": sg_rules["Inbound"],
            "SecurityGroupOutboundPorts": sg_rules["Outbound"],
            "IamInstanceProfile": iam_profile,
            "MonitoringEnabled": instance_data.get("Monitoring", {}).get(
                "State", "basic"
            ),
            "TerminationProtection": self.client.get_termination_protection(
                instance_id
            ),
            "Tags": tags,
        }

        return InventoryRecord(
            resource_arn=f"arn:aws:ec2:{region}:{self.account_id}:instance/{instance_id}",
            resource_name=name_tag,
            region=region,
            account_id=self.account_id,
            details=details,
        )
