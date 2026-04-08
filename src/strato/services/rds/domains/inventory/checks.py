import logging
from collections.abc import Iterable
from enum import StrEnum, auto
from typing import Any, cast

import boto3

from strato.core.models import BaseScanner, InventoryRecord
from strato.services.rds.client import RDSClient

logger = logging.getLogger(__name__)


class RDSInventoryScanType(StrEnum):
    ALL = auto()
    INVENTORY = auto()


class RDSInventoryScanner(BaseScanner[InventoryRecord]):
    is_global_service = False

    def __init__(
        self,
        check_type: str = RDSInventoryScanType.ALL,
        session: boto3.Session | None = None,
        account_id: str = "Unknown",
    ):
        super().__init__(check_type, session, account_id)
        self.client = RDSClient(session=self.session, account_id=self.account_id)

    @property
    def service_name(self) -> str:
        return "RDS Instances"

    def fetch_resources(self) -> Iterable[dict[str, Any]]:
        yield from self.client.list_instances()

    def analyze_resource(self, resource: Any) -> InventoryRecord:
        resource_data = cast(dict[str, Any], resource)
        db_id = str(resource_data.get("DBInstanceIdentifier", ""))
        arn = str(resource_data.get("DBInstanceArn", ""))

        tags = {
            str(t["Key"]): str(t["Value"]) for t in resource_data.get("TagList", [])
        }

        cpu_peak, cpu_mean = self.client.get_cpu_utilization(db_id)
        conn_peak, conn_mean = self.client.get_database_connections(db_id)
        write_peak, write_mean = self.client.get_write_throughput(db_id)
        read_peak, read_mean = self.client.get_read_throughput(db_id)

        az = str(resource_data.get("AvailabilityZone", ""))
        sg_ids = [
            str(sg["VpcSecurityGroupId"])
            for sg in resource_data.get("VpcSecurityGroups", [])
        ]
        param_groups = [
            str(pg["DBParameterGroupName"])
            for pg in resource_data.get("DBParameterGroups", [])
        ]

        endpoint = resource_data.get("Endpoint", {})
        port = int(endpoint.get("Port", 0))

        log_exports = [
            str(x) for x in resource_data.get("EnabledCloudwatchLogsExports", [])
        ]
        option_groups = [
            str(og["OptionGroupName"])
            for og in resource_data.get("OptionGroupMemberships", [])
        ]

        parsed_region = az[:-1] if az else str(self.session.region_name or "Unknown")

        details = {
            "DbClusterIdentifier": str(resource_data.get("DBClusterIdentifier", "")),
            "State": str(resource_data.get("DBInstanceStatus", "unknown")),
            "Engine": str(resource_data.get("Engine", "")),
            "EngineVersion": str(resource_data.get("EngineVersion", "")),
            "AvailabilityZone": az,
            "InstanceClass": str(resource_data.get("DBInstanceClass", "")),
            "VpcId": str(resource_data.get("DBSubnetGroup", {}).get("VpcId", "")),
            "Port": port,
            "SecurityGroupIds": sg_ids,
            "PubliclyAccessible": bool(resource_data.get("PubliclyAccessible", False)),
            "MultiAz": bool(resource_data.get("MultiAZ", False)),
            "StorageType": str(resource_data.get("StorageType", "")),
            "ProvisionedIops": int(resource_data.get("Iops", 0)),
            "StorageThroughput": int(resource_data.get("StorageThroughput", 0)),
            "IamAuthEnabled": bool(
                resource_data.get("IAMDatabaseAuthenticationEnabled", False)
            ),
            "CaCertificateIdentifier": resource_data.get("CACertificateIdentifier", ""),
            "ParameterGroups": param_groups,
            "OptionGroups": option_groups,
            "CloudwatchLogExports": log_exports,
            "PeakCpu90d": cpu_peak,
            "MeanCpu90d": cpu_mean,
            "PeakConnections90d": conn_peak,
            "MeanConnections90d": conn_mean,
            "PeakReadThroughput90d": read_peak,
            "MeanReadThroughput90d": read_mean,
            "PeakWriteThroughput90d": write_peak,
            "MeanWriteThroughput90d": write_mean,
            "AllocatedStorageGb": int(resource_data.get("AllocatedStorage", 0)),
            "MaxAllocatedStorageGb": int(resource_data.get("MaxAllocatedStorage", 0)),
            "StorageEncrypted": bool(resource_data.get("StorageEncrypted", False)),
            "BackupRetentionPeriodDays": int(
                resource_data.get("BackupRetentionPeriod", 0)
            ),
            "PreferredBackupWindow": str(
                resource_data.get("PreferredBackupWindow", "")
            ),
            "PreferredMaintenanceWindow": str(
                resource_data.get("PreferredMaintenanceWindow", "")
            ),
            "AutoMinorVersionUpgrade": bool(
                resource_data.get("AutoMinorVersionUpgrade", False)
            ),
            "DeletionProtection": bool(resource_data.get("DeletionProtection", False)),
            "PerformanceInsightsEnabled": bool(
                resource_data.get("PerformanceInsightsEnabled", False)
            ),
            "MonitoringIntervalSeconds": int(
                resource_data.get("MonitoringInterval", 0)
            ),
            "LicenseModel": str(resource_data.get("LicenseModel", "")),
            "Tags": tags,
        }

        return InventoryRecord(
            resource_arn=arn,
            resource_name=db_id,
            region=parsed_region,
            account_id=self.account_id,
            details=details,
        )
