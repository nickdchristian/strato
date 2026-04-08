import json

from strato.core.models import InventoryRecord


class RDSInventoryView:
    @classmethod
    def get_headers(cls, check_type: str = "INVENTORY") -> list[str]:
        return [
            "Account ID",
            "Region",
            "DB Identifier",
            "Engine",
            "Class",
            "State",
            "Storage (GB)",
            "Public",
        ]

    @classmethod
    def get_csv_headers(cls, check_type: str = "INVENTORY") -> list[str]:
        return [
            "Account ID",
            "Region",
            "DB Identifier",
            "Resource ARN",
            "Cluster Identifier",
            "State",
            "Engine",
            "Engine Version",
            "Availability Zone",
            "Instance Class",
            "VPC ID",
            "Port",
            "Security Groups",
            "Publicly Accessible",
            "Multi-AZ",
            "Storage Type",
            "Allocated Storage (GB)",
            "Max Storage (GB)",
            "Encrypted",
            "Provisioned IOPS",
            "Storage Throughput",
            "IAM Auth",
            "CA Cert",
            "Parameter Groups",
            "Option Groups",
            "Log Exports",
            "Peak CPU (90d)",
            "Mean CPU (90d)",
            "Peak Conns (90d)",
            "Mean Conns (90d)",
            "Peak Read (90d)",
            "Mean Read (90d)",
            "Peak Write (90d)",
            "Mean Write (90d)",
            "Backup Retention (Days)",
            "Backup Window",
            "Maintenance Window",
            "Auto Minor Upgrade",
            "Deletion Protection",
            "Performance Insights",
            "Monitoring Interval",
            "License Model",
            "Tags",
        ]

    @classmethod
    def format_row(cls, result: InventoryRecord) -> list[str]:
        d = result.details

        return [
            result.account_id,
            result.region,
            result.resource_name,
            str(d.get("Engine", "-")),
            str(d.get("InstanceClass", "-")),
            str(d.get("State", "-")),
            str(d.get("AllocatedStorageGb", 0)),
            "Yes" if d.get("PubliclyAccessible") else "No",
        ]

    @classmethod
    def format_csv_row(cls, result: InventoryRecord) -> list[str]:
        d = result.details

        def fmt(val):
            return "" if val is None else str(val)

        return [
            result.account_id,
            result.region,
            result.resource_name,
            result.resource_arn,
            fmt(d.get("DbClusterIdentifier")),
            fmt(d.get("State")),
            fmt(d.get("Engine")),
            fmt(d.get("EngineVersion")),
            fmt(d.get("AvailabilityZone")),
            fmt(d.get("InstanceClass")),
            fmt(d.get("VpcId")),
            fmt(d.get("Port")),
            ";".join(d.get("SecurityGroupIds", [])),
            fmt(d.get("PubliclyAccessible")),
            fmt(d.get("MultiAz")),
            fmt(d.get("StorageType")),
            fmt(d.get("AllocatedStorageGb")),
            fmt(d.get("MaxAllocatedStorageGb")),
            fmt(d.get("StorageEncrypted")),
            fmt(d.get("ProvisionedIops")),
            fmt(d.get("StorageThroughput")),
            fmt(d.get("IamAuthEnabled")),
            fmt(d.get("CaCertificateIdentifier")),
            ";".join(d.get("ParameterGroups", [])),
            ";".join(d.get("OptionGroups", [])),
            ";".join(d.get("CloudwatchLogExports", [])),
            fmt(d.get("PeakCpu90d")),
            fmt(d.get("MeanCpu90d")),
            fmt(d.get("PeakConnections90d")),
            fmt(d.get("MeanConnections90d")),
            fmt(d.get("PeakReadThroughput90d")),
            fmt(d.get("MeanReadThroughput90d")),
            fmt(d.get("PeakWriteThroughput90d")),
            fmt(d.get("MeanWriteThroughput90d")),
            fmt(d.get("BackupRetentionPeriodDays")),
            fmt(d.get("PreferredBackupWindow")),
            fmt(d.get("PreferredMaintenanceWindow")),
            fmt(d.get("AutoMinorVersionUpgrade")),
            fmt(d.get("DeletionProtection")),
            fmt(d.get("PerformanceInsightsEnabled")),
            fmt(d.get("MonitoringIntervalSeconds")),
            fmt(d.get("LicenseModel")),
            json.dumps(d.get("Tags", {})),
        ]
