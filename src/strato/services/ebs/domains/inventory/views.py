import json

from strato.core.models import InventoryRecord


class EBSInventoryView:
    @classmethod
    def get_headers(cls, check_type: str) -> list[str]:
        return [
            "Account ID",
            "Region",
            "Volume ID",
            "Type",
            "Size (GB)",
            "State",
            "Attached Instances",
            "Monthly Cost",
        ]

    @classmethod
    def get_csv_headers(cls, check_type: str) -> list[str]:
        return [
            "Account ID",
            "Region",
            "Volume Name",
            "Volume ID",
            "Resource ARN",
            "Volume Type",
            "Size (GB)",
            "State",
            "IOPS",
            "Throughput",
            "Availability Zone",
            "Create Date",
            "Encrypted",
            "KMS Key Alias",
            "Attached Instances",
            "Instance States",
            "Snapshot Count",
            "Utilization Pct (30d)",
            "Last Accessed",
            "Total Monthly Cost",
            "Optimizer Recommendation",
            "Tags",
        ]

    @classmethod
    def format_row(cls, result: InventoryRecord) -> list[str]:
        d = result.details

        attached = d.get("AttachedInstances", [])
        attached_display = f"{len(attached)} instance(s)" if attached else "Unattached"

        cost = d.get("TotalMonthlyCost", 0.0)
        cost_display = f"${cost:.2f}" if cost > 0 else "-"

        return [
            result.account_id,
            result.region,
            d.get("VolumeId", result.resource_name),
            str(d.get("VolumeType", "-")),
            str(d.get("SizeGB", 0)),
            str(d.get("State", "-")),
            attached_display,
            cost_display,
        ]

    @classmethod
    def format_csv_row(cls, result: InventoryRecord) -> list[str]:
        d = result.details
        return [
            result.account_id,
            result.region,
            result.resource_name,
            str(d.get("VolumeId", "")),
            result.resource_arn,
            str(d.get("VolumeType", "")),
            str(d.get("SizeGB", "")),
            str(d.get("State", "")),
            str(d.get("Iops", "")),
            str(d.get("Throughput", "")),
            str(d.get("AvailabilityZone", "")),
            str(d.get("CreateDate", "")),
            str(d.get("Encrypted", "")),
            str(d.get("KmsKeyAlias", "")),
            ";".join(d.get("AttachedInstances", [])),
            ";".join(d.get("InstanceStates", [])),
            str(d.get("SnapshotCount", "")),
            str(d.get("UtilizationPct30d", "")),
            str(d.get("LastAccessed", "")),
            str(d.get("TotalMonthlyCost", "")),
            str(d.get("RightSizingRecommendation", "")),
            json.dumps(d.get("Tags", {})),
        ]
