import json

from strato.core.models import InventoryRecord


class EC2InventoryView:
    @classmethod
    def get_headers(cls, check_type: str = "INVENTORY") -> list[str]:
        return [
            "Account ID",
            "Region",
            "Instance Name",
            "Instance ID",
            "Type",
            "State",
            "Platform",
            "SSM Managed",
        ]

    @classmethod
    def get_csv_headers(cls, check_type: str = "INVENTORY") -> list[str]:
        return [
            "Account ID",
            "Region",
            "Instance Name",
            "Instance ID",
            "Resource ARN",
            "Instance Type",
            "State",
            "Availability Zone",
            "Private IP",
            "Public IP",
            "Launch Time",
            "Platform",
            "Architecture",
            "Lifecycle",
            "Managed by SSM",
            "Image ID",
            "AMI Name",
            "AMI Owner",
            "AMI Create Date",
            "VPC ID",
            "Subnet ID",
            "Root Device Type",
            "Highest CPU (14d)",
            "Highest CPU (90d)",
            "Highest Mem (14d)",
            "Highest Mem (90d)",
            "Network Util (14d)",
            "Network Util (90d)",
            "Rightsizing Rec",
            "Volume Count",
            "Volume Encryption",
            "Security Group Count",
            "Security Groups",
            "Inbound Ports",
            "Outbound Ports",
            "IAM Profile",
            "Monitoring",
            "Termination Protection",
            "Tags",
        ]

    @classmethod
    def format_row(cls, result: InventoryRecord) -> list[str]:
        d = result.details
        return [
            result.account_id,
            result.region,
            result.resource_name,
            str(result.resource_arn.split("/")[-1]),
            str(d.get("InstanceType", "-")),
            str(d.get("State", "-")),
            str(d.get("Platform", "-")),
            "Yes" if d.get("ManagedBySSM") else "No",
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
            result.resource_arn.split("/")[-1],
            result.resource_arn,
            fmt(d.get("InstanceType")),
            fmt(d.get("State")),
            fmt(d.get("AvailabilityZone")),
            fmt(d.get("PrivateIpAddress")),
            fmt(d.get("PublicIpAddress")),
            fmt(d.get("LaunchTime")),
            fmt(d.get("Platform")),
            fmt(d.get("Architecture")),
            fmt(d.get("InstanceLifecycle")),
            fmt(d.get("ManagedBySSM")),
            fmt(d.get("ImageId")),
            fmt(d.get("AmiName")),
            fmt(d.get("AmiOwnerAlias")),
            fmt(d.get("AmiCreateDate")),
            fmt(d.get("VpcId")),
            fmt(d.get("SubnetId")),
            fmt(d.get("RootDeviceType")),
            fmt(d.get("HighestCpu14d")),
            fmt(d.get("HighestCpu90d")),
            fmt(d.get("HighestMem14d")),
            fmt(d.get("HighestMem90d")),
            fmt(d.get("NetworkUtil14d")),
            fmt(d.get("NetworkUtil90d")),
            fmt(d.get("RightsizingRecommendation")),
            fmt(d.get("AttachedVolumeCount")),
            fmt(d.get("AttachedVolumeEncryption")),
            fmt(d.get("SecurityGroupCount")),
            ";".join(d.get("SecurityGroupIds", [])),
            ";".join(d.get("SecurityGroupInboundPorts", [])),
            ";".join(d.get("SecurityGroupOutboundPorts", [])),
            fmt(d.get("IamInstanceProfile")),
            fmt(d.get("MonitoringEnabled")),
            fmt(d.get("TerminationProtection")),
            json.dumps(d.get("Tags", {})),
        ]
