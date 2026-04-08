import json

from strato.core.models import InventoryRecord


class ECSInventoryView:
    @classmethod
    def get_headers(cls, check_type: str = "INVENTORY") -> list[str]:
        return [
            "Account ID",
            "Region",
            "Cluster Name",
            "Service Name",
            "Launch Type",
            "Tasks (Run/Des)",
            "Autoscaling",
            "Rec",
        ]

    @classmethod
    def get_csv_headers(cls, check_type: str = "INVENTORY") -> list[str]:
        return [
            "Account ID",
            "Region",
            "Cluster Name",
            "Service Name",
            "Resource ARN",
            "Task Definition",
            "Launch Type",
            "Capacity Provider",
            "CPU Allocated (vCPU)",
            "Memory Allocated (GB)",
            "CPU Util Avg (30d)",
            "CPU Util Peak (30d)",
            "Memory Util Avg (30d)",
            "Memory Util Peak (30d)",
            "Desired Tasks",
            "Running Tasks",
            "Last Deployment (Days Ago)",
            "Rightsizing Recommendation",
            "Load Balancers",
            "Health Check Grace Period (s)",
            "Logging Enabled",
            "Autoscaling Enabled",
            "Scaling Events (30d)",
            "Tags",
        ]

    @classmethod
    def format_row(cls, result: InventoryRecord) -> list[str]:
        d = result.details
        tasks_display = f"{d.get('RunningTasks', 0)} / {d.get('DesiredTasks', 0)}"

        # Abbreviate recommendation for terminal table
        rec = str(d.get("RightsizingRecommendation", "Optimized"))
        if "Underutilized" in rec:
            rec_short = "Scale In"
        elif "Overutilized" in rec:
            rec_short = "Scale Out"
        else:
            rec_short = "Ok"

        return [
            result.account_id,
            result.region,
            str(d.get("ClusterName", "-")),
            result.resource_name,
            str(d.get("LaunchType", "-")),
            tasks_display,
            "Yes" if d.get("AutoscalingEnabled") else "No",
            rec_short,
        ]

    @classmethod
    def format_csv_row(cls, result: InventoryRecord) -> list[str]:
        d = result.details

        def fmt(val):
            return "" if val is None else str(val)

        return [
            result.account_id,
            result.region,
            fmt(d.get("ClusterName")),
            result.resource_name,
            result.resource_arn,
            fmt(d.get("TaskDefinition")),
            fmt(d.get("LaunchType")),
            fmt(d.get("CapacityProvider")),
            fmt(d.get("CpuAllocatedVcpu")),
            fmt(d.get("MemoryAllocatedGb")),
            fmt(d.get("CpuUtilizationAvg30d")),
            fmt(d.get("CpuUtilizationPeak30d")),
            fmt(d.get("MemoryUtilizationAvg30d")),
            fmt(d.get("MemoryUtilizationPeak30d")),
            fmt(d.get("DesiredTasks")),
            fmt(d.get("RunningTasks")),
            fmt(d.get("LastDeploymentDaysAgo")),
            fmt(d.get("RightsizingRecommendation")),
            ";".join(d.get("LoadBalancerNames", [])),
            fmt(d.get("HealthCheckGracePeriodSeconds")),
            fmt(d.get("LoggingEnabled")),
            fmt(d.get("AutoscalingEnabled")),
            fmt(d.get("ScalingEvents30d")),
            json.dumps(d.get("Tags", {})),
        ]
