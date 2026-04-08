import json

from strato.core.models import InventoryRecord


class LambdaInventoryView:
    @classmethod
    def get_headers(cls, check_type: str) -> list[str]:
        return [
            "Account ID",
            "Region",
            "Function Name",
            "Runtime",
            "Memory",
            "Timeout",
            "Public URL",
        ]

    @classmethod
    def get_csv_headers(cls, check_type: str) -> list[str]:
        return [
            "Account ID",
            "Region",
            "Function Name",
            "Resource ARN",
            "Runtime",
            "Architecture",
            "PackageType",
            "MemorySize (MB)",
            "Timeout (s)",
            "State",
            "Aliases",
            "EnvVarKeys",
            "FunctionUrl",
            "UrlAuthType",
            "Tags",
        ]

    @classmethod
    def format_row(cls, result: InventoryRecord) -> list[str]:
        d = result.details
        url_display = "[blue]Yes[/blue]" if d.get("FunctionUrl") else "-"

        return [
            result.account_id,
            result.region,
            result.resource_name,
            str(d.get("Runtime", "-")),
            f"{d.get('MemorySize', 0)} MB",
            f"{d.get('Timeout', 0)}s",
            url_display,
        ]

    @classmethod
    def format_csv_row(cls, result: InventoryRecord) -> list[str]:
        d = result.details
        return [
            result.account_id,
            result.region,
            result.resource_name,
            result.resource_arn,
            str(d.get("Runtime", "")),
            str(d.get("Architecture", "")),
            str(d.get("PackageType", "")),
            str(d.get("MemorySize", "")),
            str(d.get("Timeout", "")),
            str(d.get("State", "")),
            ", ".join(d.get("Aliases", [])),
            ", ".join(d.get("EnvironmentKeys", [])),
            str(d.get("FunctionUrl", "")),
            str(d.get("UrlAuthType", "")),
            json.dumps(d.get("Tags", {})),
        ]
