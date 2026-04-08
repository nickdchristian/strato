from enum import StrEnum
from typing import Any

from strato.core.models import BaseScanner, InventoryRecord
from strato.services.awslambda.client import LambdaClient


class LambdaInventoryScanType(StrEnum):
    INVENTORY = "INVENTORY"


class LambdaInventoryScanner(BaseScanner[InventoryRecord]):
    is_global_service = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = LambdaClient(session=self.session, account_id=self.account_id)

    @property
    def service_name(self) -> str:
        return "AWS Lambda"

    def fetch_resources(self):
        return self.client.list_functions()

    def analyze_resource(self, resource: dict[str, Any]) -> InventoryRecord:
        func_name = resource.get("FunctionName", "Unknown")
        func_arn = resource.get("FunctionArn", "Unknown")

        url, auth_type = self.client.get_function_url_details(func_name)
        aliases = self.client.get_function_aliases(func_name)
        tags = self.client.get_tags(func_arn)

        env_vars = list(resource.get("Environment", {}).get("Variables", {}).keys())

        details = {
            "Runtime": resource.get("Runtime", "Unknown"),
            "MemorySize": resource.get("MemorySize"),
            "Timeout": resource.get("Timeout"),
            "State": resource.get("State", "Unknown"),
            "LastModified": resource.get("LastModified"),
            "Architecture": resource.get("Architectures", ["x86_64"])[0],
            "PackageType": resource.get("PackageType", "Zip"),
            "EnvironmentKeys": env_vars,
            "Aliases": aliases,
            "Tags": tags,
            "FunctionUrl": url,
            "UrlAuthType": auth_type,
        }

        return InventoryRecord(
            resource_arn=func_arn,
            resource_name=func_name,
            region=self.session.region_name or "Unknown",
            account_id=self.account_id,
            details=details,
        )
