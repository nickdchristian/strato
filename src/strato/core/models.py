import logging
from abc import ABC, abstractmethod
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from typing import Any, TypeVar

import boto3
from rich.console import Console

logger = logging.getLogger(__name__)
console_err = Console(stderr=True)


@dataclass
class InventoryRecord:
    """Base data structure for any discovered AWS resource."""

    resource_arn: str
    resource_name: str
    region: str
    account_id: str = "Unknown"
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


T = TypeVar("T", bound=InventoryRecord)


class BaseScanner[InventoryRecordType: InventoryRecord](ABC):
    """Abstract base class for resource discovery."""

    is_global_service: bool = False

    def __init__(
        self,
        check_type: str = "ALL",
        session: boto3.Session | None = None,
        account_id: str = "Unknown",
    ):
        self.check_type = check_type
        self.session = session or boto3.Session()
        self.account_id = account_id

    @property
    @abstractmethod
    def service_name(self) -> str:
        pass

    @abstractmethod
    def fetch_resources(self) -> Iterable[Any]:
        pass

    @abstractmethod
    def analyze_resource(self, resource: Any) -> InventoryRecordType:
        """Transforms a raw AWS boto3 dictionary into an InventoryRecord."""
        pass

    def scan(self, silent: bool = False) -> list[InventoryRecordType]:
        results = []
        logger.debug(f"[{self.account_id}] Initiating {self.service_name} discovery...")

        resources = list(self.fetch_resources())
        logger.debug(
            f"[{self.account_id}] Fetched {len(resources)} {self.service_name}"
            f" resources to process."
        )

        def process_stream():
            with ThreadPoolExecutor(max_workers=20) as executor:
                results.extend(executor.map(self.analyze_resource, resources))

        if silent:
            process_stream()
        else:
            with console_err.status(
                f"[bold yellow]Discovering {self.service_name} resources...",
                spinner="dots",
            ):
                process_stream()

        logger.debug(
            f"[{self.account_id}] Successfully processed"
            f" {len(results)} {self.service_name} resources."
        )

        return results
