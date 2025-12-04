from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from typing import List, Any, Generic, TypeVar, Iterable

from rich.console import Console

from stratum.core.models import AuditResult

T = TypeVar("T", bound=AuditResult)
console = Console(stderr=True)


class BaseScanner(ABC, Generic[T]):
    def __init__(self, check_type: str = "ALL"):
        self.check_type = check_type

    @property
    @abstractmethod
    def service_name(self) -> str:
        pass

    @abstractmethod
    def fetch_resources(self) -> Iterable[Any]:
        pass

    @abstractmethod
    def analyze_resource(self, resource: Any) -> T:
        pass

    def scan(self, silent: bool = False) -> List[T]:
        results = []
        resource_stream = self.fetch_resources()

        def process_stream():
            with ThreadPoolExecutor(max_workers=20) as executor:
                results.extend(executor.map(self.analyze_resource, resource_stream))

        if silent:
            process_stream()
        else:
            with console.status(
                f"[bold yellow]Scanning {self.service_name} resources...",
                spinner="dots",
            ):
                process_stream()

        return results
