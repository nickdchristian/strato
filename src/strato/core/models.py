from dataclasses import asdict, dataclass, field
from typing import Any

from strato.core.scoring import ObservationLevel  #


@dataclass
class AuditResult:
    """
    Base data structure for any resource audit.
    """

    resource_arn: str
    resource_name: str
    region: str
    account_id: str = "Unknown"

    status_score: int = 0

    findings: list[str] = field(default_factory=list)

    @property
    def is_violation(self) -> bool:
        """
        Returns True if the resource has a negative finding (Low to Critical).
        """
        return self.status_score >= ObservationLevel.LOW

    @property
    def status(self) -> str:
        """Maps the numeric score to a human-readable status string."""
        if self.status_score >= ObservationLevel.CRITICAL:
            return "CRITICAL"
        if self.status_score >= ObservationLevel.HIGH:
            return "HIGH"
        if self.status_score >= ObservationLevel.MEDIUM:
            return "MEDIUM"
        if self.status_score >= ObservationLevel.LOW:
            return "LOW"
        if self.status_score == ObservationLevel.INFO:
            return "INFO"

        return "PASS"

    def to_dict(self) -> dict[str, Any]:
        """Serializes the object for JSON output."""
        return asdict(self)

    @classmethod
    def get_headers(cls, check_type: str = "ALL") -> list[str]:
        # Updated header names
        return ["Account ID", "Resource", "Region", "Status", "Findings"]

    def get_table_row(self) -> list[str]:
        """
        Returns a list of strings formatted for the Rich Table library.
        """
        status_color_map = {
            "CRITICAL": "red",
            "HIGH": "orange1",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "dim white",
            "PASS": "green",
        }
        color = status_color_map.get(self.status, "white")

        status_render = f"[{color}]{self.status}[/{color}]"
        findings_render = ", ".join(self.findings) if self.findings else "-"

        return [
            self.account_id,
            self.resource_name,
            self.region,
            status_render,
            findings_render,
        ]

    def get_csv_row(self) -> list[str]:
        findings_render = "; ".join(self.findings)
        return [
            self.account_id,
            self.resource_name,
            self.region,
            self.status,
            findings_render,
        ]
