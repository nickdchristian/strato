from dataclasses import dataclass, asdict, field
from typing import List, Any, Dict

from stratum.core.scoring import RiskWeight


@dataclass
class AuditResult:
    resource_arn: str
    resource_name: str
    region: str
    risk_score: int = 0
    risk_reasons: List[str] = field(default_factory=list)

    @property
    def has_risk(self) -> bool:
        return self.risk_score > 0

    @property
    def risk_level(self) -> str:
        if self.risk_score >= RiskWeight.CRITICAL:
            return "CRITICAL"
        if self.risk_score >= RiskWeight.HIGH:
            return "HIGH"
        if self.risk_score >= RiskWeight.MEDIUM:
            return "MEDIUM"
        if self.risk_score >= RiskWeight.LOW:
            return "LOW"
        return "SAFE"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def get_headers(cls, check_type: str = "ALL") -> List[str]:
        return ["Resource", "Region", "Risk Level", "Reasons"]

    def get_table_row(self) -> List[str]:
        color_map = {
            "CRITICAL": "red",
            "HIGH": "orange",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "SAFE": "green",
        }
        color = color_map.get(self.risk_level, "white")

        level_render = f"[{color}]{self.risk_level}[/{color}]"
        reasons_render = ", ".join(self.risk_reasons) if self.risk_reasons else "-"

        return [self.resource_name, self.region, level_render, reasons_render]

    def get_csv_row(self) -> List[str]:
        reasons_render = "; ".join(self.risk_reasons)
        return [self.resource_name, self.region, self.risk_level, reasons_render]
