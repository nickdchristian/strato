from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Dict, Iterable, Any
from enum import StrEnum, auto

from stratum.core.models import AuditResult
from stratum.core.scoring import RiskWeight
from stratum.core.scanner import BaseScanner
from stratum.services.s3.client import S3Client


class S3ScanType(StrEnum):
    ALL = auto()
    ENCRYPTION = auto()
    PUBLIC_ACCESS = auto()


@dataclass
class S3Result(AuditResult):
    creation_date: datetime = None
    public_access_blocked: bool = False
    encryption: str = "None"
    check_type: str = S3ScanType.ALL

    def __post_init__(self):
        self._evaluate_risk()

    def _evaluate_risk(self):
        self.risk_score = 0
        self.risk_reasons = []

        # RATIONALE: Public Access is exploitable by anyone on the internet.
        # Impact: High, Likelihood: High -> CRITICAL
        if self.check_type in [S3ScanType.ALL, S3ScanType.PUBLIC_ACCESS]:
            if not self.public_access_blocked:
                self.risk_score += RiskWeight.CRITICAL
                self.risk_reasons.append("Public Access Allowed")

        # RATIONALE: Missing encryption requires physical access or deeper compromise.
        # Impact: High, Likelihood: Low -> MEDIUM
        if self.check_type in [S3ScanType.ALL, S3ScanType.ENCRYPTION]:
            if self.encryption == "None":
                self.risk_score += RiskWeight.MEDIUM
                self.risk_reasons.append("Encryption Missing")

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if self.creation_date:
            data["creation_date"] = self.creation_date.isoformat()
        return data

    @classmethod
    def get_headers(cls, check_type: str = S3ScanType.ALL) -> List[str]:
        base = ["Bucket Name", "Region"]
        risk_cols = ["Risk Level", "Reasons"]

        if check_type == S3ScanType.ENCRYPTION:
            return base + ["Encryption"] + risk_cols

        if check_type == S3ScanType.PUBLIC_ACCESS:
            return base + ["Public Blocked"] + risk_cols

        return base + ["Creation Date", "Public Blocked", "Encryption"] + risk_cols

    def get_table_row(self) -> List[str]:
        base_row = super().get_table_row()
        level_render = base_row[2]
        reasons_render = base_row[3]

        pub_render = (
            "[green]Blocked[/green]"
            if self.public_access_blocked
            else "[red]OPEN[/red]"
        )
        date_render = (
            self.creation_date.strftime("%Y-%m-%d") if self.creation_date else "Unknown"
        )

        if self.encryption == "None":
            enc_render = "[yellow]Missing[/yellow]"
        else:
            enc_render = f"[green]{self.encryption}[/green]"

        return self._build_row(
            date_render, pub_render, enc_render, level_render, reasons_render
        )

    def get_csv_row(self) -> List[str]:
        base_row = super().get_csv_row()
        level_render = base_row[2]
        reasons_render = base_row[3]

        pub_render = "Blocked" if self.public_access_blocked else "OPEN"
        date_render = (
            self.creation_date.isoformat() if self.creation_date else "Unknown"
        )

        return self._build_row(
            date_render, pub_render, self.encryption, level_render, reasons_render
        )

    def _build_row(
        self, date_val, pub_val, enc_val, level_val, reasons_val
    ) -> List[str]:
        if self.check_type == S3ScanType.ENCRYPTION:
            return [self.resource_name, self.region, enc_val, level_val, reasons_val]

        if self.check_type == S3ScanType.PUBLIC_ACCESS:
            return [self.resource_name, self.region, pub_val, level_val, reasons_val]

        return [
            self.resource_name,
            self.region,
            date_val,
            pub_val,
            enc_val,
            level_val,
            reasons_val,
        ]


class S3Scanner(BaseScanner[S3Result]):
    def __init__(self, check_type: str = S3ScanType.ALL):
        super().__init__(check_type)
        self.client = S3Client()

    @property
    def service_name(self) -> str:
        return f"S3 ({self.check_type})"

    def fetch_resources(self) -> Iterable[Dict]:
        yield from self.client.list_buckets()

    def analyze_resource(self, bucket_data: Dict) -> S3Result:
        bucket_arn = bucket_data["BucketArn"]
        bucket_name = bucket_data["Name"]
        region = self.client.get_bucket_region(bucket_name)
        creation_date = bucket_data["CreationDate"]
        public_access_blocked = self.client.get_public_access_status(bucket_name)
        encryption = self.client.get_encryption_status(bucket_name)
        check_type = self.check_type

        return S3Result(
            resource_arn=bucket_arn,
            resource_name=bucket_name,
            region=region,
            creation_date=creation_date,
            public_access_blocked=public_access_blocked,
            encryption=encryption,
            check_type=check_type,
        )
