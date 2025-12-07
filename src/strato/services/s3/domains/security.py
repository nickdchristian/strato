from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum, auto
from typing import Any

from strato.core.models import AuditResult
from strato.core.scanner import BaseScanner
from strato.core.scoring import RiskWeight
from strato.services.s3.client import S3Client


class S3SecurityScanType(StrEnum):
    ALL = auto()
    ENCRYPTION = auto()
    PUBLIC_ACCESS = auto()
    ACLS = auto()
    VERSIONING = auto()
    OBJECT_LOCK = auto()


@dataclass
class S3SecurityResult(AuditResult):
    resource_arn: str
    resource_name: str
    region: str

    creation_date: datetime = None
    public_access_blocked: bool = False
    encryption: str = "None"
    acl_status: str = "Unknown"
    is_log_target: bool = False
    versioning: str = "Suspended"
    mfa_delete: str = "Disabled"
    object_lock: str = "Disabled"
    check_type: str = S3SecurityScanType.ALL

    def __post_init__(self):
        self._evaluate_risk()

    def _evaluate_risk(self):
        self.risk_score = 0
        self.risk_reasons = []

        if self.check_type in [
            S3SecurityScanType.ALL,
            S3SecurityScanType.PUBLIC_ACCESS,
        ]:
            if not self.public_access_blocked:
                self.risk_score += RiskWeight.CRITICAL
                self.risk_reasons.append("Public Access Allowed")

        if self.check_type in [S3SecurityScanType.ALL, S3SecurityScanType.ENCRYPTION]:
            if self.encryption == "None":
                self.risk_score += RiskWeight.MEDIUM
                self.risk_reasons.append("Encryption Missing")

        if self.check_type in [S3SecurityScanType.ALL, S3SecurityScanType.ACLS]:
            if self.acl_status == "Enabled":
                if self.is_log_target:
                    self.risk_score += RiskWeight.MEDIUM
                    self.risk_reasons.append("Legacy ACLs (Required for Logging)")
                else:
                    self.risk_score += RiskWeight.HIGH
                    self.risk_reasons.append("Legacy ACLs Enabled")

        if self.check_type in [S3SecurityScanType.ALL, S3SecurityScanType.VERSIONING]:
            if self.versioning != "Enabled":
                self.risk_score += RiskWeight.MEDIUM
                self.risk_reasons.append("Versioning Disabled")
            elif self.mfa_delete != "Enabled":
                self.risk_score += RiskWeight.LOW
                self.risk_reasons.append("MFA Delete Disabled")

        if self.check_type in [S3SecurityScanType.ALL, S3SecurityScanType.OBJECT_LOCK]:
            if self.object_lock != "Enabled":
                # Object Lock is usually optional, so we weight it LOW
                self.risk_score += RiskWeight.LOW
                self.risk_reasons.append("Object Lock Disabled")

    def to_dict(self) -> dict[str, Any]:
        data = {
            "resource_arn": self.resource_arn,
            "resource_name": self.resource_name,
            "region": self.region,
            "creation_date": self.creation_date.isoformat()
            if self.creation_date
            else None,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "risk_reasons": self.risk_reasons,
            "check_type": self.check_type,
        }

        is_all = self.check_type == S3SecurityScanType.ALL

        if is_all or self.check_type == S3SecurityScanType.ENCRYPTION:
            data["encryption"] = self.encryption

        if is_all or self.check_type == S3SecurityScanType.PUBLIC_ACCESS:
            data["public_access_blocked"] = self.public_access_blocked

        if is_all or self.check_type == S3SecurityScanType.ACLS:
            data["acl_status"] = self.acl_status
            data["is_log_target"] = self.is_log_target

        if is_all or self.check_type == S3SecurityScanType.VERSIONING:
            data["versioning"] = self.versioning
            data["mfa_delete"] = self.mfa_delete

        if is_all or self.check_type == S3SecurityScanType.OBJECT_LOCK:
            data["object_lock"] = self.object_lock

        return data

    @classmethod
    def get_headers(cls, check_type: str = S3SecurityScanType.ALL) -> list[str]:
        base_columns = ["Bucket Name", "Region", "Creation Date"]
        risk_columns = ["Risk Level", "Reasons"]

        if check_type == S3SecurityScanType.ENCRYPTION:
            return base_columns + ["Encryption"] + risk_columns

        if check_type == S3SecurityScanType.PUBLIC_ACCESS:
            return base_columns + ["Public Blocked"] + risk_columns

        if check_type == S3SecurityScanType.ACLS:
            return base_columns + ["ACL Status", "Log Target"] + risk_columns

        if check_type == S3SecurityScanType.VERSIONING:
            return base_columns + ["Versioning", "MFA Delete"] + risk_columns

        if check_type == S3SecurityScanType.OBJECT_LOCK:
            return base_columns + ["Object Lock"] + risk_columns

        # Case: ALL - Explicitly listed to ensure order matches get_csv_row
        if check_type == S3SecurityScanType.ALL:
            return (
                base_columns
                + [
                    "Public Blocked",
                    "Encryption",
                    "ACL Status",
                    "Log Target",
                    "Versioning",
                    "MFA Delete",
                    "Object Lock",
                ]
                + risk_columns
            )

        return base_columns + risk_columns

    def get_table_row(self) -> list[str]:
        base_row = super().get_table_row()

        resource_name = base_row[0]
        region = base_row[1]
        risk_level_render = base_row[2]
        risk_reasons_render = base_row[3]

        if self.check_type == S3SecurityScanType.ENCRYPTION:
            enc_render = (
                f"[green]{self.encryption}[/green]"
                if self.encryption != "None"
                else "[yellow]Missing[/yellow]"
            )
            return [
                resource_name,
                region,
                enc_render,
                risk_level_render,
                risk_reasons_render,
            ]

        if self.check_type == S3SecurityScanType.PUBLIC_ACCESS:
            pub_render = (
                "[green]Blocked[/green]"
                if self.public_access_blocked
                else "[red]OPEN[/red]"
            )
            return [
                resource_name,
                region,
                pub_render,
                risk_level_render,
                risk_reasons_render,
            ]

        if self.check_type == S3SecurityScanType.ACLS:
            if self.acl_status == "Disabled":
                acl_render = "[green]Disabled[/green]"
            elif self.is_log_target:
                acl_render = "[yellow]Enabled (Logs)[/yellow]"
            else:
                acl_render = "[red]Enabled[/red]"
            log_target_render = "Yes" if self.is_log_target else "No"

            return [
                resource_name,
                region,
                acl_render,
                log_target_render,
                risk_level_render,
                risk_reasons_render,
            ]

        if self.check_type == S3SecurityScanType.VERSIONING:
            version_render = (
                f"[green]{self.versioning}[/green]"
                if self.versioning == "Enabled"
                else f"[red]{self.versioning}[/red]"
            )
            mfa_render = (
                f"[green]{self.mfa_delete}[/green]"
                if self.mfa_delete == "Enabled"
                else f"[yellow]{self.mfa_delete}[/yellow]"
            )
            return [
                resource_name,
                region,
                version_render,
                mfa_render,
                risk_level_render,
                risk_reasons_render,
            ]

        if self.check_type == S3SecurityScanType.OBJECT_LOCK:
            lock_render = (
                f"[green]{self.object_lock}[/green]"
                if self.object_lock == "Enabled"
                else f"[yellow]{self.object_lock}[/yellow]"
            )
            return [
                self.resource_name,
                self.region,
                lock_render,
                risk_level_render,
                risk_reasons_render,
            ]

        return base_row

    def get_csv_row(self) -> list[str]:
        date_render = (
            self.creation_date.isoformat() if self.creation_date else "Unknown"
        )
        row = [self.resource_name, self.region, date_render]

        risk_reasons_str = "; ".join(self.risk_reasons)
        public_render = "Blocked" if self.public_access_blocked else "OPEN"

        # 2. Append Specific Data, must be in a strict order
        if self.check_type == S3SecurityScanType.ENCRYPTION:
            row.append(self.encryption)

        elif self.check_type == S3SecurityScanType.PUBLIC_ACCESS:
            row.append(public_render)

        elif self.check_type == S3SecurityScanType.ACLS:
            row.append(self.acl_status)
            row.append(str(self.is_log_target))

        elif self.check_type == S3SecurityScanType.VERSIONING:
            row.append(self.versioning)
            row.append(self.mfa_delete)

        elif self.check_type == S3SecurityScanType.OBJECT_LOCK:
            row.append(self.object_lock)

        elif self.check_type == S3SecurityScanType.ALL:
            # Must match the order in get_headers(ALL) exactly
            row.append(public_render)
            row.append(self.encryption)
            row.append(self.acl_status)
            row.append(str(self.is_log_target))
            row.append(self.versioning)
            row.append(self.mfa_delete)
            row.append(self.object_lock)

        row.append(self.risk_level)
        row.append(risk_reasons_str)

        return row


class S3SecurityScanner(BaseScanner[S3SecurityResult]):
    def __init__(self, check_type: str = S3SecurityScanType.ALL):
        super().__init__(check_type)
        self.client = S3Client()

    @property
    def service_name(self) -> str:
        return f"S3 Security ({self.check_type})"

    def fetch_resources(self) -> Iterable[dict]:
        yield from self.client.list_buckets()

    def analyze_resource(self, bucket_data: dict) -> S3SecurityResult:
        bucket_arn = bucket_data.get("BucketArn", f"arn:aws:s3:::{bucket_data['Name']}")
        bucket_name = bucket_data["Name"]
        region = self.client.get_bucket_region(bucket_name)
        creation_date = bucket_data["CreationDate"]

        public_access_blocked = self.client.get_public_access_status(bucket_name)
        encryption = self.client.get_encryption_status(bucket_name)

        acl_status = self.client.get_acl_status(bucket_name)
        is_log_target = False
        if acl_status == "Enabled":
            is_log_target = self.client.is_log_target(bucket_name)

        version_config = self.client.get_versioning_status(bucket_name)
        object_lock = self.client.get_object_lock_status(bucket_name)

        return S3SecurityResult(
            resource_arn=bucket_arn,
            resource_name=bucket_name,
            region=region,
            creation_date=creation_date,
            public_access_blocked=public_access_blocked,
            encryption=encryption,
            acl_status=acl_status,
            is_log_target=is_log_target,
            versioning=version_config["Status"],
            mfa_delete=version_config["MFADelete"],
            object_lock=object_lock,
            check_type=self.check_type,
        )
