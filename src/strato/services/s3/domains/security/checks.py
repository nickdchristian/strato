import math
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum, auto
from typing import Any

from strato.core.models import AuditResult, BaseScanner
from strato.services.s3.client import S3Client


class S3SecurityScanType(StrEnum):
    ALL = auto()
    ENCRYPTION = auto()
    PUBLIC_ACCESS = auto()
    POLICY = auto()
    ACLS = auto()
    VERSIONING = auto()
    OBJECT_LOCK = auto()
    NAME_PREDICTABILITY = auto()
    WEBSITE_HOSTING = auto()


@dataclass
class S3SecurityResult(AuditResult):
    """
    Data container for S3 Security and Configuration details.
    Inherits resource_arn, resource_name, region, and account_id from AuditResult.
    """

    creation_date: datetime | None = None
    public_access_block_status: bool = False
    policy_access: str = "Unknown"
    ssl_enforced: bool = False
    encryption: str = "None"
    sse_c: bool = False
    acl_status: str | None = "Unknown"
    log_target: bool = False
    versioning: str = "Suspended"
    mfa_delete: str = "Disabled"
    object_lock: str = "Disabled"
    name_predictability: str = "LOW"
    website_hosting: bool | None = None
    log_sources: list[str] = field(default_factory=list)
    check_type: str = S3SecurityScanType.ALL

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "account_id": self.account_id,
            "resource_arn": self.resource_arn,
            "resource_name": self.resource_name,
            "region": self.region,
            "creation_date": self.creation_date.isoformat()
            if self.creation_date
            else None,
            "status_score": self.status_score,
            "status": self.status,
            "findings": self.findings,
            "check_type": self.check_type,
        }

        config = {}
        is_all = self.check_type == S3SecurityScanType.ALL

        if is_all or self.check_type == S3SecurityScanType.PUBLIC_ACCESS:
            config["public_access_blocked"] = self.public_access_block_status

        if is_all or self.check_type == S3SecurityScanType.POLICY:
            config["policy_access"] = self.policy_access
            config["ssl_enforced"] = self.ssl_enforced

        if is_all or self.check_type == S3SecurityScanType.ENCRYPTION:
            config["encryption"] = self.encryption
            config["sse_c_blocked"] = self.sse_c

        if is_all or self.check_type == S3SecurityScanType.ACLS:
            config["acl_status"] = self.acl_status
            config["log_target"] = self.log_target
            config["log_sources"] = self.log_sources

        if is_all or self.check_type == S3SecurityScanType.VERSIONING:
            config["versioning"] = self.versioning
            config["mfa_delete"] = self.mfa_delete

        if is_all or self.check_type == S3SecurityScanType.OBJECT_LOCK:
            config["object_lock"] = self.object_lock

        if is_all or self.check_type == S3SecurityScanType.NAME_PREDICTABILITY:
            config["name_predictability"] = self.name_predictability

        if is_all or self.check_type == S3SecurityScanType.WEBSITE_HOSTING:
            config["website_hosting"] = self.website_hosting

        data["configuration"] = config
        return data


class S3SecurityScanner(BaseScanner[S3SecurityResult]):
    def __init__(
        self,
        check_type: str = S3SecurityScanType.ALL,
        session=None,
        account_id="Unknown",
    ):
        super().__init__(check_type, session, account_id)
        self.client = S3Client(session=self.session)

    is_global_service = True

    @property
    def service_name(self) -> str:
        return f"S3 Security ({self.check_type})"

    def fetch_resources(self) -> Iterable[dict]:
        yield from self.client.list_buckets()

    def analyze_resource(self, resource: Any) -> S3SecurityResult:
        bucket_data = resource
        name = str(bucket_data["Name"])
        arn = str(bucket_data.get("BucketArn", f"arn:aws:s3:::{name}"))
        created = bucket_data.get("CreationDate")
        region = str(self.client.get_bucket_region(name))

        pab_status: bool = False

        policy_access: str = "Unknown"
        ssl_enforced: bool = False
        log_sources: list[str] = []

        sse_algorithm: str = "None"
        ssec_blocked: bool = False

        acl_status: str = "Unknown"
        is_log_target: bool = False
        versioning_status: str = "Suspended"
        mfa_delete_str: str = "Disabled"
        object_lock_str: str = "Disabled"
        predictability: str = "LOW"
        website_hosting: bool | None = None

        is_all = self.check_type == S3SecurityScanType.ALL

        if is_all or self.check_type == S3SecurityScanType.PUBLIC_ACCESS:
            pab_status = bool(self.client.get_public_access_status(name))

        if is_all or self.check_type == S3SecurityScanType.POLICY:
            policy_data = self.client.get_bucket_policy(name)
            policy_access = str(policy_data.get("Access", "Unknown"))
            ssl_enforced = bool(policy_data.get("SSL_Enforced", False))

            raw_logs = policy_data.get("Log_Sources", [])
            log_sources = raw_logs if isinstance(raw_logs, list) else []

        if is_all or self.check_type == S3SecurityScanType.ENCRYPTION:
            enc_data = self.client.get_encryption_status(name)
            sse_algorithm = str(enc_data.get("SSEAlgorithm", "None"))
            ssec_blocked = bool(enc_data.get("SSECBlocked", False))

        if is_all or self.check_type == S3SecurityScanType.ACLS:
            acl_status = str(self.client.get_acl_status(name).get("Status", "Unknown"))

            if acl_status == "Enabled":
                is_log_target = bool(self.client.is_log_target(name))

        if is_all or self.check_type == S3SecurityScanType.VERSIONING:
            v_data = self.client.get_versioning_status(name)
            versioning_status = str(v_data.get("Status", "Suspended"))
            mfa_delete_str = "Enabled" if v_data.get("MFADelete") else "Disabled"

        if is_all or self.check_type == S3SecurityScanType.OBJECT_LOCK:
            lock_data = self.client.get_object_lock_details(name)
            object_lock_str = "Enabled" if lock_data.get("Status") else "Disabled"

        if is_all or self.check_type == S3SecurityScanType.NAME_PREDICTABILITY:
            predictability = str(self._calculate_entropy(name))

        if is_all or self.check_type == S3SecurityScanType.WEBSITE_HOSTING:
            website_hosting = bool(self.client.get_website_hosting_status(name))

        return S3SecurityResult(
            account_id=str(self.account_id),
            resource_arn=arn,
            resource_name=name,
            region=region,
            creation_date=created,
            public_access_block_status=pab_status,
            policy_access=policy_access,
            ssl_enforced=ssl_enforced,
            log_sources=log_sources,
            encryption=sse_algorithm,
            sse_c=ssec_blocked,
            acl_status=acl_status,
            log_target=is_log_target,
            versioning=versioning_status,
            mfa_delete=mfa_delete_str,
            object_lock=object_lock_str,
            name_predictability=predictability,
            website_hosting=website_hosting,
            check_type=str(self.check_type),
        )

    @staticmethod
    def _calculate_entropy(bucket_name: str) -> str:
        """
        Calculates the predictability of a bucket name using Shannon entropy analysis.
        """
        entropy = 0
        has_guid_fragment = bool(re.search(r"[a-f0-9]{8,}", bucket_name))
        character_frequency = Counter(bucket_name)
        bucket_name_length = len(bucket_name)

        for frequency in character_frequency.values():
            probability = frequency / bucket_name_length
            entropy -= probability * math.log2(probability)

        if has_guid_fragment and entropy > 3.0:
            return "LOW"
        elif entropy < 2.5 or len(bucket_name) < 8:
            return "HIGH"
        else:
            return "MODERATE"
