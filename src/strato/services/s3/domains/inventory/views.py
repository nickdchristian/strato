from typing import Any, cast

from strato.core.models import AuditResult
from strato.core.presenter import GenericView
from strato.services.s3.domains.inventory.checks import S3InventoryResult


class S3InventoryView(GenericView):
    @classmethod
    def get_headers(cls, check_type: str = "INVENTORY") -> list[str]:
        return cls.get_csv_headers(check_type)

    @classmethod
    def get_csv_headers(cls, check_type: str = "INVENTORY") -> list[str]:
        return [
            "Account ID",
            "Region",
            "Bucket Name",
            "Creation Date",
            "Encryption",
            "KMS Key ID",
            "Bucket Key",
            "Versioning",
            "MFA Delete",
            "Public Access Blocked",
            "Bucket Policy",
            "Ownership",
            "Logging",
            "Website Hosting",
            "Transfer Accel",
            "Intelligent-Tiering",
            "Object Lock",
            "Lock Mode",
            "Lock Retention",
            "Replication Status",
            "Replication Dest",
            "Repl Cost Impact",
            "Lifecycle Status",
            "Lifecycle Rules",
            "Total Size (GB)",
            "Total Objects",
            "Requests (All)",
            "Requests (Get)",
            "Requests (Put)",
            "Standard (GB)",
            "Standard-IA (GB)",
            "Intelligent-Tiering (GB)",
            "Glacier (GB)",
            "Deep Archive (GB)",
            "RRS (GB)",
            "Glacier Obj Count",
            "Deep Archive Obj Count",
            "Tags",
        ]

    @classmethod
    def format_row(cls, result: AuditResult) -> list[str]:
        return cls.format_csv_row(result)

    @classmethod
    def format_csv_row(cls, result: AuditResult) -> list[str]:
        s3_result = cast(S3InventoryResult, result)
        tags_string = "; ".join(
            f"{key}={value}" for key, value in s3_result.tags.items()
        )

        creation_string = (
            s3_result.creation_date.isoformat() if s3_result.creation_date else ""
        )

        def fmt(val: Any) -> str:
            if val is None:
                return ""
            return str(val)

        return [
            s3_result.account_id,
            s3_result.region,
            s3_result.resource_name,
            creation_string,
            fmt(s3_result.encryption_type),
            fmt(s3_result.kms_master_key_id),
            str(s3_result.bucket_key_enabled),
            s3_result.versioning_status,
            s3_result.mfa_delete,
            str(s3_result.block_all_public_access),
            str(s3_result.has_bucket_policy),
            fmt(s3_result.bucket_ownership),
            fmt(s3_result.server_access_logging),
            s3_result.static_website_hosting,
            s3_result.transfer_acceleration,
            s3_result.intelligent_tiering_config,
            s3_result.object_lock,
            fmt(s3_result.object_lock_mode),
            fmt(s3_result.object_lock_retention),
            s3_result.replication_status,
            fmt(s3_result.replication_destination),
            fmt(s3_result.replication_cost_impact),
            s3_result.lifecycle_status,
            str(s3_result.lifecycle_rule_count),
            str(s3_result.total_bucket_size_gb),
            str(s3_result.total_object_count),
            str(s3_result.all_requests_count),
            str(s3_result.get_requests_count),
            str(s3_result.put_requests_count),
            str(s3_result.standard_size_gb),
            str(s3_result.standard_ia_size_gb),
            str(s3_result.intelligent_tiering_size_gb),
            str(s3_result.glacier_size_gb),
            str(s3_result.deep_archive_size_gb),
            str(s3_result.rrs_size_gb),
            str(s3_result.glacier_object_count),
            str(s3_result.deep_archive_object_count),
            tags_string,
        ]
