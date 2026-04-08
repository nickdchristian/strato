import json

from strato.core.models import InventoryRecord


class S3InventoryView:
    @classmethod
    def get_headers(cls, check_type: str = "INVENTORY") -> list[str]:
        return [
            "Account ID",
            "Region",
            "Bucket Name",
            "Versioning",
            "Encryption",
            "Public Access Blocked",
            "Total Size (GB)",
        ]

    @classmethod
    def get_csv_headers(cls, check_type: str = "INVENTORY") -> list[str]:
        return [
            "Account ID",
            "Region",
            "Bucket Name",
            "Resource ARN",
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
    def format_row(cls, result: InventoryRecord) -> list[str]:
        d = result.details
        return [
            result.account_id,
            result.region,
            result.resource_name,
            str(d.get("VersioningStatus", "-")),
            str(d.get("EncryptionType", "-")),
            "Yes" if d.get("BlockAllPublicAccess") else "No",
            str(d.get("TotalBucketSizeGb", 0)),
        ]

    @classmethod
    def format_csv_row(cls, result: InventoryRecord) -> list[str]:
        d = result.details

        def fmt(val):
            return "" if val is None else str(val)

        return [
            result.account_id,
            result.region,
            result.resource_name,
            result.resource_arn,
            fmt(d.get("CreationDate")),
            fmt(d.get("EncryptionType")),
            fmt(d.get("KmsMasterKeyId")),
            fmt(d.get("BucketKeyEnabled")),
            fmt(d.get("VersioningStatus")),
            fmt(d.get("MfaDelete")),
            fmt(d.get("BlockAllPublicAccess")),
            fmt(d.get("HasBucketPolicy")),
            fmt(d.get("BucketOwnership")),
            fmt(d.get("ServerAccessLogging")),
            fmt(d.get("StaticWebsiteHosting")),
            fmt(d.get("TransferAcceleration")),
            fmt(d.get("IntelligentTieringConfig")),
            fmt(d.get("ObjectLock")),
            fmt(d.get("ObjectLockMode")),
            fmt(d.get("ObjectLockRetention")),
            fmt(d.get("ReplicationStatus")),
            fmt(d.get("ReplicationDestination")),
            fmt(d.get("ReplicationCostImpact")),
            fmt(d.get("LifecycleStatus")),
            fmt(d.get("LifecycleRuleCount")),
            fmt(d.get("TotalBucketSizeGb")),
            fmt(d.get("TotalObjectCount")),
            fmt(d.get("AllRequestsCount")),
            fmt(d.get("GetRequestsCount")),
            fmt(d.get("PutRequestsCount")),
            fmt(d.get("StandardSizeGb")),
            fmt(d.get("StandardIaSizeGb")),
            fmt(d.get("IntelligentTieringSizeGb")),
            fmt(d.get("GlacierSizeGb")),
            fmt(d.get("DeepArchiveSizeGb")),
            fmt(d.get("RrsSizeGb")),
            fmt(d.get("GlacierObjectCount")),
            fmt(d.get("DeepArchiveObjectCount")),
            json.dumps(d.get("Tags", {})),
        ]
