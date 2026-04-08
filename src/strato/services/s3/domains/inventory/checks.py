import logging
from collections.abc import Iterable
from datetime import datetime
from enum import StrEnum, auto
from typing import Any, cast

import boto3

from strato.core.models import BaseScanner, InventoryRecord
from strato.services.s3.client import S3Client

logger = logging.getLogger(__name__)


class S3InventoryScanType(StrEnum):
    ALL = auto()
    INVENTORY = auto()


class S3InventoryScanner(BaseScanner[InventoryRecord]):
    is_global_service = True

    def __init__(
        self,
        check_type: str = S3InventoryScanType.ALL,
        session: boto3.Session | None = None,
        account_id: str = "Unknown",
    ):
        super().__init__(check_type, session, account_id)
        self.client = S3Client(session=self.session, account_id=self.account_id)

    @property
    def service_name(self) -> str:
        return "S3 Buckets"

    def fetch_resources(self) -> Iterable[dict[str, Any]]:
        yield from self.client.list_buckets()

    def analyze_resource(self, resource: Any) -> InventoryRecord:
        bucket_data = cast(dict[str, Any], resource)
        bucket_name = str(bucket_data.get("Name", "Unknown"))
        bucket_arn = f"arn:aws:s3:::{bucket_name}"

        creation_date = bucket_data.get("CreationDate")
        creation_string = (
            creation_date.isoformat()
            if isinstance(creation_date, datetime)
            else str(creation_date)
        )

        region = str(self.client.get_bucket_region(bucket_name) or "Unknown")
        bucket_tags = self.client.get_bucket_tags(bucket_name)

        encryption_status = self.client.get_encryption_status(bucket_name)
        versioning_status = self.client.get_versioning_status(bucket_name)
        bucket_policy = self.client.get_bucket_policy(bucket_name)
        public_access_status = self.client.get_public_access_status(bucket_name)
        object_lock_details = self.client.get_object_lock_details(bucket_name)

        replication_rules = self.client.get_replication_configuration(bucket_name)
        lifecycle_rules = self.client.get_lifecycle_configuration(bucket_name)
        intelligent_tiering_configs = (
            self.client.get_intelligent_tiering_configurations(bucket_name)
        )

        bucket_metrics = self.client.get_bucket_metrics(bucket_name)
        storage_metrics = bucket_metrics["Storage"]
        request_metrics = bucket_metrics["Requests"]

        replication_info = self._extract_replication_info(replication_rules, region)
        lifecycle_info = self._extract_lifecycle_info(lifecycle_rules)

        total_bucket_size = sum(value["Size"] for value in storage_metrics.values())
        total_object_count = sum(value["Count"] for value in storage_metrics.values())

        ret_days = object_lock_details.get("RetentionDays")
        ret_years = object_lock_details.get("RetentionYears")
        retention = (
            f"{ret_days} Days"
            if ret_days
            else (f"{ret_years} Years" if ret_years else None)
        )

        logger.debug(f"[{bucket_name}] Analysis complete.")

        details = {
            "CreationDate": creation_string,
            "EncryptionType": encryption_status.get("SSEAlgorithm"),
            "KmsMasterKeyId": encryption_status.get("KMSMasterKeyID"),
            "BucketKeyEnabled": bool(encryption_status.get("BucketKeyEnabled", False)),
            "BlockAllPublicAccess": bool(public_access_status),
            "HasBucketPolicy": bucket_policy.get("Access") != "Error",
            "BucketOwnership": self.client.get_acl_status(bucket_name).get("Ownership"),
            "AclStatus": self.client.get_acl_status(bucket_name).get(
                "Status", "Disabled"
            ),
            "ServerAccessLogging": self.client.get_logging_status(bucket_name)
            or "Disabled",
            "VersioningStatus": versioning_status.get("Status", "Suspended"),
            "MfaDelete": "Enabled"
            if versioning_status.get("MFADelete")
            else "Disabled",
            "ObjectLock": "Enabled"
            if object_lock_details.get("Status")
            else "Disabled",
            "ObjectLockMode": object_lock_details.get("Mode"),
            "ObjectLockRetention": retention,
            "StaticWebsiteHosting": "Enabled"
            if self.client.get_website_hosting_status(bucket_name)
            else "Disabled",
            "TransferAcceleration": self.client.get_accelerate_configuration(
                bucket_name
            ),
            "RequestPayer": self.client.get_request_payment(bucket_name),
            "CorsRulesCount": self.client.get_cors_count(bucket_name),
            "IntelligentTieringConfig": "Enabled"
            if intelligent_tiering_configs
            else "Disabled",
            "ReplicationStatus": str(
                replication_info.get("replication_status", "Disabled")
            ),
            "ReplicationRuleName": replication_info.get("replication_rule_name"),
            "ReplicationDestination": replication_info.get("replication_destination"),
            "ReplicationStorageClass": replication_info.get(
                "replication_storage_class"
            ),
            "ReplicationKmsEncrypted": bool(
                replication_info.get("replication_kms_encrypted", False)
            ),
            "ReplicationCostImpact": replication_info.get("replication_cost_impact"),
            "LifecycleStatus": str(lifecycle_info.get("lifecycle_status", "Disabled")),
            "LifecycleRuleCount": int(lifecycle_info.get("lifecycle_rule_count", 0)),
            "LifecycleActiveRuleId": lifecycle_info.get("lifecycle_active_rule_id"),
            "NotificationConfigs": self.client.get_notification_configuration_count(
                bucket_name
            ),
            "InventoryConfigs": self.client.get_inventory_configuration_count(
                bucket_name
            ),
            "AnalyticsConfigs": self.client.get_analytics_configuration_count(
                bucket_name
            ),
            "MetricConfigs": self.client.get_metrics_configuration_count(bucket_name),
            "StandardSizeGb": storage_metrics["Standard"]["Size"],
            "StandardIaSizeGb": storage_metrics["Standard-IA"]["Size"],
            "IntelligentTieringSizeGb": storage_metrics["Intelligent-Tiering"]["Size"],
            "RrsSizeGb": storage_metrics["RRS"]["Size"],
            "GlacierSizeGb": storage_metrics["Glacier"]["Size"],
            "DeepArchiveSizeGb": storage_metrics["Glacier-Deep-Archive"]["Size"],
            "GlacierObjectCount": storage_metrics["Glacier"]["Count"],
            "DeepArchiveObjectCount": storage_metrics["Glacier-Deep-Archive"]["Count"],
            "TotalBucketSizeGb": round(total_bucket_size, 2),
            "TotalObjectCount": int(total_object_count),
            "AllRequestsCount": request_metrics["All"],
            "GetRequestsCount": request_metrics["Get"],
            "PutRequestsCount": request_metrics["Put"],
            "Tags": bucket_tags,
        }

        return InventoryRecord(
            resource_arn=bucket_arn,
            resource_name=bucket_name,
            region=region,
            account_id=self.account_id,
            details=details,
        )

    def _extract_replication_info(
        self, rules: list[dict[str, Any]], region: str
    ) -> dict[str, Any]:
        cost_impact_list = self.client.calculate_replication_cost_impact(region, rules)
        cost_impact = ", ".join(cost_impact_list) if cost_impact_list else None

        if not rules:
            return {
                "replication_status": "Disabled",
                "replication_cost_impact": cost_impact,
            }

        rule = rules[0]
        return {
            "replication_status": rule.get("Status", "Unknown"),
            "replication_rule_name": rule.get("ID"),
            "replication_destination": rule.get("DestinationBucket"),
            "replication_storage_class": rule.get("StorageClass", "Standard"),
            "replication_kms_encrypted": rule.get("KMSEncrypted") == "Enabled",
            "replication_cost_impact": cost_impact,
        }

    @staticmethod
    def _extract_lifecycle_info(rules: list[dict[str, Any]]) -> dict[str, Any]:
        if not rules:
            return {
                "lifecycle_status": "Disabled",
                "lifecycle_rule_count": 0,
                "lifecycle_active_rule_id": None,
            }

        return {
            "lifecycle_status": "Enabled",
            "lifecycle_rule_count": len(rules),
            "lifecycle_active_rule_id": rules[0].get("ID"),
        }
