import json

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


class S3Client:
    """
    Wrapper for Boto3 S3 interactions.

    Handles:
    - Pagination
    - Adaptive Retries (to handle throttling)
    - Error suppression (returns defaults on missing permissions/configs)
    """

    def __init__(self):
        # Adaptive mode helps with rate limiting during multi-threaded scans
        retry_config = Config(retries={"mode": "adaptive", "max_attempts": 10})
        self._client = boto3.client("s3", config=retry_config)

    def list_buckets(self) -> list[dict]:
        """Lists all buckets in the account using pagination."""
        paginator = self._client.get_paginator("list_buckets")
        buckets = []
        for page in paginator.paginate():
            buckets.extend(page.get("Buckets", []))

        return buckets

    def get_bucket_region(self, bucket_name: str) -> str:
        """Resolves bucket region."""
        try:
            response = self._client.get_bucket_location(Bucket=bucket_name)
            return response.get("LocationConstraint") or "us-east-1"
        except ClientError:
            return "unknown"

    def get_public_access_status(self, bucket_name: str) -> bool:
        """
        Checks if the bucket has Public Access Block enabled.
        """
        try:
            response = self._client.get_public_access_block(Bucket=bucket_name)
            public_access_config = response.get("PublicAccessBlockConfiguration", {})
            return all(
                [
                    public_access_config.get("BlockPublicAcls", False),
                    public_access_config.get("IgnorePublicAcls", False),
                    public_access_config.get("BlockPublicPolicy", False),
                    public_access_config.get("RestrictPublicBuckets", False),
                ]
            )
        except ClientError:
            # If we can't read the config, assume it's not blocked (fail safe)
            return False

    def get_bucket_policy(self, bucket_name: str) -> dict:
        """
        Scans a bucket policy to determine:
        1. How public the bucket is (String: Public, Potentially Public, Private)
        2. If SSL is strictly enforced (Boolean)
        """
        policy_assessment = {"Access": "Private", "SSL_Enforced": False}

        try:
            response = self._client.get_bucket_policy(Bucket=bucket_name)
            raw_bucket_policy = response.get("Policy", "{}")
            bucket_policy = json.loads(raw_bucket_policy)

            for statement in bucket_policy.get("Statement", []):
                if statement.get("Effect") == "Deny":
                    condition = statement.get("Condition", {})
                    bool_block = condition.get("Bool", {})
                    if str(bool_block.get("aws:SecureTransport")).lower() == "false":
                        policy_assessment["SSL_Enforced"] = True

                if statement.get("Effect") == "Allow":
                    if policy_assessment["Access"] == "Public":
                        continue

                    principal = statement.get("Principal")
                    if isinstance(principal, dict) and principal.get("AWS") == "*":
                        if statement.get("Condition"):
                            policy_assessment["Access"] = "Potentially Public"
                        else:
                            policy_assessment["Access"] = "Public"

                    elif principal == "*":
                        if statement.get("Condition"):
                            policy_assessment["Access"] = "Potentially Public"
                        else:
                            policy_assessment["Access"] = "Public"

            return policy_assessment

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                return policy_assessment
            else:
                return {"Access": "Error", "SSL_Enforced": False}

    def get_encryption_status(self, bucket_name: str) -> dict:
        """
        Checks for default server-side encryption and SSE-C blocking status.
        """
        result = {"SSEAlgorithm": "None", "SSECBlocked": False}
        try:
            response = self._client.get_bucket_encryption(Bucket=bucket_name)
            rules = response.get("ServerSideEncryptionConfiguration", {}).get(
                "Rules", []
            )
            if not rules:
                return result

            rule = rules[0]
            encryption_config = rule.get("ApplyServerSideEncryptionByDefault", {})
            result["SSEAlgorithm"] = encryption_config.get("SSEAlgorithm", "Unknown")

            blocked_types = rule.get("BlockedEncryptionTypes", [])
            if "SSE-C" in blocked_types:
                result["SSECBlocked"] = True

            return result
        except ClientError:
            return result

    def get_acl_status(self, bucket_name: str) -> str:
        """
        Returns 'Disabled' if BucketOwnerEnforced, otherwise 'Enabled'.
        """
        try:
            response = self._client.get_bucket_ownership_controls(Bucket=bucket_name)
            rules = response.get("OwnershipControls", {}).get("Rules", [])

            if not rules:
                return "Enabled"

            ownership = rules[0].get("ObjectOwnership")
            return "Disabled" if ownership == "BucketOwnerEnforced" else "Enabled"

        except ClientError:
            return "Enabled"

    def is_log_target(self, bucket_name: str) -> bool:
        """
        Checks if bucket is a target for S3 or CloudFront legacy logging.
        """
        cloudfront_log_delivery_id = (
            "c4c1ede66af53448b93c283ce9448c4ba468c9432aa01d700d3878632f77d2d0"
        )
        s3_log_delivery_uri = "http://acs.amazonaws.com/groups/s3/LogDelivery"

        try:
            acl = self._client.get_bucket_acl(Bucket=bucket_name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})

                if grantee.get("URI") == s3_log_delivery_uri:
                    return True

                if (
                    grantee.get("Type") == "CanonicalUser"
                    and grantee.get("ID") == cloudfront_log_delivery_id
                ):
                    return True
            return False
        except ClientError:
            return False

    def get_versioning_status(self, bucket_name: str) -> dict:
        """
        Returns a dict
        with 'Status' (Enabled/Suspended) and 'MFADelete' (Enabled/Disabled).
        """
        try:
            response = self._client.get_bucket_versioning(Bucket=bucket_name)
            return {
                "Status": response.get("Status", "Suspended"),
                "MFADelete": response.get("MFADelete", "Disabled"),
            }
        except ClientError:
            return {"Status": "Suspended", "MFADelete": "Disabled"}

    def get_object_lock_status(self, bucket_name: str) -> str:
        """
        Returns 'Enabled' or 'Disabled'.
        AWS throws ObjectLockConfigurationNotFoundError if disabled.
        """
        try:
            response = self._client.get_object_lock_configuration(Bucket=bucket_name)
            return response.get("ObjectLockConfiguration", {}).get(
                "ObjectLockEnabled", "Disabled"
            )
        except ClientError as e:
            # If config is not found, it implies it is disabled
            if e.response["Error"]["Code"] == "ObjectLockConfigurationNotFoundError":
                return "Disabled"
            return "Unknown"
