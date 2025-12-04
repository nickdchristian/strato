from typing import List, Dict

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


class S3Client:
    def __init__(self):
        retry_config = Config(retries={"mode": "adaptive", "max_attempts": 10})
        self._client = boto3.client("s3", config=retry_config)

    def list_buckets(self) -> List[Dict]:
        paginator = self._client.get_paginator("list_buckets")
        buckets = []
        for page in paginator.paginate():
            buckets.extend(page.get("Buckets", []))

        return buckets

    def get_bucket_region(self, bucket_name: str) -> str:
        try:
            response = self._client.get_bucket_location(Bucket=bucket_name)
            return response.get("LocationConstraint") or "us-east-1"
        except ClientError:
            return "unknown"

    def get_public_access_status(self, bucket_name: str) -> bool:
        try:
            response = self._client.get_public_access_block(Bucket=bucket_name)
            conf = response.get("PublicAccessBlockConfiguration", {})
            return all(
                [
                    conf.get("BlockPublicAcls", False),
                    conf.get("IgnorePublicAcls", False),
                    conf.get("BlockPublicPolicy", False),
                    conf.get("RestrictPublicBuckets", False),
                ]
            )
        except ClientError:
            return False

    def get_encryption_status(self, bucket_name: str) -> str:
        try:
            response = self._client.get_bucket_encryption(Bucket=bucket_name)
            rules = response.get("ServerSideEncryptionConfiguration", {}).get(
                "Rules", []
            )
            if not rules:
                return "None"

            algo = (
                rules[0]
                .get("ApplyServerSideEncryptionByDefault", {})
                .get("SSEAlgorithm")
            )
            return algo or "Unknown"
        except ClientError:
            return "None"
