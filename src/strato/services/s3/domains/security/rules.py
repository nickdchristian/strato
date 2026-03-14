from collections.abc import Callable

from strato.core.models import ObservationLevel
from strato.services.s3.domains.security.checks import (
    S3SecurityResult,
    S3SecurityScanType,
)


class S3SecurityEvaluator:
    """
    Applies business logic and best-practice scoring to pure S3 facts.
    """

    @classmethod
    def evaluate(cls, resource: S3SecurityResult) -> tuple[int, list[str]]:
        score = 0
        findings = []

        # Iterate only through the functions required for this check_type
        for check_func in cls._get_check_functions(resource.check_type):
            c_score, c_findings = check_func(resource)
            score += c_score
            findings.extend(c_findings)

        return score, findings

    @classmethod
    def _get_check_functions(
        cls, check_type: str
    ) -> list[Callable[[S3SecurityResult], tuple[int, list[str]]]]:
        """Maps the ScanType to the specific rule functions that need to be run."""

        check_map: dict[str, Callable[[S3SecurityResult], tuple[int, list[str]]]] = {
            S3SecurityScanType.PUBLIC_ACCESS: cls._check_public_access,
            S3SecurityScanType.POLICY: cls._check_policy,
            S3SecurityScanType.ENCRYPTION: cls._check_encryption,
            S3SecurityScanType.ACLS: cls._check_acls,
            S3SecurityScanType.VERSIONING: cls._check_versioning,
            S3SecurityScanType.OBJECT_LOCK: cls._check_object_lock,
            S3SecurityScanType.NAME_PREDICTABILITY: cls._check_name_predictability,
            S3SecurityScanType.WEBSITE_HOSTING: cls._check_website_hosting,
        }

        if check_type == S3SecurityScanType.ALL:
            return list(check_map.values())

        func = check_map.get(check_type)
        return [func] if func else []

    @staticmethod
    def _check_public_access(r: S3SecurityResult) -> tuple[int, list[str]]:
        if not r.public_access_block_status:
            return ObservationLevel.CRITICAL, ["Public Access Allowed"]
        return 0, []

    @staticmethod
    def _check_policy(r: S3SecurityResult) -> tuple[int, list[str]]:
        score, findings = 0, []
        if not r.ssl_enforced:
            score += ObservationLevel.MEDIUM
            findings.append("SSL Not Enforced")
        if r.policy_access == "Public":
            score += ObservationLevel.CRITICAL
            findings.append("Bucket Policy Allows Public Access")
        elif r.policy_access == "Potentially Public":
            score += ObservationLevel.HIGH
            findings.append("Bucket Policy Potentially Allows Public Access")
        return score, findings

    @staticmethod
    def _check_encryption(r: S3SecurityResult) -> tuple[int, list[str]]:
        score, findings = 0, []
        if r.encryption == "None":
            score += ObservationLevel.MEDIUM
            findings.append("Encryption Missing")
        if not r.sse_c:
            score += ObservationLevel.LOW
            findings.append("SSE-C Not Blocked")
        return score, findings

    @staticmethod
    def _check_acls(r: S3SecurityResult) -> tuple[int, list[str]]:
        if r.acl_status == "Enabled":
            if r.log_target:
                return ObservationLevel.MEDIUM, ["Legacy ACLs (Required for Logging)"]
            return ObservationLevel.HIGH, ["Legacy ACLs Enabled"]
        return 0, []

    @staticmethod
    def _check_versioning(r: S3SecurityResult) -> tuple[int, list[str]]:
        score, findings = 0, []
        if r.versioning != "Enabled":
            score += ObservationLevel.MEDIUM
            findings.append("Versioning Disabled")
        elif r.mfa_delete != "Enabled" and len(r.log_sources) > 0:
            score += ObservationLevel.LOW
            findings.append(f"MFA Delete Disabled ({', '.join(r.log_sources)} Bucket)")
        return score, findings

    @staticmethod
    def _check_object_lock(r: S3SecurityResult) -> tuple[int, list[str]]:
        if r.object_lock != "Enabled" and len(r.log_sources) > 0:
            return ObservationLevel.LOW, [
                f"Object Lock Disabled ({', '.join(r.log_sources)} Bucket)"
            ]
        return 0, []

    @staticmethod
    def _check_name_predictability(r: S3SecurityResult) -> tuple[int, list[str]]:
        if r.name_predictability == "HIGH":
            return ObservationLevel.LOW, ["Highly Predictable Bucket Name"]
        if r.name_predictability == "MODERATE":
            return ObservationLevel.INFO, ["Moderately Predictable Bucket Name"]
        return 0, []

    @staticmethod
    def _check_website_hosting(r: S3SecurityResult) -> tuple[int, list[str]]:
        if r.website_hosting:
            return ObservationLevel.HIGH, ["Static Website Hosting Enabled"]
        return 0, []
