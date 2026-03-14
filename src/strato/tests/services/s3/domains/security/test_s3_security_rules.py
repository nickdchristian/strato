from strato.core.models import ObservationLevel
from strato.services.s3.domains.security.checks import (
    S3SecurityResult,
    S3SecurityScanType,
)
from strato.services.s3.domains.security.rules import S3SecurityEvaluator


def test_evaluator_all_clear():
    result = S3SecurityResult(
        resource_arn="arn:aws:s3:::safe-bucket",
        resource_name="safe-bucket",
        region="us-east-1",
        account_id="123",
        public_access_block_status=True,
        ssl_enforced=True,
        policy_access="Private",
        encryption="AES256",
        versioning="Enabled",
        acl_status="Disabled",
        sse_c=True,
        name_predictability="LOW",
        check_type=S3SecurityScanType.ALL,
    )

    score, findings = S3SecurityEvaluator.evaluate(result)

    assert score == 0
    assert not findings


def test_evaluator_public_access():
    result = S3SecurityResult(
        resource_arn="arn",
        resource_name="bucket",
        region="us",
        account_id="123",
        public_access_block_status=False,
        check_type=S3SecurityScanType.PUBLIC_ACCESS,
    )

    score, findings = S3SecurityEvaluator.evaluate(result)

    assert score >= ObservationLevel.CRITICAL
    assert "Public Access Allowed" in findings


def test_evaluator_policy_issues():
    result = S3SecurityResult(
        resource_arn="arn",
        resource_name="bucket",
        region="us",
        account_id="123",
        ssl_enforced=False,
        policy_access="Potentially Public",
        check_type=S3SecurityScanType.POLICY,
    )

    score, findings = S3SecurityEvaluator.evaluate(result)

    assert score >= ObservationLevel.HIGH
    assert "SSL Not Enforced" in findings
    assert "Bucket Policy Potentially Allows Public Access" in findings


def test_evaluator_encryption():
    result = S3SecurityResult(
        resource_arn="arn",
        resource_name="bucket",
        region="us",
        account_id="123",
        encryption="None",
        sse_c=False,
        check_type=S3SecurityScanType.ENCRYPTION,
    )

    score, findings = S3SecurityEvaluator.evaluate(result)

    assert score >= ObservationLevel.MEDIUM
    assert "Encryption Missing" in findings
    assert "SSE-C Not Blocked" in findings


def test_evaluator_acls_logging():
    res_log = S3SecurityResult(
        resource_arn="arn",
        resource_name="b",
        region="us",
        account_id="1",
        acl_status="Enabled",
        log_target=True,
        check_type=S3SecurityScanType.ACLS,
    )
    score_log, _ = S3SecurityEvaluator.evaluate(res_log)
    assert score_log == ObservationLevel.MEDIUM

    res_std = S3SecurityResult(
        resource_arn="arn",
        resource_name="b",
        region="us",
        account_id="1",
        acl_status="Enabled",
        log_target=False,
        check_type=S3SecurityScanType.ACLS,
    )
    score_std, _ = S3SecurityEvaluator.evaluate(res_std)
    assert score_std == ObservationLevel.HIGH


def test_evaluator_versioning_mfa():
    result = S3SecurityResult(
        resource_arn="arn",
        resource_name="bucket",
        region="us",
        account_id="123",
        versioning="Enabled",
        mfa_delete="Disabled",
        log_sources=["cloudtrail.amazonaws.com"],
        check_type=S3SecurityScanType.VERSIONING,
    )

    score, findings = S3SecurityEvaluator.evaluate(result)

    assert score >= ObservationLevel.LOW
    assert any("MFA Delete Disabled" in f for f in findings)


def test_evaluator_website_hosting():
    result = S3SecurityResult(
        resource_arn="arn",
        resource_name="bucket",
        region="us",
        account_id="123",
        website_hosting=True,
        check_type=S3SecurityScanType.WEBSITE_HOSTING,
    )

    score, findings = S3SecurityEvaluator.evaluate(result)

    assert score >= ObservationLevel.HIGH
    assert "Static Website Hosting Enabled" in findings
