from datetime import datetime

import pytest

from strato.core.scoring import ObservationLevel
from strato.services.s3.domains.security import S3SecurityResult, S3SecurityScanType


@pytest.fixture
def safe_result():
    return S3SecurityResult(
        account_id="111122223333",
        resource_arn="arn:aws:s3:::safe-bucket-3a9f1c4d",
        resource_name="safe-bucket-3a9f1c4d",
        region="us-east-1",
        creation_date=datetime(2023, 1, 1),
        public_access_block_status=True,
        policy_access="Private",
        ssl_enforced=True,
        encryption="AES256",
        sse_c=True,
        acl_status="Disabled",
        versioning="Enabled",
        mfa_delete="Enabled",
        object_lock="Enabled",
        check_type=S3SecurityScanType.ALL,
        log_sources=[],
    )


@pytest.fixture
def observation_result():
    return S3SecurityResult(
        account_id="111122223333",
        resource_arn="arn:aws:s3:::risky-bucket-7b8e9f0a",
        resource_name="risky-bucket-7b8e9f0a",
        region="us-east-1",
        creation_date=datetime(2023, 1, 1),
        public_access_block_status=False,
        encryption="None",
        acl_status="Enabled",
        versioning="Suspended",
        mfa_delete="Disabled",
        object_lock="Disabled",
        check_type=S3SecurityScanType.ALL,
        log_sources=[],
    )


@pytest.fixture
def policy_result():
    return S3SecurityResult(
        account_id="111122223333",
        resource_arn="arn:aws:s3:::policy-bucket-1a2b3c4d",
        resource_name="policy-bucket-1a2b3c4d",
        region="us-east-1",
        creation_date=datetime(2023, 1, 1),
        policy_access="Private",
        ssl_enforced=True,
        check_type=S3SecurityScanType.POLICY,
    )


def test_observation_level_all_safe(safe_result):
    assert safe_result.status_score == ObservationLevel.PASS
    assert safe_result.status == "PASS"
    assert len(safe_result.findings) == 0


def test_observation_level_critical(safe_result):
    safe_result.public_access_block_status = False
    safe_result._evaluate_status()

    assert safe_result.status_score >= ObservationLevel.CRITICAL
    assert "Public Access Allowed" in safe_result.findings


def test_observation_level_medium(safe_result):
    safe_result.encryption = "None"
    safe_result.sse_c = True
    safe_result._evaluate_status()

    assert safe_result.status_score == ObservationLevel.MEDIUM
    assert "Encryption Missing" in safe_result.findings


def test_observation_level_ssec_warning(safe_result):
    safe_result.sse_c = False
    safe_result._evaluate_status()

    assert safe_result.status_score == ObservationLevel.LOW
    assert "SSE-C Not Blocked" in safe_result.findings


def test_observation_level_mfa_object_lock_ignored_for_standard_buckets(observation_result):
    # Renamed fixture argument from 'risky_result' to 'observation_result'
    observation_result.public_access_block_status = True
    observation_result.encryption = "AES256"
    observation_result.sse_c = True
    observation_result.acl_status = "Disabled"
    observation_result.ssl_enforced = True
    observation_result.policy_access = "Private"

    # Versioning is enabled, but MFA/ObjectLock are disabled
    observation_result.versioning = "Enabled"
    observation_result.mfa_delete = "Disabled"
    observation_result.object_lock = "Disabled"
    observation_result.log_sources = []

    observation_result._evaluate_status()

    assert observation_result.status_score == ObservationLevel.PASS
    assert "MFA Delete Disabled" not in str(observation_result.findings)
    assert "Object Lock Disabled" not in str(observation_result.findings)


def test_status_scoring_mfa_object_lock_flagged_for_log_buckets(observation_result):
    # Renamed fixture argument from 'risky_result' to 'observation_result'
    observation_result.public_access_block_status = True
    observation_result.encryption = "AES256"
    observation_result.sse_c = True
    observation_result.acl_status = "Disabled"
    observation_result.ssl_enforced = True
    observation_result.policy_access = "Private"
    observation_result.versioning = "Enabled"

    # Inject log source
    observation_result.log_sources = ["cloudtrail.amazonaws.com"]

    observation_result._evaluate_status()

    assert observation_result.status_score >= ObservationLevel.LOW
    reasons = " ".join(observation_result.findings)
    assert "MFA Delete Disabled" in reasons
    assert "Object Lock Disabled" in reasons


def test_status_scoring_filtering(safe_result):
    safe_result.public_access_block_status = False
    safe_result.check_type = S3SecurityScanType.ENCRYPTION
    safe_result.encryption = "AES256"
    safe_result.sse_c = True
    safe_result._evaluate_status()

    assert safe_result.status_score == ObservationLevel.PASS


def test_render_style_integration(safe_result):
    safe_result.check_type = S3SecurityScanType.ENCRYPTION
    row = safe_result.get_table_row()
    # Row: [Account, Resource, Region, Date, Encryption, SSE-C, Status, Findings]
    enc_render = row[4]

    assert "[green]AES256[/green]" in enc_render


def test_render_style_risky(observation_result):
    # Renamed fixture argument from 'risky_result' to 'observation_result'
    observation_result.check_type = S3SecurityScanType.PUBLIC_ACCESS
    row = observation_result.get_table_row()
    # Row: [Account, Resource, Region, Date, BlockStatus, Status, Findings]
    pub_render = row[4]

    assert "[red]OPEN[/red]" in pub_render


def test_all_scan_table_is_summary(safe_result):
    safe_result.check_type = S3SecurityScanType.ALL
    headers = safe_result.get_headers(S3SecurityScanType.ALL)
    row = safe_result.get_table_row()

    assert len(headers) == 6
    assert len(row) == 6
    assert "Account ID" in headers
    assert "Encryption" not in headers
    assert "Object Lock" not in headers


def test_all_scan_csv_is_full_detail(safe_result):
    safe_result.check_type = S3SecurityScanType.ALL
    headers = safe_result.get_csv_headers(S3SecurityScanType.ALL)
    row = safe_result.get_csv_row()

    assert len(headers) > 6
    assert len(row) > 6
    assert len(headers) == len(row)
    assert "Account ID" in headers
    assert "Encryption" in headers
    assert "SSE-C" in headers
    assert "Object Lock" in headers
    assert "MFA Delete" in headers


def test_specific_scan_headers_match(safe_result):
    check_type = S3SecurityScanType.OBJECT_LOCK
    safe_result.check_type = check_type

    table_headers = safe_result.get_headers(check_type)
    csv_headers = safe_result.get_csv_headers(check_type)

    assert table_headers == csv_headers
    assert "Object Lock" in table_headers
    assert len(table_headers) == 7


def test_csv_row_alignment(safe_result):
    for scan_type in S3SecurityScanType:
        safe_result.check_type = scan_type
        headers = safe_result.get_csv_headers(scan_type)
        row = safe_result.get_csv_row()
        assert len(headers) == len(row)


def test_table_row_alignment(safe_result):
    for scan_type in S3SecurityScanType:
        safe_result.check_type = scan_type
        headers = safe_result.get_headers(scan_type)
        row = safe_result.get_table_row()
        assert len(headers) == len(row)


def test_json_filtering(safe_result):
    safe_result.check_type = S3SecurityScanType.OBJECT_LOCK
    data = safe_result.to_dict()

    assert "account_id" in data
    assert data["account_id"] == "111122223333"
    assert "resource_name" in data
    assert "status_score" in data
    assert "object_lock" in data
    assert "encryption" not in data
    assert "public_access_block_status" not in data
    assert "versioning" not in data


def test_json_structure_includes_log_sources(safe_result):
    safe_result.log_sources = ["config.amazonaws.com"]
    data = safe_result.to_dict()

    assert "log_sources" in data
    assert data["log_sources"] == ["config.amazonaws.com"]


def test_policy_scoring_safe(policy_result):
    assert policy_result.status_score == ObservationLevel.PASS
    assert policy_result.status == "PASS"
    assert len(policy_result.findings) == 0


def test_policy_scoring_critical_public(policy_result):
    policy_result.policy_access = "Public"
    policy_result._evaluate_status()

    assert policy_result.status_score >= ObservationLevel.CRITICAL
    assert "Bucket Policy Allows Public Access" in policy_result.findings


def test_policy_scoring_high_potentially_public(policy_result):
    policy_result.policy_access = "Potentially Public"
    policy_result._evaluate_status()

    assert policy_result.status_score == ObservationLevel.HIGH
    assert (
        "Bucket Policy Potentially Allows Public Access" in policy_result.findings
    )


def test_policy_scoring_medium_no_ssl(policy_result):
    policy_result.ssl_enforced = False
    policy_result._evaluate_status()

    assert policy_result.status_score == ObservationLevel.MEDIUM
    assert "SSL Not Enforced" in policy_result.findings


def test_policy_scoring_cumulative(policy_result):
    policy_result.policy_access = "Potentially Public"
    policy_result.ssl_enforced = False
    policy_result._evaluate_status()

    expected_score = ObservationLevel.HIGH + ObservationLevel.MEDIUM
    assert policy_result.status_score == expected_score
    assert len(policy_result.findings) == 2


def test_policy_render_style_safe(policy_result):
    row = policy_result.get_table_row()
    # Row: [Account, Resource, Region, Date, Access, SSL, Status, Findings]
    access_render = row[4]
    ssl_render = row[5]

    assert "Private" in access_render
    assert "green" in access_render
    assert "Yes" in ssl_render
    assert "green" in ssl_render


def test_policy_render_style_risky(policy_result):
    policy_result.policy_access = "Public"
    policy_result.ssl_enforced = False
    row = policy_result.get_table_row()

    assert "Public" in row[4]
    assert "red" in row[4]
    assert "No" in row[5]
    assert "red" in row[5]


def test_policy_render_style_warning(policy_result):
    policy_result.policy_access = "Potentially Public"
    row = policy_result.get_table_row()

    assert "Potentially Public" in row[4]
    assert "yellow" in row[4]


def test_policy_scan_csv_headers(policy_result):
    headers = policy_result.get_csv_headers(S3SecurityScanType.POLICY)

    assert "Account ID" in headers
    assert "Policy Access" in headers
    assert "SSL Enforced" in headers
    assert "Encryption" not in headers
    assert "MFA Delete" not in headers


def test_policy_json_structure(policy_result):
    policy_result.policy_access = "Public"
    policy_result.ssl_enforced = False
    data = policy_result.to_dict()

    assert data["policy_access"] == "Public"
    assert data["ssl_enforced"] is False


@pytest.fixture
def website_result():
    return S3SecurityResult(
        account_id="111122223333",
        resource_arn="arn:aws:s3:::website-bucket-123",
        resource_name="website-bucket-123",
        region="us-east-1",
        creation_date=datetime(2023, 1, 1),
        website_hosting=False,
        check_type=S3SecurityScanType.WEBSITE_HOSTING,
    )


def test_website_scoring_safe(website_result):
    website_result.website_hosting = False
    website_result._evaluate_status()

    assert website_result.status_score == ObservationLevel.PASS
    assert len(website_result.findings) == 0


def test_website_scoring_risky(website_result):
    website_result.website_hosting = True
    website_result._evaluate_status()

    assert website_result.status_score == ObservationLevel.HIGH
    assert "Static Website Hosting Enabled" in website_result.findings


def test_website_render_style_safe(website_result):
    website_result.website_hosting = False
    row = website_result.get_table_row()
    render = row[4]

    assert "Disabled" in str(render)
    assert "green" in str(render)


def test_website_render_style_risky(website_result):
    website_result.website_hosting = True
    row = website_result.get_table_row()
    render = row[4]

    assert "Enabled" in str(render)
    assert "yellow" in str(render)


def test_website_csv_headers(website_result):
    headers = website_result.get_csv_headers(S3SecurityScanType.WEBSITE_HOSTING)

    assert "Account ID" in headers
    assert "Website Hosting" in headers
    assert "Encryption" not in headers
    assert "Object Lock" not in headers


def test_website_json_structure(website_result):
    website_result.website_hosting = True
    data = website_result.to_dict()

    assert "website_hosting" in data
    assert data["website_hosting"] is True