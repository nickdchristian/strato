from strato.core.scoring import RiskWeight
from strato.services.s3.domains.security import S3SecurityScanType


def test_s3_safe(base_s3_result):
    assert base_s3_result.risk_score == RiskWeight.NONE
    assert base_s3_result.risk_level == "SAFE"


def test_s3_public_access_risk(base_s3_result):
    base_s3_result.public_access_blocked = False
    base_s3_result._evaluate_risk()

    assert base_s3_result.risk_score == RiskWeight.CRITICAL
    assert "Public Access Allowed" in base_s3_result.risk_reasons


def test_s3_encryption_risk(base_s3_result):
    base_s3_result.encryption = "None"
    base_s3_result._evaluate_risk()

    assert base_s3_result.risk_score == RiskWeight.MEDIUM
    assert "Encryption Missing" in base_s3_result.risk_reasons


def test_s3_mixed_risk(base_s3_result):
    base_s3_result.public_access_blocked = False
    base_s3_result.encryption = "None"
    base_s3_result._evaluate_risk()

    expected_score = RiskWeight.CRITICAL + RiskWeight.MEDIUM
    assert base_s3_result.risk_score == expected_score
    assert len(base_s3_result.risk_reasons) == 2


def test_s3_check_type_filtering(base_s3_result):
    base_s3_result.check_type = S3SecurityScanType.ENCRYPTION
    base_s3_result.public_access_blocked = False
    base_s3_result.encryption = "AES256"
    base_s3_result._evaluate_risk()

    assert base_s3_result.risk_score == RiskWeight.NONE


def test_s3_acl_safe(base_s3_result):
    base_s3_result.acl_status = "Disabled"
    base_s3_result.is_log_target = False
    base_s3_result._evaluate_risk()

    assert base_s3_result.risk_score == RiskWeight.NONE
    assert "Legacy ACLs" not in str(base_s3_result.risk_reasons)


def test_s3_acl_legacy_log_risk(base_s3_result):
    base_s3_result.acl_status = "Enabled"
    base_s3_result.is_log_target = True
    base_s3_result._evaluate_risk()

    assert base_s3_result.risk_score == RiskWeight.MEDIUM
    assert "Legacy ACLs (Required for Logging)" in base_s3_result.risk_reasons


def test_s3_acl_legacy_enabled_risk(base_s3_result):
    base_s3_result.acl_status = "Enabled"
    base_s3_result.is_log_target = False
    base_s3_result._evaluate_risk()

    assert base_s3_result.risk_score == RiskWeight.HIGH
    assert "Legacy ACLs Enabled" in base_s3_result.risk_reasons


def test_s3_acl_check_type_filtering(base_s3_result):
    base_s3_result.encryption = "None"
    base_s3_result.acl_status = "Enabled"
    base_s3_result.is_log_target = False

    # Scan ONLY for Encryption
    base_s3_result.check_type = S3SecurityScanType.ENCRYPTION
    base_s3_result._evaluate_risk()

    assert base_s3_result.risk_score == RiskWeight.MEDIUM
    assert "Encryption Missing" in base_s3_result.risk_reasons
    assert "Legacy ACLs Enabled" not in base_s3_result.risk_reasons

    # Scan ONLY for ACLs
    base_s3_result.check_type = S3SecurityScanType.ACLS
    base_s3_result._evaluate_risk()

    assert base_s3_result.risk_score == RiskWeight.HIGH
    assert "Legacy ACLs Enabled" in base_s3_result.risk_reasons
    assert "Encryption Missing" not in base_s3_result.risk_reasons


def test_s3_versioning_risk_medium(base_s3_result):
    """Verify Versioning Disabled is a MEDIUM risk."""
    base_s3_result.check_type = S3SecurityScanType.VERSIONING
    base_s3_result.versioning = "Suspended"
    base_s3_result._evaluate_risk()

    assert base_s3_result.risk_score == RiskWeight.MEDIUM
    assert "Versioning Disabled" in base_s3_result.risk_reasons


def test_s3_mfa_delete_risk_low(base_s3_result):
    """Verify MFA Delete Disabled is a LOW risk."""
    base_s3_result.check_type = S3SecurityScanType.VERSIONING
    base_s3_result.versioning = "Enabled"
    base_s3_result.mfa_delete = "Disabled"
    base_s3_result._evaluate_risk()

    assert base_s3_result.risk_score == RiskWeight.LOW
    assert "MFA Delete Disabled" in base_s3_result.risk_reasons


def test_s3_versioning_safe(base_s3_result):
    """Verify SAFE state when both Versioning and MFA are enabled."""
    base_s3_result.check_type = S3SecurityScanType.VERSIONING
    base_s3_result.versioning = "Enabled"
    base_s3_result.mfa_delete = "Enabled"
    base_s3_result._evaluate_risk()

    assert base_s3_result.risk_score == RiskWeight.NONE
    assert len(base_s3_result.risk_reasons) == 0


def test_s3_versioning_check_type_filtering(base_s3_result):
    """Verify Versioning risks are ignored if the scan type is ENCRYPTION."""
    base_s3_result.versioning = "Suspended"

    # Scan ONLY for Encryption
    base_s3_result.check_type = S3SecurityScanType.ENCRYPTION
    base_s3_result.encryption = "AES256"

    base_s3_result._evaluate_risk()

    # Should be 0 because we didn't ask for a Versioning check
    assert base_s3_result.risk_score == RiskWeight.NONE
    assert "Versioning Disabled" not in base_s3_result.risk_reasons


def test_s3_object_lock_risk_low(base_s3_result):
    """Verify Object Lock Disabled is a LOW risk."""
    base_s3_result.check_type = S3SecurityScanType.OBJECT_LOCK
    base_s3_result.object_lock = "Disabled"
    base_s3_result._evaluate_risk()

    assert base_s3_result.risk_score == RiskWeight.LOW
    assert "Object Lock Disabled" in base_s3_result.risk_reasons


def test_s3_object_lock_safe(base_s3_result):
    """Verify SAFE state when Object Lock is enabled."""
    base_s3_result.check_type = S3SecurityScanType.OBJECT_LOCK
    base_s3_result.object_lock = "Enabled"
    base_s3_result._evaluate_risk()

    assert base_s3_result.risk_score == RiskWeight.NONE
    assert "Object Lock Disabled" not in base_s3_result.risk_reasons


def test_s3_object_lock_check_type_filtering(base_s3_result):
    """Verify Object Lock risks are ignored if the scan type is ENCRYPTION."""
    base_s3_result.object_lock = "Disabled"

    # Scan ONLY for Encryption
    base_s3_result.check_type = S3SecurityScanType.ENCRYPTION
    # Set encryption to safe so we expect 0 risk
    base_s3_result.encryption = "AES256"

    base_s3_result._evaluate_risk()

    # Should be 0 because we didn't ask for an Object Lock check
    assert base_s3_result.risk_score == RiskWeight.NONE
    assert "Object Lock Disabled" not in base_s3_result.risk_reasons


def test_s3_object_lock_included_in_all(base_s3_result):
    """Verify Object Lock is checked during an ALL scan."""
    base_s3_result.check_type = S3SecurityScanType.ALL
    base_s3_result.object_lock = "Disabled"

    # Set other fields to safe to isolate Object Lock risk
    base_s3_result.public_access_blocked = True
    base_s3_result.encryption = "AES256"
    base_s3_result.acl_status = "Disabled"
    base_s3_result.versioning = "Enabled"
    base_s3_result.mfa_delete = "Enabled"

    base_s3_result._evaluate_risk()

    assert base_s3_result.risk_score == RiskWeight.LOW
    assert "Object Lock Disabled" in base_s3_result.risk_reasons


def test_s3_json_filtering_object_lock(base_s3_result):
    """
    Regression Test: Ensure JSON output (to_dict) strictly filters out
    fields irrelevant to the current check_type.
    """
    # Setup: A result specifically for OBJECT_LOCK
    base_s3_result.check_type = S3SecurityScanType.OBJECT_LOCK
    base_s3_result.object_lock = "Enabled"
    # Set other fields that should exist in memory but NOT in the JSON output
    base_s3_result.encryption = "AES256"
    base_s3_result.public_access_blocked = True

    data = base_s3_result.to_dict()

    # Assert: Core fields must be present
    assert "resource_name" in data
    assert "risk_score" in data
    assert "object_lock" in data

    # Assert: Irrelevant fields must be ABSENT
    assert "encryption" not in data
    assert "public_access_blocked" not in data
    assert "acl_status" not in data
    assert "versioning" not in data


def test_s3_csv_alignment_strict(base_s3_result):
    """
    Regression Test: Ensures CSV Row and Headers have the exact same length and order.
    This catches the 'Creation Date' mismatch bug.
    """
    # Setup: Use ALL scan to test the widest possible row
    base_s3_result.check_type = S3SecurityScanType.ALL
    base_s3_result.object_lock = "Enabled"

    headers = base_s3_result.get_headers(S3SecurityScanType.ALL)
    row = base_s3_result.get_csv_row()

    # Assert 1: Length mismatch is the most common regression
    assert len(headers) == len(row), (
        f"Mismatch! Headers count ({len(headers)}) != Row count ({len(row)})"
    )

    # Assert 2: Verify specific headers align with expected data
    # Index 0-2 should always be Name, Region, Date
    assert headers[0] == "Bucket Name"
    assert row[0] == base_s3_result.resource_name

    assert headers[2] == "Creation Date"
    assert row[2] == base_s3_result.creation_date.isoformat()

    # Assert 3: Verify the tail (Risk Data) is aligned
    assert headers[-1] == "Reasons"
    # The last row item should be the stringified reasons (empty string if safe)
    assert isinstance(row[-1], str)


def test_s3_csv_specific_scan_filtering(base_s3_result):
    """
    Regression Test: Ensure a specific scan (e.g., Encryption) produces
    a minimal CSV row without leaking other columns.
    """
    base_s3_result.check_type = S3SecurityScanType.ENCRYPTION
    base_s3_result.encryption = "AES256"

    headers = base_s3_result.get_headers(S3SecurityScanType.ENCRYPTION)
    row = base_s3_result.get_csv_row()

    # Verify length match
    assert len(headers) == len(row)

    # Verify specific columns
    assert "Encryption" in headers
    assert "Object Lock" not in headers
    assert "Public Blocked" not in headers

    # Verify data exists in the correct column
    enc_index = headers.index("Encryption")
    assert row[enc_index] == "AES256"
