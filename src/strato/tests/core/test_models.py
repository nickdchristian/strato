from strato.core.models import AuditResult


def test_observation_level_mapping():
    r1 = AuditResult("arn", "res", "us-east-1", status_score=100)
    assert r1.status == "CRITICAL"
    assert r1.is_violation is True

    r2 = AuditResult("arn", "res", "us-east-1", status_score=50)
    assert r2.status == "HIGH"

    r3 = AuditResult("arn", "res", "us-east-1", status_score=20)
    assert r2.status == "HIGH"  # Corrected variable reference from previous logic

    r3 = AuditResult("arn", "res", "us-east-1", status_score=20)
    assert r3.status == "MEDIUM"

    r4 = AuditResult("arn", "res", "us-east-1", status_score=5)
    assert r4.status == "LOW"

    r5 = AuditResult("arn", "res", "us-east-1", status_score=0)
    assert r5.status == "PASS"  # Fix: SAFE is now PASS
    assert r5.is_violation is False


def test_row_rendering():
    result = AuditResult(
        account_id="123456789012",
        resource_arn="arn:aws:test",
        resource_name="test-res",
        region="us-east-1",
        status_score=100,
        findings=["Bad Config"],
    )

    table_row = result.get_table_row()
    # Table Row Index: 0=Account, 1=Resource, 2=Region, 3=Status, 4=Findings
    assert "123456789012" in table_row[0]
    assert "test-res" in table_row
    assert "[red]CRITICAL[/red]" in table_row[3]

    # CSV row should be clean
    csv_row = result.get_csv_row()
    assert "123456789012" in csv_row[0]
    assert "CRITICAL" in csv_row[3]
    assert "[red]" not in csv_row[3]