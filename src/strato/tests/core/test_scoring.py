from strato.core.scoring import ObservationLevel


def test_risk_weights_integrity():
    assert ObservationLevel.CRITICAL == 100
    assert ObservationLevel.HIGH == 50
    assert ObservationLevel.MEDIUM == 20
    assert ObservationLevel.LOW == 5
    assert ObservationLevel.INFO == 1
    assert ObservationLevel.PASS == 0