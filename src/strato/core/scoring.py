from enum import IntEnum


class ObservationLevel(IntEnum):
    """
    Standardized Levels for audit results.
    """

    # Impact: Catastrophic (Data Breach, Full Compromise)
    CRITICAL = 100

    # Impact: High (Privileged access, Unencrypted sensitive data)
    HIGH = 50

    # Impact: Medium (Configuration drift, Non-compliant settings)
    MEDIUM = 20

    # Impact: Low (Hygiene, Tagging)
    LOW = 5

    # Neutral: Purely informational (Inventory data)
    INFO = 1

    # Compliant: Explicitly passed a check
    PASS = 0
