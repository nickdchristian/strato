import typer
from stratum.core.runner import run_scan  # Import the shared runner
from stratum.services.s3.audit import S3Scanner, S3Result, S3ScanType

app = typer.Typer(help="S3 Security Audits")


@app.command("all")
def security_scan_all(
    verbose: bool = False,
    fail_on_risk: bool = typer.Option(
        False, "--fail-on-risk", help="Exit code 1 if risks found"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
    csv_output: bool = typer.Option(False, "--csv", help="Output CSV"),
    failures_only: bool = typer.Option(
        False, "--failures-only", help="Show failures only"
    ),
):
    """Run ALL S3 Security checks."""
    run_scan(
        S3Scanner,
        S3Result,
        S3ScanType.ALL,
        verbose,
        fail_on_risk,
        json_output,
        csv_output,
        failures_only,
    )


@app.command("encryption")
def encryption_scan(
    verbose: bool = False,
    fail_on_risk: bool = typer.Option(
        False, "--fail-on-risk", help="Exit code 1 if risks found"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
    csv_output: bool = typer.Option(False, "--csv", help="Output CSV"),
    failures_only: bool = typer.Option(
        False, "--failures-only", help="Show failures only"
    ),
):
    """Scan ONLY for default encryption."""
    run_scan(
        S3Scanner,
        S3Result,
        S3ScanType.ENCRYPTION,
        verbose,
        fail_on_risk,
        json_output,
        csv_output,
        failures_only,
    )


@app.command("public-access")
def public_access_scan(
    verbose: bool = False,
    fail_on_risk: bool = typer.Option(
        False, "--fail-on-risk", help="Exit code 1 if risks found"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
    csv_output: bool = typer.Option(False, "--csv", help="Output CSV"),
    failures_only: bool = typer.Option(
        False, "--failures-only", help="Show failures only"
    ),
):
    """Scan ONLY for public access blocks."""
    run_scan(
        S3Scanner,
        S3Result,
        S3ScanType.PUBLIC_ACCESS,
        verbose,
        fail_on_risk,
        json_output,
        csv_output,
        failures_only,
    )
