from typing import Annotated

import boto3
import typer
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
from rich.console import Console

from strato.services.awslambda.cli import lambda_app
from strato.services.ebs.cli import ebs_app
from strato.services.ec2.cli import ec2_app
from strato.services.ecs.cli import ecs_app
from strato.services.rds.cli import rds_app
from strato.services.s3.cli import s3_app

app = typer.Typer(help="Strato: AWS Auditor")
console_err = Console(stderr=True)


@app.callback()
def main(
    ctx: typer.Context,
    profile: Annotated[
        str | None, typer.Option("--profile", "-p", help="Specific AWS profile to use")
    ] = None,
    region: Annotated[
        str | None, typer.Option("--region", "-r", help="Specific AWS region to target")
    ] = None,
):
    """
    Global configuration for the AWS connection.
    Executes before any service subcommand.
    """
    # Initialize the context object dictionary
    ctx.ensure_object(dict)

    try:
        session = boto3.Session(profile_name=profile, region_name=region)

        # Identity check to verify live session
        sts = session.client("sts")
        identity = sts.get_caller_identity()

        # Inject into Typer context for downstream commands
        ctx.obj["session"] = session
        ctx.obj["account_id"] = identity.get("Account")

    except NoCredentialsError:
        console_err.print(
            "[bold red]Error:[/bold red] No AWS credentials found. "
            "Please run `aws configure` or log in via SSO."
        )
        raise typer.Exit(code=1) from None

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code in ["ExpiredToken", "RequestExpired", "UnauthorizedException"]:
            console_err.print(
                f"[bold red]Error:[/bold red] AWS session expired ({error_code}). "
                "Please re-authenticate your SSO or refresh your credentials."
            )
        else:
            console_err.print(f"[bold red]AWS Error:[/bold red] {e}")
        raise typer.Exit(code=1) from None

    except BotoCoreError as e:
        error_msg = str(e)
        if "SSO" in error_msg or "TokenRetrievalError" in e.__class__.__name__:
            console_err.print(
                "[bold red]Error:[/bold red] SSO Token expired or invalid. "
                "Please run `aws sso login`."
            )
        else:
            console_err.print(f"[bold red]AWS Connection Error:[/bold red] {error_msg}")
        raise typer.Exit(code=1) from None

    except Exception as e:
        console_err.print(f"[bold red]Unexpected Error:[/bold red] {e}")
        raise typer.Exit(code=1) from e


app.add_typer(s3_app, name="s3")
app.add_typer(ec2_app, name="ec2")
app.add_typer(lambda_app, name="lambda")
app.add_typer(rds_app, name="rds")
app.add_typer(ebs_app, name="ebs")
app.add_typer(ecs_app, name="ecs")

if __name__ == "__main__":
    app()
