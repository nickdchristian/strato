import typer
from stratum.services.s3.cli import s3_app

app = typer.Typer(help="Stratum (stm): Multi-service AWS Auditor")

app.add_typer(s3_app, name="s3")

if __name__ == "__main__":
    app()