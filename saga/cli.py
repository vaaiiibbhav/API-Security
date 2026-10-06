"""CLI entrypoint for SAGA using Typer."""

from pathlib import Path

import typer

from saga import __version__
from saga.core.config import SagaConfig
from saga.core.logging import setup_logging
from saga.parser.ast_parser import parse_ast_routes_from_directory, parse_ast_routes_from_file
from saga.parser.correlator import correlate_endpoints
from saga.parser.openapi import parse_openapi_spec
from saga.verifier.static_verifier import analyze_target_security

app = typer.Typer(
    name="saga",
    help="SAGA: Security Analysis & Graph-based Audit Tool",
    add_completion=False,
)


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        typer.echo(f"SAGA version {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool | None = typer.Option(
        None,
        "--version",
        "-v",
        help="Show SAGA version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """SAGA CLI main entrypoint."""
    pass


@app.command()
def info() -> None:
    """Display system information and default configuration."""
    config = SagaConfig()
    logger = setup_logging(config.logging)
    logger.info("Initializing SAGA CLI...")
    typer.echo(f"SAGA Framework v{__version__}")
    typer.echo(f"Project: {config.project_name}")
    typer.echo(f"Target Base URL: {config.target.base_url}")


@app.command()
def graph(
    target: str = typer.Argument(
        "./testbed",
        help="Target directory, python file, or OpenAPI spec to analyze.",
    ),
) -> None:
    """Construct SAGA Authorization Graph and display static verification results."""
    target_path = Path(target)
    if not target_path.exists():
        typer.echo(f"Error: Target path '{target}' does not exist.", err=True)
        raise typer.Exit(code=1)

    # Perform AST route and security context parsing into Canonical IR
    if target_path.is_file():
        ast_endpoints = parse_ast_routes_from_file(target_path)
    else:
        ast_endpoints = parse_ast_routes_from_directory(target_path)

    # Check for optional OpenAPI spec file in target directory or app
    openapi_endpoints = []
    openapi_file = target_path / "openapi.json" if target_path.is_dir() else None
    if openapi_file and openapi_file.is_file():
        openapi_endpoints = parse_openapi_spec(openapi_file)

    correlated = correlate_endpoints(openapi_endpoints, ast_endpoints)
    if not correlated:
        correlated = ast_endpoints

    summary = analyze_target_security(correlated, target_path=str(target_path))


    typer.echo(f"\nDiscovered {summary.discovered_endpoints} endpoints\n")

    for report in summary.reports:
        typer.echo(f"{report.http_method} {report.path}\n")

        typer.echo("Principal:")
        typer.echo(f"    {report.principal}\n")

        typer.echo("Object:")
        typer.echo(f"    {report.object_entity}\n")

        typer.echo("Reference:")
        typer.echo(f"    {report.reference_param}\n")

        typer.echo("Authorization:")
        typer.echo(f"    {report.authorization_rule}\n")

        typer.echo("Graph:")
        for edge in report.graph_edges:
            typer.echo(f"    {edge}")
        typer.echo()

        typer.echo("Result:")
        typer.echo(f"    {report.result.value}\n")

        if report.result.value == "UNPROVEN":
            typer.echo("Candidate:")
            typer.echo(f"    {report.candidate.value}")
            typer.echo(f"    Confidence: {report.confidence}\n")

        typer.echo("-" * 50 + "\n")


if __name__ == "__main__":
    app()
