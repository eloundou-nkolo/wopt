"""
wopt.cli

Point d'entrée en ligne de commande.

Exemples :
    wopt scan exemple.com
    wopt scan https://exemple.com --format json
    wopt scan https://exemple.com --format html -o rapport.html
    wopt scan https://exemple.com --ai-context
    wopt scan https://exemple.com --no-probes
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from wopt.core.http_client import FetchError
from wopt.core.scanner import scan
from wopt.models import Severity
from wopt.report.ai_context_output import to_ai_context
from wopt.report.html_output import to_html
from wopt.report.json_output import to_json

app = typer.Typer(
    name="wopt",
    help="Mini audit de sécurité web en ligne de commande.\n\n"
    "Développé par Eloundou Nkolo Ryan — https://eloundounkolo.com",
    add_completion=False,
)
console = Console()

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

SCORE_COLORS = {"A": "green", "B": "green", "C": "yellow", "D": "yellow", "E": "red", "F": "bold red"}


@app.command()
def scan_command(
    target: str = typer.Argument(..., help="URL ou domaine à scanner, ex: exemple.com"),
    format: str = typer.Option("table", "--format", "-f", help="table | json | html"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Fichier de sortie (json/html)"),
    ai_context: bool = typer.Option(
        False, "--ai-context", help="Génère un rapport markdown prêt à coller dans un agent IA"
    ),
    no_probes: bool = typer.Option(
        False, "--no-probes", help="Désactive la vérification des chemins sensibles (scan plus léger)"
    ),
    timeout: float = typer.Option(10.0, "--timeout", help="Timeout HTTP en secondes"),
):
    """Lance un audit de sécurité non-intrusif sur TARGET."""
    with console.status(f"[bold cyan]Scan de {target}...[/bold cyan]"):
        try:
            result = scan(target, timeout=timeout, include_probes=not no_probes)
        except FetchError as exc:
            console.print(f"[bold red]Erreur :[/bold red] {exc}")
            raise typer.Exit(code=1)

    if ai_context:
        content = to_ai_context(result)
        if output:
            output.write_text(content, encoding="utf-8")
            console.print(f"[green]Rapport IA écrit dans {output}[/green]")
        else:
            console.print(content)
        return

    if format == "json":
        content = to_json(result)
        if output:
            output.write_text(content, encoding="utf-8")
            console.print(f"[green]Rapport JSON écrit dans {output}[/green]")
        else:
            console.print(content)
        return

    if format == "html":
        content = to_html(result)
        out_path = output or Path("wopt-report.html")
        out_path.write_text(content, encoding="utf-8")
        console.print(f"[green]Rapport HTML écrit dans {out_path}[/green]")
        return

    _print_table(result)


def _print_table(result) -> None:
    score_color = SCORE_COLORS.get(result.score, "white")
    console.print()
    console.print(f"[bold]Cible :[/bold] {result.target}")
    console.print(f"[bold]Score :[/bold] [{score_color}]{result.score}[/{score_color}] ({result.score_value}/100)")
    console.print(f"[dim]Scan effectué en {result.duration_ms:.0f} ms[/dim]")
    console.print()

    if not result.findings:
        console.print("[green]✓ Aucun problème détecté.[/green]")
        return

    table = Table(show_lines=False)
    table.add_column("Sévérité", no_wrap=True)
    table.add_column("Catégorie", no_wrap=True)
    table.add_column("Problème")
    table.add_column("Recommandation")

    severity_order = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]
    for severity in severity_order:
        for finding in result.findings_by_severity(severity):
            color = SEVERITY_COLORS.get(severity, "white")
            table.add_row(
                f"[{color}]{severity.value.upper()}[/{color}]",
                finding.category,
                finding.title,
                finding.recommendation,
            )

    console.print(table)


def main():
    app()


if __name__ == "__main__":
    main()
