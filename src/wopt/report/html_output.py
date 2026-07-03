"""
wopt.report.html_output

Rend le rapport HTML lisible via le template Jinja2.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from wopt.models import ScanResult

TEMPLATES_DIR = Path(__file__).parent / "templates"


def to_html(result: ScanResult) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html.j2")
    return template.render(
        result=result,
        findings=result.findings,
        summary=result.count_by_severity(),
    )
