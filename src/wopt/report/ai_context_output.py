"""
wopt.report.ai_context_output

Formate un ScanResult en markdown structuré, optimisé pour être
collé directement dans un prompt d'agent IA (Claude Code, Cursor...)
afin qu'il corrige automatiquement les failles trouvées.
C'est le différenciateur "vibe coding" de wopt (v0.3).
"""

from __future__ import annotations

from wopt.models import ScanResult, Severity

SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def to_ai_context(result: ScanResult) -> str:
    lines = [
        f"# Audit de sécurité — {result.target}",
        "",
        f"Score global : {result.score} ({result.score_value}/100)",
        "",
        "Corrige les problèmes suivants, du plus critique au moins critique. "
        "Pour chaque correctif, applique la recommandation indiquée.",
        "",
    ]

    for severity in SEVERITY_ORDER:
        items = result.findings_by_severity(severity)
        if not items:
            continue
        lines.append(f"## {severity.value.upper()} ({len(items)})")
        lines.append("")
        for f in items:
            lines.append(f"- **{f.title}**")
            lines.append(f"  - Problème : {f.description}")
            lines.append(f"  - Correctif : {f.recommendation}")
            if f.evidence:
                lines.append(f"  - Preuve observée : `{f.evidence}`")
        lines.append("")

    return "\n".join(lines)
