"""
wopt.report.scoring

Calcule un score de sécurité global (0-100, converti en lettre A-F)
à partir de la liste de findings, en pondérant par sévérité.
Inspiré de l'approche Mozilla Observatory : on part de 100 et on
soustrait des points selon la gravité de chaque finding.
"""

from __future__ import annotations

from wopt.models import Finding

MAX_SCORE = 100


def compute_score(findings: list[Finding]) -> tuple[str, int]:
    """Retourne (lettre, valeur_numerique)."""
    penalty = sum(f.severity.weight for f in findings)
    score_value = max(0, MAX_SCORE - penalty)
    return _to_letter(score_value), score_value


def _to_letter(score_value: int) -> str:
    if score_value >= 90:
        return "A"
    if score_value >= 75:
        return "B"
    if score_value >= 60:
        return "C"
    if score_value >= 40:
        return "D"
    if score_value >= 20:
        return "E"
    return "F"
