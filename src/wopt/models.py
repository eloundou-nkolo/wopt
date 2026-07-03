"""
wopt.models

Structures de données partagées par tout le projet :
- Severity : niveau de gravité d'un résultat
- Finding : un résultat individuel produit par un check
- ScanContext : les données brutes collectées sur la cible, passées à chaque check
- ScanResult : le résultat final agrégé d'un scan complet
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    PASS = "pass"

    @property
    def weight(self) -> int:
        """Poids utilisé pour le calcul du score global."""
        return {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 0,
            Severity.PASS: 0,
        }[self]


@dataclass
class Finding:
    """Un résultat individuel produit par un check de sécurité."""

    check_id: str
    title: str
    severity: Severity
    category: str
    description: str
    recommendation: str
    evidence: str | None = None


@dataclass
class Cookie:
    name: str
    secure: bool
    http_only: bool
    same_site: str | None


@dataclass
class ScanContext:
    """Toutes les données brutes collectées sur la cible.
    Centralisé pour qu'un seul jeu de requêtes HTTP suffise
    à alimenter tous les checks (pas de requêtes redondantes)."""

    url: str
    final_url: str
    status_code: int
    response_headers: dict[str, str]
    response_body: str
    cookies: list[Cookie] = field(default_factory=list)
    tls_info: dict | None = None
    elapsed_ms: float = 0.0


@dataclass
class ScanResult:
    """Résultat final agrégé, prêt à être formaté (JSON/HTML/CLI)."""

    target: str
    scanned_at: datetime
    findings: list[Finding]
    score: str = "?"          # lettre A-F
    score_value: int = 0       # 0-100
    duration_ms: float = 0.0

    @classmethod
    def build(cls, target: str, findings: list[Finding], duration_ms: float) -> "ScanResult":
        return cls(
            target=target,
            scanned_at=datetime.now(timezone.utc),
            findings=findings,
            duration_ms=duration_ms,
        )

    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def count_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts
