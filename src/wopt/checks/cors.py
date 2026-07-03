"""
wopt.checks.cors

Détecte les configurations CORS dangereuses, en particulier
la combinaison Access-Control-Allow-Origin: * associée à
Access-Control-Allow-Credentials: true, qui permet à n'importe
quel site tiers de lire des réponses authentifiées.
"""

from __future__ import annotations

from wopt.checks.base import Check
from wopt.models import Finding, ScanContext, Severity


class CORSCheck(Check):
    id = "cors.configuration"
    name = "CORS Configuration"
    category = "cors"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        headers_lower = {k.lower(): v for k, v in ctx.response_headers.items()}

        acao = headers_lower.get("access-control-allow-origin")
        acac = headers_lower.get("access-control-allow-credentials", "").lower() == "true"

        if acao == "*" and acac:
            findings.append(
                Finding(
                    check_id=f"{self.id}.wildcard_with_credentials",
                    title="CORS critique : origine wildcard combinée aux credentials",
                    severity=Severity.CRITICAL,
                    category=self.category,
                    description=(
                        "Access-Control-Allow-Origin est réglé sur '*' alors que "
                        "Access-Control-Allow-Credentials est à 'true'. N'importe quel "
                        "site tiers peut lire des réponses authentifiées de l'utilisateur."
                    ),
                    recommendation=(
                        "Remplacer '*' par une liste blanche explicite d'origines de confiance, "
                        "ou désactiver les credentials si le wildcard est nécessaire."
                    ),
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                )
            )
        elif acao == "*":
            findings.append(
                Finding(
                    check_id=f"{self.id}.wildcard_origin",
                    title="CORS permissif : origine wildcard",
                    severity=Severity.LOW,
                    category=self.category,
                    description="Access-Control-Allow-Origin accepte toute origine ('*').",
                    recommendation="Restreindre aux origines réellement nécessaires si l'API contient des données sensibles.",
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                )
            )

        return findings
