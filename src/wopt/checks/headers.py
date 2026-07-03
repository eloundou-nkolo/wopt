"""
wopt.checks.headers

Vérifie la présence et la qualité des en-têtes de sécurité HTTP.
C'est la faille la plus documentée dans les études sur le code
généré par IA : la quasi-totalité des applications vibe-codées
en sont dépourvues.
"""

from __future__ import annotations

from wopt.checks.base import Check
from wopt.models import Finding, ScanContext, Severity

SECURITY_HEADERS = {
    "strict-transport-security": {
        "severity": Severity.HIGH,
        "title": "HSTS absent",
        "description": "Le header Strict-Transport-Security est absent : le navigateur "
        "peut être redirigé vers une version HTTP non chiffrée du site.",
        "recommendation": "Ajouter 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
    },
    "content-security-policy": {
        "severity": Severity.HIGH,
        "title": "CSP absent",
        "description": "Aucune Content-Security-Policy définie : la page est plus "
        "vulnérable aux attaques XSS et à l'injection de contenu tiers.",
        "recommendation": "Définir une Content-Security-Policy restrictive adaptée à l'application.",
    },
    "x-frame-options": {
        "severity": Severity.MEDIUM,
        "title": "X-Frame-Options absent",
        "description": "Le site peut être intégré dans une iframe tierce, exposant "
        "les utilisateurs à des attaques de clickjacking.",
        "recommendation": "Ajouter 'X-Frame-Options: DENY' ou utiliser 'frame-ancestors' en CSP.",
    },
    "x-content-type-options": {
        "severity": Severity.LOW,
        "title": "X-Content-Type-Options absent",
        "description": "Le navigateur peut tenter de deviner le type MIME des ressources, "
        "ce qui ouvre la porte à des attaques par confusion de type.",
        "recommendation": "Ajouter 'X-Content-Type-Options: nosniff'.",
    },
    "referrer-policy": {
        "severity": Severity.LOW,
        "title": "Referrer-Policy absent",
        "description": "Sans Referrer-Policy, l'URL complète peut fuiter vers des sites tiers "
        "via l'en-tête Referer.",
        "recommendation": "Ajouter 'Referrer-Policy: strict-origin-when-cross-origin'.",
    },
    "permissions-policy": {
        "severity": Severity.INFO,
        "title": "Permissions-Policy absent",
        "description": "Aucune restriction explicite sur les APIs navigateur sensibles "
        "(caméra, micro, géolocalisation).",
        "recommendation": "Ajouter 'Permissions-Policy' pour désactiver les APIs non utilisées.",
    },
}


class SecurityHeadersCheck(Check):
    id = "headers.security_headers"
    name = "Security Headers"
    category = "headers"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        headers_lower = {k.lower(): v for k, v in ctx.response_headers.items()}

        for header_name, rule in SECURITY_HEADERS.items():
            if header_name not in headers_lower:
                findings.append(
                    Finding(
                        check_id=f"{self.id}.{header_name}_missing",
                        title=rule["title"],
                        severity=rule["severity"],
                        category=self.category,
                        description=rule["description"],
                        recommendation=rule["recommendation"],
                    )
                )

        # Vérification qualitative de la CSP, pas juste présence/absence
        csp = headers_lower.get("content-security-policy")
        if csp:
            weak_tokens = [t for t in ("'unsafe-inline'", "'unsafe-eval'", "*") if t in csp]
            if weak_tokens:
                findings.append(
                    Finding(
                        check_id=f"{self.id}.csp_weak",
                        title="CSP affaiblie détectée",
                        severity=Severity.MEDIUM,
                        category=self.category,
                        description=(
                            "La Content-Security-Policy contient des directives permissives "
                            f"({', '.join(weak_tokens)}) qui réduisent sa protection contre le XSS."
                        ),
                        recommendation="Retirer 'unsafe-inline'/'unsafe-eval'/'*' et utiliser des nonces ou hashes.",
                        evidence=csp,
                    )
                )

        # Exposition de la stack technique
        for leaky_header in ("server", "x-powered-by"):
            if leaky_header in headers_lower and headers_lower[leaky_header]:
                findings.append(
                    Finding(
                        check_id=f"{self.id}.stack_disclosure_{leaky_header}",
                        title=f"Divulgation de stack via '{leaky_header}'",
                        severity=Severity.INFO,
                        category=self.category,
                        description=f"Le header '{leaky_header}' révèle des informations sur la stack technique.",
                        recommendation=f"Masquer ou supprimer le header '{leaky_header}' côté serveur.",
                        evidence=headers_lower[leaky_header],
                    )
                )

        return findings
