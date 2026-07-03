"""
wopt.checks.cookies

Vérifie que chaque cookie détecté sur la réponse HTTP est
correctement sécurisé : Secure, HttpOnly, SameSite.
"""

from __future__ import annotations

from wopt.checks.base import Check
from wopt.models import Finding, ScanContext, Severity


class CookiesCheck(Check):
    id = "cookies.flags"
    name = "Cookie Security Flags"
    category = "cookies"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        for cookie in ctx.cookies:
            if not cookie.secure:
                findings.append(
                    Finding(
                        check_id=f"{self.id}.{cookie.name}_not_secure",
                        title=f"Cookie '{cookie.name}' sans flag Secure",
                        severity=Severity.MEDIUM,
                        category=self.category,
                        description="Ce cookie peut être transmis en clair sur une connexion non chiffrée.",
                        recommendation=f"Ajouter le flag Secure au cookie '{cookie.name}'.",
                    )
                )
            if not cookie.http_only:
                findings.append(
                    Finding(
                        check_id=f"{self.id}.{cookie.name}_not_httponly",
                        title=f"Cookie '{cookie.name}' sans flag HttpOnly",
                        severity=Severity.MEDIUM,
                        category=self.category,
                        description="Ce cookie est accessible via JavaScript, ce qui facilite son vol en cas de XSS.",
                        recommendation=f"Ajouter le flag HttpOnly au cookie '{cookie.name}'.",
                    )
                )
            if not cookie.same_site or cookie.same_site.lower() == "none":
                findings.append(
                    Finding(
                        check_id=f"{self.id}.{cookie.name}_samesite_weak",
                        title=f"Cookie '{cookie.name}' avec SameSite absent ou 'None'",
                        severity=Severity.LOW,
                        category=self.category,
                        description="Ce cookie peut être envoyé lors de requêtes cross-site, augmentant le risque CSRF.",
                        recommendation=f"Définir 'SameSite=Lax' ou 'Strict' sur le cookie '{cookie.name}'.",
                        evidence=cookie.same_site or "absent",
                    )
                )

        return findings
