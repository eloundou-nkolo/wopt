"""
wopt.checks.tls

Vérifie la configuration TLS/SSL : version du protocole négociée
et date d'expiration du certificat. Les informations TLS sont
collectées en amont (core/http_client.py) et transmises via
ScanContext.tls_info pour éviter une connexion TLS redondante.

ScanContext.tls_info attendu (dict) :
    {
        "protocol_version": "TLSv1.3",
        "not_after": "2026-09-01T00:00:00+00:00",  # ISO 8601
        "days_until_expiry": 60,
        "cipher": "TLS_AES_256_GCM_SHA384",
    }
"""

from __future__ import annotations

from wopt.checks.base import Check
from wopt.models import Finding, ScanContext, Severity

OUTDATED_PROTOCOLS = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"}


class TLSCheck(Check):
    id = "tls.configuration"
    name = "TLS Configuration"
    category = "tls"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        if not ctx.url.startswith("https://"):
            findings.append(
                Finding(
                    check_id=f"{self.id}.no_https",
                    title="Le site n'est pas servi en HTTPS",
                    severity=Severity.CRITICAL,
                    category=self.category,
                    description="La cible a été scannée en HTTP simple, sans chiffrement TLS.",
                    recommendation="Migrer le site vers HTTPS avec un certificat valide.",
                )
            )
            return findings

        if ctx.tls_info is None:
            findings.append(
                Finding(
                    check_id=f"{self.id}.info_unavailable",
                    title="Impossible de récupérer les informations TLS",
                    severity=Severity.INFO,
                    category=self.category,
                    description="La négociation TLS a échoué ou n'a pas pu être analysée.",
                    recommendation="Vérifier manuellement la configuration TLS du serveur.",
                )
            )
            return findings

        protocol = ctx.tls_info.get("protocol_version")
        if protocol in OUTDATED_PROTOCOLS:
            findings.append(
                Finding(
                    check_id=f"{self.id}.outdated_protocol",
                    title=f"Protocole TLS obsolète : {protocol}",
                    severity=Severity.HIGH,
                    category=self.category,
                    description=f"Le serveur accepte encore {protocol}, considéré comme non sûr.",
                    recommendation="Désactiver TLS < 1.2 et n'accepter que TLS 1.2 / 1.3.",
                    evidence=protocol,
                )
            )

        days_left = ctx.tls_info.get("days_until_expiry")
        if days_left is not None:
            if days_left < 0:
                findings.append(
                    Finding(
                        check_id=f"{self.id}.cert_expired",
                        title="Certificat TLS expiré",
                        severity=Severity.CRITICAL,
                        category=self.category,
                        description="Le certificat présenté par le serveur est expiré.",
                        recommendation="Renouveler le certificat TLS immédiatement.",
                    )
                )
            elif days_left < 14:
                findings.append(
                    Finding(
                        check_id=f"{self.id}.cert_expiring_soon",
                        title=f"Certificat TLS expire dans {days_left} jours",
                        severity=Severity.MEDIUM,
                        category=self.category,
                        description="Le certificat arrive bientôt à expiration.",
                        recommendation="Planifier le renouvellement du certificat.",
                        evidence=str(days_left),
                    )
                )

        return findings
