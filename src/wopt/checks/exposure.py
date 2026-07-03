"""
wopt.checks.exposure

Vérifie passivement si des chemins sensibles connus répondent
avec un statut 200 (fichier accessible). Aucune tentative de
lecture/exploitation du contenu au-delà de la détection : on
observe uniquement le code de statut HTTP renvoyé.

Ce check nécessite des requêtes HTTP additionnelles, effectuées
par le scanner (pas par ScanContext initial) via check.probe_paths().
"""

from __future__ import annotations

from wopt.checks.base import Check
from wopt.models import Finding, ScanContext, Severity

SENSITIVE_PATHS = {
    "/.env": Severity.CRITICAL,
    "/.git/HEAD": Severity.HIGH,
    "/.git/config": Severity.HIGH,
    "/wp-config.php.bak": Severity.CRITICAL,
    "/config.php.bak": Severity.CRITICAL,
    "/.DS_Store": Severity.LOW,
    "/backup.zip": Severity.MEDIUM,
    "/.aws/credentials": Severity.CRITICAL,
}


class ExposurePathsCheck(Check):
    """Ce check est particulier : il a besoin de requêtes HTTP
    supplémentaires (une par chemin testé). Le scanner l'invoque
    via `probe_paths()` plutôt que `run()` classique -- voir
    core/scanner.py pour l'intégration."""

    id = "exposure.sensitive_paths"
    name = "Sensitive Paths Exposure"
    category = "exposure"

    def paths_to_probe(self) -> dict[str, Severity]:
        return SENSITIVE_PATHS

    def build_finding(self, path: str, severity: Severity, status_code: int) -> Finding:
        return Finding(
            check_id=f"{self.id}.{path.strip('/').replace('/', '_').replace('.', '_')}",
            title=f"Chemin sensible potentiellement exposé : {path}",
            severity=severity,
            category=self.category,
            description=(
                f"La requête vers '{path}' a retourné un statut {status_code}, "
                "suggérant que ce fichier pourrait être accessible publiquement."
            ),
            recommendation=f"Vérifier manuellement '{path}' et bloquer son accès public si confirmé.",
            evidence=f"HTTP {status_code}",
        )

    def run(self, ctx: ScanContext) -> list[Finding]:
        # Ce check ne fait rien via run() seul -- voir probe_paths()
        # dans le scanner qui gère les requêtes réseau réelles.
        return []
