"""
wopt.checks.base

Contrat que tout check de sécurité doit respecter.
Chaque nouveau check hérite de Check et implémente run().
Le scanner orchestrateur n'a besoin de rien connaître de la
logique interne de chaque check : il les découvre et les exécute
tous de la même façon.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from wopt.models import Finding, ScanContext


class Check(ABC):
    """Classe abstraite : tout check de sécurité l'implémente."""

    id: str = "base.check"
    name: str = "Base Check"
    category: str = "general"  # headers | tls | cookies | cors | exposure

    @abstractmethod
    def run(self, ctx: ScanContext) -> list[Finding]:
        """Exécute la vérification et retourne une liste de Finding.
        Une liste vide = rien à signaler (tout est conforme)."""
        raise NotImplementedError
