"""
wopt.core.scanner

Orchestrateur principal : récupère les données de la cible,
exécute tous les checks enregistrés, agrège les résultats en
un ScanResult prêt à être scoré et formaté.
"""

from __future__ import annotations

import time

from wopt.checks import ALL_CHECKS, PROBE_CHECKS
from wopt.core.http_client import FetchError, fetch, probe_path
from wopt.models import Finding, ScanResult
from wopt.report.scoring import compute_score


def scan(url: str, timeout: float = 10.0, include_probes: bool = True) -> ScanResult:
    """Lance un scan complet sur `url` et retourne un ScanResult.

    Args:
        url: URL ou nom de domaine de la cible.
        timeout: timeout HTTP en secondes.
        include_probes: si True, teste aussi les chemins sensibles
            connus (requêtes HTTP additionnelles). Mettre à False
            pour un scan plus rapide/moins bruyant côté serveur cible.
    """
    start = time.perf_counter()
    findings: list[Finding] = []

    ctx = fetch(url, timeout=timeout)

    for check_cls in ALL_CHECKS:
        check = check_cls()
        findings.extend(check.run(ctx))

    if include_probes:
        for check_cls in PROBE_CHECKS:
            check = check_cls()
            for path, severity in check.paths_to_probe().items():
                status = probe_path(ctx.final_url, path, timeout=timeout)
                if status is not None and status < 400:
                    findings.append(check.build_finding(path, severity, status))

    duration_ms = (time.perf_counter() - start) * 1000
    result = ScanResult.build(target=ctx.final_url, findings=findings, duration_ms=duration_ms)
    result.score, result.score_value = compute_score(findings)
    return result
