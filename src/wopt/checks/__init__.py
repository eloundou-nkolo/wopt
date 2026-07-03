"""
wopt.checks

Registre central des checks disponibles. Pour ajouter un nouveau
check : créer la classe dans un module de ce package, puis
l'ajouter à ALL_CHECKS. Le scanner n'a rien d'autre à connaître.
"""

from wopt.checks.cookies import CookiesCheck
from wopt.checks.cors import CORSCheck
from wopt.checks.exposure import ExposurePathsCheck
from wopt.checks.headers import SecurityHeadersCheck
from wopt.checks.tls import TLSCheck

# Checks "standards" exécutés directement sur le ScanContext
ALL_CHECKS = [
    SecurityHeadersCheck,
    TLSCheck,
    CookiesCheck,
    CORSCheck,
]

# Checks nécessitant des requêtes HTTP additionnelles (probing actif)
PROBE_CHECKS = [
    ExposurePathsCheck,
]

__all__ = [
    "ALL_CHECKS",
    "PROBE_CHECKS",
    "SecurityHeadersCheck",
    "TLSCheck",
    "CookiesCheck",
    "CORSCheck",
    "ExposurePathsCheck",
]
