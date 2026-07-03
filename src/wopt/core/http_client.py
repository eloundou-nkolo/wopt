"""
wopt.core.http_client

Encapsule les requêtes HTTP nécessaires au scan : une requête
principale vers la cible, plus les informations TLS et cookies
extraites de la même connexion pour limiter le nombre de
requêtes effectuées.
"""

from __future__ import annotations

import ssl
import time
from datetime import datetime, timezone

import httpx

from wopt.models import Cookie, ScanContext

DEFAULT_TIMEOUT = 10.0
DEFAULT_HEADERS = {
    "User-Agent": "wopt/0.1 (+https://github.com/eloundou-nkolo/wopt) security-audit-tool",
}


class FetchError(Exception):
    """Levée quand la cible ne peut pas être contactée."""


def _normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url


def _extract_tls_info(url: str, timeout: float) -> dict | None:
    """Récupère la version du protocole TLS et la date d'expiration
    du certificat via une connexion SSL directe (indépendante de httpx,
    qui n'expose pas facilement ces détails bas niveau)."""
    if not url.startswith("https://"):
        return None

    hostname = url.split("://", 1)[1].split("/", 1)[0].split(":")[0]

    try:
        import socket

        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol_version = ssock.version()
                cipher = ssock.cipher()

        not_after_str = cert.get("notAfter") if cert else None
        days_until_expiry = None
        if not_after_str:
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            days_until_expiry = (not_after - datetime.now(timezone.utc)).days

        return {
            "protocol_version": protocol_version,
            "not_after": not_after_str,
            "days_until_expiry": days_until_expiry,
            "cipher": cipher[0] if cipher else None,
        }
    except Exception:
        # On ne bloque jamais le scan pour une erreur d'introspection TLS :
        # le check TLS gérera lui-même le cas tls_info=None.
        return None


def _parse_cookies(response: httpx.Response) -> list[Cookie]:
    cookies = []
    for header_value in response.headers.get_list("set-cookie"):
        parts = [p.strip() for p in header_value.split(";")]
        name = parts[0].split("=", 1)[0] if parts else "unknown"
        lower_parts = [p.lower() for p in parts]

        same_site = None
        for p in parts:
            if p.lower().startswith("samesite="):
                same_site = p.split("=", 1)[1]

        cookies.append(
            Cookie(
                name=name,
                secure="secure" in lower_parts,
                http_only="httponly" in lower_parts,
                same_site=same_site,
            )
        )
    return cookies


def fetch(url: str, timeout: float = DEFAULT_TIMEOUT) -> ScanContext:
    """Effectue la requête principale vers la cible et construit
    le ScanContext utilisé par tous les checks standards."""
    url = _normalize_url(url)
    start = time.perf_counter()

    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers=DEFAULT_HEADERS,
            verify=True,
        ) as client:
            response = client.get(url)
    except httpx.RequestError as exc:
        raise FetchError(f"Impossible de contacter '{url}' : {exc}") from exc

    elapsed_ms = (time.perf_counter() - start) * 1000
    tls_info = _extract_tls_info(str(response.url), timeout)

    return ScanContext(
        url=url,
        final_url=str(response.url),
        status_code=response.status_code,
        response_headers=dict(response.headers),
        response_body=response.text,
        cookies=_parse_cookies(response),
        tls_info=tls_info,
        elapsed_ms=elapsed_ms,
    )


def probe_path(base_url: str, path: str, timeout: float = DEFAULT_TIMEOUT) -> int | None:
    """Requête légère pour vérifier si un chemin spécifique répond.
    Retourne le status_code, ou None si la requête échoue."""
    target = base_url.rstrip("/") + path
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False, headers=DEFAULT_HEADERS) as client:
            response = client.get(target)
            return response.status_code
    except httpx.RequestError:
        return None
