import pytest

from wopt.models import Cookie, ScanContext


@pytest.fixture
def secure_context() -> ScanContext:
    """Un contexte de scan simulant un site bien configuré."""
    return ScanContext(
        url="https://exemple.com",
        final_url="https://exemple.com",
        status_code=200,
        response_headers={
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "geolocation=()",
        },
        response_body="<html></html>",
        cookies=[Cookie(name="session", secure=True, http_only=True, same_site="Strict")],
        tls_info={
            "protocol_version": "TLSv1.3",
            "not_after": None,
            "days_until_expiry": 120,
            "cipher": "TLS_AES_256_GCM_SHA384",
        },
    )


@pytest.fixture
def insecure_context() -> ScanContext:
    """Un contexte de scan simulant un site mal configuré (cas vibe-codé typique)."""
    return ScanContext(
        url="https://exemple.com",
        final_url="https://exemple.com",
        status_code=200,
        response_headers={
            "server": "nginx/1.18.0",
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        },
        response_body="<html></html>",
        cookies=[Cookie(name="session", secure=False, http_only=False, same_site=None)],
        tls_info={
            "protocol_version": "TLSv1.1",
            "not_after": None,
            "days_until_expiry": 5,
            "cipher": None,
        },
    )
