from wopt.checks.cors import CORSCheck
from wopt.models import Severity


def test_no_cors_headers_no_findings(secure_context):
    check = CORSCheck()
    findings = check.run(secure_context)
    assert findings == []


def test_wildcard_with_credentials_is_critical(insecure_context):
    check = CORSCheck()
    findings = check.run(insecure_context)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert "wildcard_with_credentials" in findings[0].check_id


def test_wildcard_alone_is_low(secure_context):
    secure_context.response_headers["access-control-allow-origin"] = "*"
    check = CORSCheck()
    findings = check.run(secure_context)
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
