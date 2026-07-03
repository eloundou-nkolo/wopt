from wopt.checks.tls import TLSCheck
from wopt.models import Severity


def test_secure_tls_has_no_findings(secure_context):
    check = TLSCheck()
    findings = check.run(secure_context)
    assert findings == []


def test_outdated_protocol_detected(insecure_context):
    check = TLSCheck()
    findings = check.run(insecure_context)
    protocol_findings = [f for f in findings if "outdated_protocol" in f.check_id]
    assert len(protocol_findings) == 1
    assert protocol_findings[0].severity == Severity.HIGH


def test_cert_expiring_soon_detected(insecure_context):
    check = TLSCheck()
    findings = check.run(insecure_context)
    expiry_findings = [f for f in findings if "cert_expiring_soon" in f.check_id]
    assert len(expiry_findings) == 1


def test_no_https_is_critical(secure_context):
    secure_context.url = "http://exemple.com"
    check = TLSCheck()
    findings = check.run(secure_context)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
