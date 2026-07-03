from wopt.checks.headers import SecurityHeadersCheck


def test_secure_site_has_no_missing_header_findings(secure_context):
    check = SecurityHeadersCheck()
    findings = check.run(secure_context)
    missing_findings = [f for f in findings if "missing" in f.check_id]
    assert missing_findings == []


def test_insecure_site_flags_all_missing_headers(insecure_context):
    check = SecurityHeadersCheck()
    findings = check.run(insecure_context)
    missing_ids = {f.check_id for f in findings if "missing" in f.check_id}
    assert f"{check.id}.strict-transport-security_missing" in missing_ids
    assert f"{check.id}.content-security-policy_missing" in missing_ids


def test_stack_disclosure_detected(insecure_context):
    check = SecurityHeadersCheck()
    findings = check.run(insecure_context)
    disclosure = [f for f in findings if "stack_disclosure" in f.check_id]
    assert len(disclosure) == 1
    assert disclosure[0].evidence == "nginx/1.18.0"


def test_weak_csp_detected(secure_context):
    secure_context.response_headers["content-security-policy"] = "default-src *; script-src 'unsafe-inline'"
    check = SecurityHeadersCheck()
    findings = check.run(secure_context)
    weak = [f for f in findings if "csp_weak" in f.check_id]
    assert len(weak) == 1
