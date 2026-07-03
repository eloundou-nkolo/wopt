from wopt.checks.cookies import CookiesCheck


def test_secure_cookies_have_no_findings(secure_context):
    check = CookiesCheck()
    findings = check.run(secure_context)
    assert findings == []


def test_insecure_cookie_flags_all_issues(insecure_context):
    check = CookiesCheck()
    findings = check.run(insecure_context)
    ids = {f.check_id for f in findings}
    assert f"{check.id}.session_not_secure" in ids
    assert f"{check.id}.session_not_httponly" in ids
    assert f"{check.id}.session_samesite_weak" in ids
