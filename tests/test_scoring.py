from wopt.models import Finding, Severity
from wopt.report.scoring import compute_score


def _finding(severity: Severity) -> Finding:
    return Finding(
        check_id="test.check",
        title="Test",
        severity=severity,
        category="test",
        description="desc",
        recommendation="reco",
    )


def test_no_findings_gives_perfect_score():
    letter, value = compute_score([])
    assert letter == "A"
    assert value == 100


def test_critical_finding_drops_score_significantly():
    letter, value = compute_score([_finding(Severity.CRITICAL)])
    assert value == 75
    assert letter == "B"


def test_multiple_criticals_can_reach_f():
    findings = [_finding(Severity.CRITICAL) for _ in range(5)]
    letter, value = compute_score(findings)
    assert value == 0
    assert letter == "F"


def test_info_findings_do_not_affect_score():
    letter, value = compute_score([_finding(Severity.INFO)])
    assert value == 100
    assert letter == "A"
