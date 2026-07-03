"""
wopt.report.json_output

Sérialise un ScanResult en JSON, pensé pour être consommé par
un pipeline CI/CD ou un autre outil (parsing facile, structure stable).
"""

from __future__ import annotations

import json

from wopt.models import ScanResult


def to_dict(result: ScanResult) -> dict:
    return {
        "target": result.target,
        "scanned_at": result.scanned_at.isoformat(),
        "duration_ms": round(result.duration_ms, 2),
        "score": result.score,
        "score_value": result.score_value,
        "summary": result.count_by_severity(),
        "findings": [
            {
                "check_id": f.check_id,
                "title": f.title,
                "severity": f.severity.value,
                "category": f.category,
                "description": f.description,
                "recommendation": f.recommendation,
                "evidence": f.evidence,
            }
            for f in result.findings
        ],
    }


def to_json(result: ScanResult, indent: int = 2) -> str:
    return json.dumps(to_dict(result), indent=indent, ensure_ascii=False)
