from pathlib import Path

from checkup.scanning.engine import scan_project


DEMO_PROJECT = Path(__file__).parents[1] / "examples" / "vulnerable_api"
SECURE_PROJECT = Path(__file__).parents[1] / "examples" / "secure_api"


def test_vulnerable_demo_exercises_current_security_checks() -> None:
    report = scan_project(
        DEMO_PROJECT,
        vulnerability_lookup=lambda dependencies: [],
    )

    rule_ids = {finding.rule_id for finding in report.findings}
    assert {
        "fastapi.request-to-dynamic-code",
        "fastapi.request-to-file-path",
        "fastapi.request-to-shell",
        "fastapi.request-to-sql-query",
        "python.disabled-tls-verification",
        "python.unsafe-pickle",
        "secrets.hardcoded-credential",
    } <= rule_ids
    assert len(report.routes) == 6
    assert len(report.dependencies) == 2
    assert report.errors == []


def test_corrected_demo_has_no_supported_findings() -> None:
    report = scan_project(
        SECURE_PROJECT,
        vulnerability_lookup=lambda dependencies: [],
    )

    assert report.findings == []
    assert len(report.routes) == 6
    assert len(report.dependencies) == 2
    assert report.errors == []
