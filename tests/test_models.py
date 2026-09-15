import pytest
from pydantic import ValidationError

from checkup.models import Confidence, Finding, Severity, SourceLocation


def test_finding_serializes_as_plain_report_data() -> None:
    finding = Finding(
        rule_id="python.shell-injection",
        title="Shell command uses untrusted input",
        description="Request data reaches a shell command.",
        category="injection",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        location=SourceLocation(path="app/routes.py", line=12),
        evidence="subprocess.run(command, shell=True)",
        remediation="Pass command arguments without invoking a shell.",
    )

    report_data = finding.model_dump(mode="json")

    assert report_data["severity"] == "high"
    assert report_data["location"] == {"path": "app/routes.py", "line": 12}


def test_source_location_rejects_invalid_line_number() -> None:
    with pytest.raises(ValidationError):
        SourceLocation(path="app/routes.py", line=0)
