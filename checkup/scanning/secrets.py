import re

from checkup.models import Confidence, Finding, Severity, SourceLocation


SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|password)\b"
    r"\s*[:=]\s*[\"']?([^\"'\s#;,]{8,})"
)
PRIVATE_KEY_MARKER = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----")
PLACEHOLDER_VALUES = {
    "changeme",
    "example",
    "not-a-secret",
    "placeholder",
    "replace-me",
    "your-api-key",
    "your-secret-here",
}


def find_exposed_secrets(source: str, relative_path: str) -> list[Finding]:
    findings: list[Finding] = []

    for line_number, line in enumerate(source.splitlines(), start=1):
        private_key = PRIVATE_KEY_MARKER.search(line)
        if private_key:
            findings.append(_private_key_finding(relative_path, line_number))

        for match in SECRET_ASSIGNMENT.finditer(line):
            name, value = match.groups()
            if _is_placeholder(value):
                continue
            findings.append(
                Finding(
                    rule_id="secrets.hardcoded-credential",
                    title="Possible credential stored in source code",
                    description=(
                        "A variable with a security-sensitive name contains a literal "
                        "value. Committed credentials can be copied from repository history."
                    ),
                    category="secrets",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    location=SourceLocation(path=relative_path, line=line_number),
                    evidence=f"{name}=<redacted>",
                    remediation=(
                        "Move the value to an environment variable. If it has been committed, "
                        "revoke or rotate the credential as well."
                    ),
                )
            )

    return findings


def _is_placeholder(value: str) -> bool:
    normalized = value.lower().strip()
    return (
        normalized in PLACEHOLDER_VALUES
        or normalized.startswith(("example-", "test-", "dummy-"))
        or normalized.startswith(("${", "environ.", "os.getenv(", "settings."))
        or set(normalized) <= {"x", "-", "_"}
    )


def _private_key_finding(relative_path: str, line_number: int) -> Finding:
    return Finding(
        rule_id="secrets.private-key",
        title="Private key stored in the project",
        description=(
            "Private key material appears in a project file. Anyone with access to the "
            "repository may be able to impersonate its owner."
        ),
        category="secrets",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        location=SourceLocation(path=relative_path, line=line_number),
        evidence="-----BEGIN <redacted> PRIVATE KEY-----",
        remediation=(
            "Remove the key from the project and revoke or replace it. Store the new key "
            "outside the repository."
        ),
    )
