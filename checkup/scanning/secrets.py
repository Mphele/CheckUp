import re

from checkup.models import Confidence, Finding, Severity, SourceLocation


SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|password)\b"
    r"\s*[:=]\s*[\"']?([^\"'\s#;,]{8,})"
)
PRIVATE_KEY_MARKER = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----")
PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----\s*(.*?)\s*"
    r"-----END (?:[A-Z0-9]+ )?PRIVATE KEY-----",
    re.DOTALL,
)
PRIVATE_KEY_PLACEHOLDER = re.compile(
    r"(?i)(?:placeholder|example|dummy|fake|replace|your[_ -]?private[_ -]?key|<[^>]+>)"
)
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
    placeholder_key_lines = _placeholder_private_key_lines(source, relative_path)

    for line_number, line in enumerate(source.splitlines(), start=1):
        private_key = PRIVATE_KEY_MARKER.search(line)
        if private_key:
            findings.append(
                _private_key_finding(
                    relative_path,
                    line_number,
                    is_placeholder=line_number in placeholder_key_lines,
                )
            )

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


def _placeholder_private_key_lines(source: str, relative_path: str) -> set[int]:
    example_file = any(
        word in relative_path.lower() for word in ("example", "sample", "template")
    )
    placeholder_lines: set[int] = set()
    for match in PRIVATE_KEY_BLOCK.finditer(source):
        body = match.group(1).strip()
        compact_body = re.sub(r"\s+", "", body)
        if PRIVATE_KEY_PLACEHOLDER.search(body) or (
            example_file and len(compact_body) < 256
        ):
            placeholder_lines.add(source.count("\n", 0, match.start()) + 1)
    return placeholder_lines


def _private_key_finding(
    relative_path: str, line_number: int, *, is_placeholder: bool
) -> Finding:
    if is_placeholder:
        return Finding(
            rule_id="secrets.private-key-placeholder",
            title="Private key placeholder resembles a real key",
            description=(
                "This example contains a PEM-style private-key block, but its short or "
                "explicitly labelled contents indicate placeholder data rather than a "
                "usable key."
            ),
            category="secrets",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            location=SourceLocation(path=relative_path, line=line_number),
            evidence="-----BEGIN <placeholder> PRIVATE KEY-----",
            remediation=(
                "Use a plain value such as YOUR_PRIVATE_KEY_HERE instead of a "
                "PEM-style block."
            ),
        )

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
