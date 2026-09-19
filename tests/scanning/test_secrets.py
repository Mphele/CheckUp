from checkup.models import Confidence, Severity
from checkup.scanning.secrets import find_exposed_secrets


def test_finds_and_redacts_a_hardcoded_credential() -> None:
    secret = "live-value-123456"

    findings = find_exposed_secrets(f'API_KEY = "{secret}"', "settings.py")

    assert len(findings) == 1
    assert findings[0].rule_id == "secrets.hardcoded-credential"
    assert findings[0].severity is Severity.HIGH
    assert secret not in findings[0].evidence
    assert findings[0].evidence == "API_KEY=<redacted>"


def test_ignores_documentation_placeholder() -> None:
    source = "API_KEY=your-api-key"

    assert find_exposed_secrets(source, ".env.example") == []


def test_ignores_environment_variable_lookup() -> None:
    source = 'PASSWORD = os.getenv("DATABASE_PASSWORD")'

    assert find_exposed_secrets(source, "settings.py") == []


def test_finds_private_key_without_copying_it_to_evidence() -> None:
    source = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        + "A" * 512
        + "\n-----END RSA PRIVATE KEY-----"
    )

    findings = find_exposed_secrets(source, "deploy.pem")

    assert len(findings) == 1
    assert findings[0].rule_id == "secrets.private-key"
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].confidence is Confidence.HIGH
    assert "RSA" not in findings[0].evidence


def test_downgrades_an_obvious_example_private_key() -> None:
    source = """-----BEGIN PRIVATE KEY-----
YOUR_PRIVATE_KEY_HERE
-----END PRIVATE KEY-----"""

    findings = find_exposed_secrets(source, "google-credentials-example.json")

    assert len(findings) == 1
    assert findings[0].rule_id == "secrets.private-key-placeholder"
    assert findings[0].severity is Severity.LOW
    assert "YOUR_PRIVATE_KEY_HERE" not in findings[0].evidence
