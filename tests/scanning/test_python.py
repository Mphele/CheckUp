import pytest

from checkup.models import Confidence, Severity
from checkup.scanning.python import (
    find_disabled_tls_verification,
    find_dynamic_code_execution,
    find_shell_invocations,
)


@pytest.mark.parametrize(
    "source",
    [
        "subprocess.run(command, shell=True)",
        "subprocess.Popen(command, shell=True)",
        "os.system(command)",
    ],
)
def test_finds_shell_invocations(source: str) -> None:
    findings = find_shell_invocations(source, "app/routes.py")

    assert len(findings) == 1
    assert findings[0].rule_id == "python.shell-injection"
    assert findings[0].severity is Severity.HIGH
    assert findings[0].confidence is Confidence.MEDIUM
    assert findings[0].location.path == "app/routes.py"
    assert findings[0].location.line == 1


def test_ignores_subprocess_call_without_shell() -> None:
    source = 'subprocess.run(["nslookup", host], shell=False)'

    assert find_shell_invocations(source, "app/routes.py") == []


def test_reports_the_call_line() -> None:
    source = "def lookup(command):\n    return os.system(command)\n"

    findings = find_shell_invocations(source, "app/routes.py")

    assert findings[0].location.line == 2
    assert findings[0].evidence == "return os.system(command)"


@pytest.mark.parametrize("function_name", ["eval", "exec", "builtins.eval"])
def test_finds_dynamic_code_execution(function_name: str) -> None:
    source = f"result = {function_name}(user_input)"

    findings = find_dynamic_code_execution(source, "app/calculator.py")

    assert len(findings) == 1
    assert findings[0].rule_id == "python.dynamic-code-execution"
    assert findings[0].severity is Severity.HIGH
    assert findings[0].location.line == 1


def test_ignores_literal_eval() -> None:
    source = "result = ast.literal_eval(user_input)"

    assert find_dynamic_code_execution(source, "app/calculator.py") == []


@pytest.mark.parametrize(
    "source",
    [
        'requests.get("https://example.com", verify=False)',
        "httpx.Client(verify=False)",
        "httpx.AsyncClient(verify=False)",
    ],
)
def test_finds_disabled_tls_verification(source: str) -> None:
    findings = find_disabled_tls_verification(source, "app/client.py")

    assert len(findings) == 1
    assert findings[0].rule_id == "python.disabled-tls-verification"
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].confidence is Confidence.HIGH


def test_ignores_enabled_tls_verification() -> None:
    source = 'requests.get("https://example.com", verify=True)'

    assert find_disabled_tls_verification(source, "app/client.py") == []
