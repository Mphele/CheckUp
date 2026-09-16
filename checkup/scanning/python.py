import ast

from checkup.models import Confidence, Finding, Severity, SourceLocation


SHELL_FUNCTIONS = {
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
    "subprocess.run",
}
DYNAMIC_EXECUTION_FUNCTIONS = {"builtins.eval", "builtins.exec", "eval", "exec"}
HTTP_FUNCTIONS = {
    "requests.delete",
    "requests.get",
    "requests.head",
    "requests.options",
    "requests.patch",
    "requests.post",
    "requests.put",
    "requests.request",
}
HTTP_CLIENTS = {"httpx.AsyncClient", "httpx.Client", "requests.Session"}


def find_shell_invocations(source: str, relative_path: str) -> list[Finding]:
    tree = ast.parse(source, filename=relative_path)
    lines = source.splitlines()
    findings: list[Finding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _invokes_shell(node):
            continue

        evidence = lines[node.lineno - 1].strip()[:200]
        findings.append(
            Finding(
                rule_id="python.shell-injection",
                title="Shell command may allow command injection",
                description=(
                    "This call invokes a system shell. If any part of the command comes "
                    "from a user, the user may be able to execute additional commands."
                ),
                category="injection",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                location=SourceLocation(path=relative_path, line=node.lineno),
                evidence=evidence,
                remediation=(
                    "Pass the program and its arguments as a list without using a shell, "
                    "and validate any user-controlled values."
                ),
            )
        )

    return findings


def find_dynamic_code_execution(source: str, relative_path: str) -> list[Finding]:
    tree = ast.parse(source, filename=relative_path)
    lines = source.splitlines()
    findings: list[Finding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _qualified_name(node.func) not in DYNAMIC_EXECUTION_FUNCTIONS:
            continue

        findings.append(
            Finding(
                rule_id="python.dynamic-code-execution",
                title="Dynamic code execution may run untrusted input",
                description=(
                    "This function interprets a string as Python code. If that string "
                    "can be influenced by a user, arbitrary code may run with the "
                    "application's permissions."
                ),
                category="injection",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                location=SourceLocation(path=relative_path, line=node.lineno),
                evidence=lines[node.lineno - 1].strip()[:200],
                remediation=(
                    "Replace dynamic execution with explicit parsing or a restricted "
                    "operation designed for the expected input format."
                ),
            )
        )

    return findings


def find_disabled_tls_verification(source: str, relative_path: str) -> list[Finding]:
    tree = ast.parse(source, filename=relative_path)
    lines = source.splitlines()
    findings: list[Finding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function_name = _qualified_name(node.func)
        if function_name not in HTTP_FUNCTIONS | HTTP_CLIENTS:
            continue
        if not _has_false_keyword(node, "verify"):
            continue

        findings.append(
            Finding(
                rule_id="python.disabled-tls-verification",
                title="TLS certificate verification is disabled",
                description=(
                    "This request accepts certificates that cannot be verified. An attacker "
                    "on the network may be able to intercept or alter the connection."
                ),
                category="transport-security",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                location=SourceLocation(path=relative_path, line=node.lineno),
                evidence=lines[node.lineno - 1].strip()[:200],
                remediation=(
                    "Enable certificate verification. For a private certificate authority, "
                    "provide its trusted CA bundle instead of using verify=False."
                ),
            )
        )

    return findings


def _invokes_shell(call: ast.Call) -> bool:
    function_name = _qualified_name(call.func)
    if function_name == "os.system":
        return True
    if function_name not in SHELL_FUNCTIONS:
        return False

    return any(
        keyword.arg == "shell"
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is True
        for keyword in call.keywords
    )


def _qualified_name(node: ast.expr) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _has_false_keyword(call: ast.Call, keyword_name: str) -> bool:
    return any(
        keyword.arg == keyword_name
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is False
        for keyword in call.keywords
    )
