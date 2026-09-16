from pathlib import Path

from checkup.models import Finding, RouteInfo, ScanError, ScanReport
from checkup.scanning.fastapi import find_fastapi_routes, find_request_input_flows
from checkup.scanning.files import discover_files
from checkup.scanning.python import (
    find_disabled_tls_verification,
    find_dynamic_code_execution,
    find_shell_invocations,
    find_unsafe_deserialization,
)
from checkup.scanning.secrets import find_exposed_secrets


def scan_project(project_root: Path) -> ScanReport:
    root = project_root.resolve(strict=True)
    project_files = discover_files(root)
    findings: list[Finding] = []
    routes: list[RouteInfo] = []
    errors: list[ScanError] = []
    files_analyzed = 0

    for project_file in project_files:
        try:
            source = project_file.path.read_text(encoding="utf-8")
            findings.extend(find_exposed_secrets(source, project_file.relative_path))
            if project_file.path.suffix.lower() == ".py":
                generic_findings = [
                    *find_shell_invocations(source, project_file.relative_path),
                    *find_dynamic_code_execution(source, project_file.relative_path),
                    *find_disabled_tls_verification(
                        source, project_file.relative_path
                    ),
                    *find_unsafe_deserialization(source, project_file.relative_path),
                ]
                contextual_findings = find_request_input_flows(
                    source, project_file.relative_path
                )
                findings.extend(
                    _prefer_contextual_findings(
                        generic_findings, contextual_findings
                    )
                )
                routes.extend(find_fastapi_routes(source, project_file.relative_path))
            files_analyzed += 1
        except UnicodeDecodeError:
            errors.append(
                ScanError(
                    path=project_file.relative_path,
                    message="The file is not valid UTF-8 text.",
                )
            )
        except SyntaxError as error:
            errors.append(
                ScanError(
                    path=project_file.relative_path,
                    message=f"Python syntax error on line {error.lineno or 1}.",
                )
            )
        except OSError:
            errors.append(
                ScanError(
                    path=project_file.relative_path,
                    message="The file could not be read.",
                )
            )

    return ScanReport(
        project_name=root.name,
        files_discovered=len(project_files),
        files_analyzed=files_analyzed,
        findings=findings,
        routes=routes,
        errors=errors,
    )


def _prefer_contextual_findings(
    generic_findings: list[Finding],
    contextual_findings: list[Finding],
) -> list[Finding]:
    replacements = {
        "fastapi.request-to-shell": "python.shell-injection",
        "fastapi.request-to-dynamic-code": "python.dynamic-code-execution",
    }
    replaced = {
        (
            finding.location.path,
            finding.location.line,
            replacements[finding.rule_id],
        )
        for finding in contextual_findings
        if finding.rule_id in replacements
    }
    remaining = [
        finding
        for finding in generic_findings
        if (finding.location.path, finding.location.line, finding.rule_id) not in replaced
    ]
    return [*remaining, *contextual_findings]
