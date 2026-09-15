from pathlib import Path

from checkup.models import Finding, ScanError, ScanReport
from checkup.scanning.files import discover_files
from checkup.scanning.python import find_shell_invocations


def scan_project(project_root: Path) -> ScanReport:
    root = project_root.resolve(strict=True)
    project_files = discover_files(root)
    findings: list[Finding] = []
    errors: list[ScanError] = []
    files_analyzed = 0

    for project_file in project_files:
        if project_file.path.suffix.lower() != ".py":
            continue

        try:
            source = project_file.path.read_text(encoding="utf-8")
            findings.extend(
                find_shell_invocations(source, project_file.relative_path)
            )
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
        errors=errors,
    )

