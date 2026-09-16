from pathlib import Path

from checkup.scanning.engine import scan_project


def test_scans_python_files_and_returns_a_project_report(tmp_path: Path) -> None:
    (tmp_path / "safe.py").write_text(
        'subprocess.run(["nslookup", host])', encoding="utf-8"
    )
    (tmp_path / "unsafe.py").write_text(
        "subprocess.run(command, shell=True)", encoding="utf-8"
    )
    (tmp_path / "pyproject.toml").write_text("[project]", encoding="utf-8")

    report = scan_project(tmp_path)

    assert report.project_name == tmp_path.name
    assert report.files_discovered == 3
    assert report.files_analyzed == 3
    assert len(report.findings) == 1
    assert report.findings[0].location.path == "unsafe.py"
    assert report.errors == []


def test_reports_python_files_that_cannot_be_parsed(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_text("def broken(", encoding="utf-8")

    report = scan_project(tmp_path)

    assert report.files_analyzed == 0
    assert report.findings == []
    assert len(report.errors) == 1
    assert report.errors[0].path == "broken.py"
    assert "syntax error" in report.errors[0].message.lower()


def test_scans_configuration_files_without_exposing_secret_values(
    tmp_path: Path,
) -> None:
    secret = "live-secret-value-123"
    (tmp_path / ".env").write_text(f"SECRET_KEY={secret}", encoding="utf-8")

    report = scan_project(tmp_path)

    assert report.files_analyzed == 1
    assert report.findings[0].rule_id == "secrets.hardcoded-credential"
    assert secret not in report.model_dump_json()


def test_includes_fastapi_routes_in_project_report(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        '''
@router.get("/account")
def get_account(user = Depends(get_current_user)):
    return user
''',
        encoding="utf-8",
    )

    report = scan_project(tmp_path)

    assert len(report.routes) == 1
    assert report.routes[0].path == "/account"
    assert report.routes[0].security_dependencies == ["get_current_user"]


def test_includes_dynamic_execution_findings(tmp_path: Path) -> None:
    (tmp_path / "calculator.py").write_text("result = eval(expression)", encoding="utf-8")

    report = scan_project(tmp_path)

    assert [finding.rule_id for finding in report.findings] == [
        "python.dynamic-code-execution"
    ]
