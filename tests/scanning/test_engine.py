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
    assert report.files_analyzed == 2
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
