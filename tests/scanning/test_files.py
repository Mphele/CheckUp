from pathlib import Path

import pytest

from checkup.scanning.files import discover_files


def test_discovers_supported_project_files(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "main.py").write_text("print('hello')", encoding="utf-8")
    (tmp_path / ".env.local").write_text("TOKEN=test", encoding="utf-8")
    (tmp_path / "logo.png").write_bytes(b"not source code")
    (tmp_path / "signing.pem").write_text(
        "-----BEGIN PRIVATE KEY-----", encoding="utf-8"
    )
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "ignored.py").write_text("pass", encoding="utf-8")

    files = discover_files(tmp_path)

    assert [file.relative_path for file in files] == [
        ".env.local",
        "signing.pem",
        "app/main.py",
    ]


def test_skips_files_over_the_size_limit(tmp_path: Path) -> None:
    (tmp_path / "large.py").write_text("12345", encoding="utf-8")

    assert discover_files(tmp_path, max_file_size=4) == []


def test_rejects_a_file_as_project_root(tmp_path: Path) -> None:
    file_path = tmp_path / "main.py"
    file_path.touch()

    with pytest.raises(NotADirectoryError):
        discover_files(file_path)
