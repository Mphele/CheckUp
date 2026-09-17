from checkup.scanning.dependencies import is_requirements_file, parse_requirements


def test_parses_pinned_requirements() -> None:
    source = '''
FastAPI==0.115.13
uvicorn[standard] == 0.34.3 ; python_version >= "3.11"
requests==2.32.4  # HTTP client
'''

    dependencies = parse_requirements(source, "requirements.txt")

    assert [(item.name, item.version) for item in dependencies] == [
        ("fastapi", "0.115.13"),
        ("uvicorn", "0.34.3"),
        ("requests", "2.32.4"),
    ]
    assert dependencies[0].location.line == 2


def test_ignores_unpinned_and_included_requirements() -> None:
    source = '''
fastapi>=0.115
httpx
-r requirements/base.txt
'''

    assert parse_requirements(source, "requirements.txt") == []


def test_recognizes_requirements_file_names() -> None:
    assert is_requirements_file("requirements.txt")
    assert is_requirements_file("config/requirements-dev.txt")
    assert not is_requirements_file("notes.txt")
