from pathlib import Path

from fastapi.testclient import TestClient

from checkup.main import create_app


def test_health_endpoint_reports_ok() -> None:
    client = TestClient(create_app())

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_dashboard_is_served() -> None:
    client = TestClient(create_app())

    response = client.get("/")

    assert response.status_code == 200
    assert "Give your project a security check-up" in response.text
    assert 'id="results"' in response.text
    assert 'id="route-map"' in response.text
    assert 'id="severity-filter"' in response.text
    assert 'id="dependency-report"' in response.text
    assert 'id="export-report"' in response.text


def test_dashboard_javascript_is_served() -> None:
    client = TestClient(create_app())

    response = client.get("/static/app.js")

    assert response.status_code == 200
    assert 'fetch("/api/scans"' in response.text
    assert "Review access control" in response.text
    assert "finding.confidence" in response.text
    assert "dependency_check_performed" in response.text
    assert "JSON.stringify(currentReport" in response.text


def test_scan_endpoint_returns_findings(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        "subprocess.run(command, shell=True)", encoding="utf-8"
    )
    client = TestClient(create_app())

    response = client.post("/api/scans", json={"project_path": str(tmp_path)})

    assert response.status_code == 200
    report = response.json()
    assert report["project_name"] == tmp_path.name
    assert report["findings"][0]["rule_id"] == "python.shell-injection"
    assert report["routes"] == []
    assert report["dependencies"] == []
    assert report["dependency_vulnerabilities"] == []
    assert report["dependency_check_performed"] is False


def test_scan_endpoint_rejects_missing_directory(tmp_path: Path) -> None:
    client = TestClient(create_app())

    response = client.post(
        "/api/scans", json={"project_path": str(tmp_path / "missing")}
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Choose an existing project directory."
