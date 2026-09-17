import httpx
import pytest

from checkup.models import Dependency, SourceLocation
from checkup.scanning.osv import VulnerabilityServiceError, query_vulnerabilities


def test_queries_exact_pypi_versions_and_maps_advisories() -> None:
    dependency = Dependency(
        name="example-package",
        version="1.2.3",
        location=SourceLocation(path="requirements.txt", line=4),
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/querybatch"
        assert request.read().decode() == (
            '{"queries":[{"package":{"ecosystem":"PyPI",'
            '"name":"example-package"},"version":"1.2.3"}]}'
        )
        return httpx.Response(
            200,
            json={"results": [{"vulns": [{"id": "GHSA-abcd-1234-5678"}]}]},
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        vulnerabilities = query_vulnerabilities([dependency], client=client)

    assert len(vulnerabilities) == 1
    assert vulnerabilities[0].advisory_id == "GHSA-abcd-1234-5678"
    assert vulnerabilities[0].package == "example-package"
    assert vulnerabilities[0].location.line == 4


def test_returns_empty_result_without_a_network_request() -> None:
    assert query_vulnerabilities([]) == []


def test_wraps_network_failures() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=request)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(VulnerabilityServiceError):
            query_vulnerabilities(
                [
                    Dependency(
                        name="example",
                        version="1.0",
                        location=SourceLocation(path="requirements.txt", line=1),
                    )
                ],
                client=client,
            )
