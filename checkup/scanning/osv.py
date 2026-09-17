from urllib.parse import quote

import httpx

from checkup.models import Dependency, DependencyVulnerability


OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


class VulnerabilityServiceError(RuntimeError):
    pass


def query_vulnerabilities(
    dependencies: list[Dependency],
    *,
    client: httpx.Client | None = None,
) -> list[DependencyVulnerability]:
    if not dependencies:
        return []

    owns_client = client is None
    http_client = client or httpx.Client(timeout=10.0)
    try:
        response = http_client.post(
            OSV_BATCH_URL,
            json={
                "queries": [
                    {
                        "package": {"ecosystem": "PyPI", "name": dependency.name},
                        "version": dependency.version,
                    }
                    for dependency in dependencies
                ]
            },
        )
        response.raise_for_status()
        results = response.json().get("results")
        if not isinstance(results, list) or len(results) != len(dependencies):
            raise VulnerabilityServiceError("OSV returned an unexpected response.")

        vulnerabilities: list[DependencyVulnerability] = []
        for dependency, result in zip(dependencies, results, strict=True):
            for vulnerability in result.get("vulns", []):
                advisory_id = vulnerability.get("id")
                if not advisory_id:
                    continue
                vulnerabilities.append(
                    DependencyVulnerability(
                        advisory_id=advisory_id,
                        package=dependency.name,
                        version=dependency.version,
                        advisory_url=f"https://osv.dev/vulnerability/{quote(advisory_id)}",
                        location=dependency.location,
                    )
                )
        return vulnerabilities
    except (httpx.HTTPError, ValueError, TypeError) as error:
        raise VulnerabilityServiceError(
            "The vulnerability database could not be reached."
        ) from error
    finally:
        if owns_client:
            http_client.close()

