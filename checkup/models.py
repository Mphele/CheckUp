from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SourceLocation(BaseModel):
    path: str
    line: int = Field(ge=1)


class Finding(BaseModel):
    rule_id: str
    title: str
    description: str
    category: str
    severity: Severity
    confidence: Confidence
    location: SourceLocation
    evidence: str
    remediation: str


class ScanError(BaseModel):
    path: str
    message: str


class RouteInfo(BaseModel):
    path: str
    method: str
    handler: str
    parameters: list[str]
    dependencies: list[str] = Field(default_factory=list)
    security_dependencies: list[str] = Field(default_factory=list)
    location: SourceLocation


class Dependency(BaseModel):
    name: str
    version: str
    location: SourceLocation


class DependencyVulnerability(BaseModel):
    advisory_id: str
    package: str
    version: str
    advisory_url: str
    location: SourceLocation


class ScanReport(BaseModel):
    project_name: str
    files_discovered: int
    files_analyzed: int
    findings: list[Finding]
    routes: list[RouteInfo]
    dependencies: list[Dependency]
    dependency_vulnerabilities: list[DependencyVulnerability]
    dependency_check_performed: bool
    errors: list[ScanError]


class ScanRequest(BaseModel):
    project_path: str = Field(min_length=1)
