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


class ScanReport(BaseModel):
    project_name: str
    files_discovered: int
    files_analyzed: int
    findings: list[Finding]
    errors: list[ScanError]


class ScanRequest(BaseModel):
    project_path: str = Field(min_length=1)


class RouteInfo(BaseModel):
    path: str
    method: str
    handler: str
    parameters: list[str]
    location: SourceLocation
