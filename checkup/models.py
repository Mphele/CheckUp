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

