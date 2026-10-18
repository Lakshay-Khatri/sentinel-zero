from pydantic import BaseModel, Field
from typing import List, Optional, Dict
from enum import Enum

class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Finding(BaseModel):
    id: str = Field(..., description="Stable identifier for the finding (e.g., 'MISSING_HSTS')")
    title: str = Field(..., description="Concise title of the issue")
    severity: Severity = Field(..., description="Severity level of the finding")
    evidence: Optional[str] = Field(None, description="The exact value or missing attribute found")
    explanation: str = Field(..., description="Explanation of why this is a risk")
    remediation: str = Field(..., description="How to fix the issue")

class AnalysisReport(BaseModel):
    target_url: str
    validated_ip: str
    findings: List[Finding] = []
    scan_metadata: Dict[str, str] = {}
