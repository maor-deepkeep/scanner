from pydantic import BaseModel
from datetime import datetime
from enum import Enum

class StaticScanInitiationRequest(BaseModel):
    model_id: str
    model_name: str
    model_version: str
    model_url: str
    model_metadata: dict | None = None
    org_id: str

class StaticScanInitiationResponse(BaseModel):
    success: bool
    operation_id: str
    error: str | None = None

class StaticScanStatus(BaseModel):
    operation_id: str
    status: str
    progress: int
    error: str | None = None

class ModelMetadata(BaseModel):
    model_id: str
    model_name: str
    model_version: str
    model_metadata: dict | None = None

class ModelArtifact(BaseModel):
    metadata: ModelMetadata
    folder_path: str

class ModelFile(BaseModel):
    path: str
    hash: str

class Manifest(BaseModel):
    files: list[ModelFile]
    manifest_hash: str

class Verdict(Enum):
    VALID = "Valid"
    TAMPERED = "Tampered"

class ValidationResult(BaseModel):
    old_manifest: Manifest | None
    new_manifest: Manifest
    verdict: Verdict
    changed_files: list[str]
    validated_at: datetime

class Severity(Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ScannerType(Enum):
    TRIVY = "trivy"
    MODEL_TOTAL = "model_total"

class PackageManager(Enum):
    PIP = "pip"
    UNKNOWN = "unknown"

class LicenseClassification(Enum):
    NOTICE = "notice"
    PERMISSIVE = "permissive"
    UNENCUMBERED = "unencumbered"
    RESTRICTED = "restricted"
    RECIPROCAL = "reciprocal"
    FORBIDDEN = "forbidden"
    UNKNOWN = "unknown"

class RiskLevel(Enum):
    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    UNKNOWN = "unknown"

class AffectedType(Enum):
    PACKAGE = "package"
    FILE = "file"

class Affected(BaseModel):
    kind: AffectedType
    ref: str
    version: str | None = None

class Vulnerability(BaseModel):
    id: str
    affected: list[Affected]
    severity: Severity
    detected_by: ScannerType
    detect_at: datetime
    cvss: dict
    title: str
    description: str
    references: list[str]

class Package(BaseModel):
    name: str
    version: str
    package_manager: PackageManager

class License(BaseModel):
    name: str
    package: Package

class LicenseWithClassification(BaseModel):
    license: License
    classification: LicenseClassification
    risk_level: RiskLevel

class TrivyScanningResult(BaseModel):
    vulnerabilities: list[Vulnerability]
    packages: list[Package]
    sbom: dict

class LicensesScanningResult(BaseModel):
    licenses: list[License]

class IssueType(Enum):
    VULNERABILITY = "vulnerability"
    LICENSE = "license"
    TAMPER = "tamper"
    RISK = "risk"

class Issue(BaseModel):
    id: str
    type: IssueType
    title: str
    description: str
    severity: Severity
    cvss: dict
    affected: list[Affected]
    recommendation: str
    references: list[str]
    detected_by: ScannerType
    detected_at: datetime

class StaticScanResult(BaseModel):
    operation_id: str
    ml_bom: dict
    s_bom: dict
    issues: list[Issue]
    generated_at: datetime

class TrivyDBUpdateResult(BaseModel):
    success: bool
    updated_at: datetime