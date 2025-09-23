from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any, Union, TYPE_CHECKING, Set
from abc import ABC, abstractmethod
import uuid
import os
import logging
import zipfile
import tarfile

logger = logging.getLogger(__name__)



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
    MODELSCAN = "modelscan"
    PICKLESCAN = "picklescan"
    FICKLING = "fickling"
    MODELAUDIT = "modelaudit"

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
    location: str | None = None
    line_number: Optional[int] = None

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
    MALICIOUS_CODE = "malicious_code"

class TechnicalDetails(BaseModel):
    """Dynamic technical details from scanner outputs - captures all raw scanner data"""
    model_config = {"extra": "allow"}  # Pydantic v2 way to allow extra fields

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
    detected_by: Union[ScannerType, list[ScannerType]]
    detected_at: datetime
    technical_details: Optional[TechnicalDetails] = None
    occurrences: Optional[int] = 1  # Number of times this issue was found (for aggregated issues)
    
    @staticmethod
    def generate_id(issue_type: IssueType, base_id: str = None) -> str:
        """Generate ID with consistent format: iss-{type}-{id}"""
        # Map issue types to short prefixes
        type_map = {
            IssueType.VULNERABILITY: 'vuln',
            IssueType.LICENSE: 'lic',
            IssueType.TAMPER: 'tam',
            IssueType.MALICIOUS_CODE: 'mal',
            IssueType.RISK: 'risk'
        }
        
        # Get the type prefix
        type_prefix = type_map.get(issue_type, 'unk')
        
        # Use provided ID or generate a new one
        id_part = base_id if base_id else str(uuid.uuid4())[:16]
        
        # Special handling for CVE IDs
        if issue_type == IssueType.VULNERABILITY and id_part.startswith("CVE-"):
            return f"iss-{id_part.lower()}"
        else:
            return f"iss-{type_prefix}-{id_part}"


class BaseScanResult(BaseModel):
    """Base model for all scanner results with common fields and conversion method."""
    
    # Core fields (always available)
    scanner_name: str
    scan_duration: float = 0.0
    
    # Result fields (easily derivable from all scanners)
    verdict: str = "SAFE"  # SAFE, SUSPICIOUS, MALICIOUS
    issues_count: int = 0
    
    # Optional fields (not all scanners can provide these)
    files_scanned: List[str] = Field(default_factory=list)
    affected_files: List[str] = Field(default_factory=list)  # Files with issues/problems
    
    # Scanner-specific data used by to_issues() method
    scanner_data: Dict[str, Any] = Field(default_factory=dict)
    
    # Debug/raw data
    raw_output: Dict[str, Any] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)
    
    @abstractmethod
    def to_issues(self) -> List[Issue]:
        """
        Convert scanner-specific results to standardized Issue objects.
        
        Each scanner result must implement this method to transform
        its findings into the common Issue format.
        
        Returns:
            List of Issue objects representing security findings
        """
        pass


class BaseScanner(ABC):
    """
    Base scanner class with shared functionality for all security scanners.
    
    Provides common file discovery, trusted module filtering, and other
    utilities that all scanners can leverage.
    """
    
    # File extension definitions (consolidated from file_extensions.py)
    PICKLE_EXTENSIONS: Set[str] = {
        '.pkl', '.pickle', '.p', '.joblib', '.dat', '.data'
    }
    
    ML_MODEL_EXTENSIONS: Set[str] = {
        # PyTorch
        '.pt', '.pth', '.bin', '.ckpt',
        # TensorFlow/Keras
        '.h5', '.hdf5', '.pb', '.keras',
        # ONNX
        '.onnx',
        # SafeTensors
        '.safetensors',
        # TensorFlow Lite
        '.tflite',
        # Core ML
        '.mlmodel',
        # Other
        '.model', '.weights'
    }
    
    # Combined sets for convenience
    SERIALIZED_EXTENSIONS: Set[str] = PICKLE_EXTENSIONS | ML_MODEL_EXTENSIONS
    
    # Archive extensions
    ARCHIVE_EXTENSIONS: Set[str] = {
        '.zip', '.tar', '.tar.gz', '.tar.bz2', '.tar.xz', '.tgz'
    }
    
    # Trusted ML frameworks (used when trusted filter is enabled)
    TRUSTED_MODULES: Set[str] = {
        # Core ML frameworks
        'torch', 'torchvision', 'pytorch',
        'tensorflow', 'tf', 'keras',
        # Scientific computing
        'numpy', 'scipy', 'sklearn', 'scikit-learn',
        'pandas', 'matplotlib', 'seaborn',
        # Deep learning extensions
        'transformers', 'datasets', 'tokenizers',
        'lightning', 'fastai',
        # Common utilities
        'joblib', 'dill', 'cloudpickle'
    }
    
    def __init__(self):
        """Initialize the scanner with common configuration."""
        # Extract scanner name from class name (e.g., ModelScanScanner -> modelscan)
        self.scanner_name = self.__class__.__name__.replace('Scanner', '').lower()
        
        # Check if trusted module filtering is enabled via environment variable
        # Default to true (enabled) unless explicitly disabled
        env_var = f"{self.scanner_name.upper()}_TRUSTED_FILTER"
        self.enable_trusted_filter = os.getenv(env_var, "true").lower() != "false"
        
        if self.enable_trusted_filter:
            logger.info(f"{self.scanner_name}: Trusted module filtering enabled")
    
    @abstractmethod
    def scan(self, path: str) -> BaseScanResult:
        """
        Run the scanner on the specified path.
        
        Args:
            path: File or directory path to scan
            
        Returns:
            Scanner-specific result object that extends BaseScanResult
        """
        pass
    
    @classmethod
    def is_pickle_file(cls, filepath: str) -> bool:
        """Check if a file is a pickle format."""
        return any(filepath.lower().endswith(ext) for ext in cls.PICKLE_EXTENSIONS)
    
    @classmethod
    def is_ml_model_file(cls, filepath: str) -> bool:
        """Check if a file is a machine learning model."""
        return any(filepath.lower().endswith(ext) for ext in cls.ML_MODEL_EXTENSIONS)
    
    @classmethod
    def is_serialized_file(cls, filepath: str) -> bool:
        """Check if a file contains serialized data (pickle or ML model)."""
        return any(filepath.lower().endswith(ext) for ext in cls.SERIALIZED_EXTENSIONS)
    
    @classmethod
    def is_archive_file(cls, filepath: str) -> bool:
        """Check if a file is an archive."""
        return any(filepath.lower().endswith(ext) for ext in cls.ARCHIVE_EXTENSIONS)
    
    def is_zip_archive(self, file_path: str) -> bool:
        """Check if file is a ZIP archive by trying to open it."""
        try:
            with zipfile.ZipFile(file_path, 'r'):
                return True
        except (zipfile.BadZipFile, IsADirectoryError):
            return False
    
    def is_tar_archive(self, file_path: str) -> bool:
        """Check if file is a TAR archive by trying to open it."""
        try:
            with tarfile.open(file_path, 'r'):
                return True
        except (tarfile.TarError, IsADirectoryError):
            return False
    
    def is_trusted_module_issue(self, module_or_text: str) -> bool:
        """
        Check if an issue is from a trusted module and should be filtered.
        
        Args:
            module_or_text: Module name or text containing module info
            
        Returns:
            True if the issue is from a trusted module, False otherwise
        """
        if not self.enable_trusted_filter:
            return False
        
        # Check if the module (or any part of it) is in trusted modules
        text = str(module_or_text).lower()
        for trusted in self.TRUSTED_MODULES:
            if trusted.lower() in text:
                return True
        return False


class StaticScanResult(BaseModel):
    operation_id: str
    model_id: str
    model_name: str
    model_version: str
    final_verdict: str
    ml_bom: dict
    s_bom: dict
    issues: list[Issue]
    generated_at: datetime

class TrivyDBUpdateResult(BaseModel):
    success: bool
    updated_at: datetime

# Scanner result models - simplified since scanner-specific data goes in scanner_data field
# The actual implementations with full to_issues() methods are in the scanner files
class ModelScanResult(BaseScanResult):
    def to_issues(self) -> List[Issue]:
        """Implemented in the actual scanner file"""
        return []

class PickleScanResult(BaseScanResult):
    def to_issues(self) -> List[Issue]:
        """Implemented in the actual scanner file"""
        return []

class FicklingResult(BaseScanResult):
    def to_issues(self) -> List[Issue]:
        """Implemented in the actual scanner file"""
        return []

class ModelAuditResult(BaseScanResult):
    def to_issues(self) -> List[Issue]:
        """Implemented in the actual scanner file"""
        return []

class ModelSecurityScanningResult(BaseModel):
    modelscan_result: Optional[ModelScanResult] = None
    picklescan_result: Optional[PickleScanResult] = None
    fickling_result: Optional[FicklingResult] = None
    modelaudit_result: Optional[ModelAuditResult] = None
    aggregated_issues: list[Issue]