import aiohttp
import asyncio
import logging

from typing import Optional, Dict, Any, List, Union
from datetime import datetime
from enum import Enum
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Copied models from the app for standalone usage
class StaticScanInitiationRequest(BaseModel):
    model_id: str
    model_name: str
    model_version: str
    model_url: str
    model_metadata: Dict[str, Any] | None = None
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


class AffectedType(Enum):
    PACKAGE = "package"
    FILE = "file"


class IssueType(Enum):
    VULNERABILITY = "vulnerability"
    LICENSE = "license"
    TAMPER = "tamper"
    RISK = "risk"
    MALICIOUS_CODE = "malicious_code"


class TechnicalDetails(BaseModel):
    """Dynamic technical details from scanner outputs - captures all raw scanner data"""
    model_config = {"extra": "allow"}  # Pydantic v2 way to allow extra fields


class Affected(BaseModel):
    kind: AffectedType
    ref: str
    version: str | None = None


class Issue(BaseModel):
    id: str
    type: IssueType
    title: str
    description: str
    severity: Severity
    cvss: Dict[str, Any]
    affected: List[Affected]
    recommendation: str
    references: List[str]
    detected_by: Union[ScannerType, List[ScannerType]]
    detected_at: datetime
    technical_details: Optional[TechnicalDetails] = None


class StaticScanResult(BaseModel):
    operation_id: str
    model_id: str
    model_name: str
    model_version: str
    final_verdict: str
    ml_bom: Dict[str, Any]
    s_bom: Dict[str, Any]
    issues: List[Issue]
    generated_at: datetime

class TrivyDBUpdateResult(BaseModel):
    success: bool
    updated_at: datetime

DEFAULT_TIMEOUT = 30

class ModelTotal:
    """
    ModelTotal client for communicating with the FastAPI backend.
    
    Provides methods to:
    1. Scan artifacts for vulnerabilities, licenses and security issues
    2. Update Trivy database with new vulnerability data
    3. Monitor scan progress and retrieve results
    
    Example usage:
        async with ModelTotal("http://localhost:8000") as client:
            result = await client.scan_artifact(
                model_id="my-model",
                model_name="example-model",
                model_version="1.0.0",
                model_url="http://example.com/model.zip",
                org_id="my-org"
            )
            print(f"Scan completed: {len(result.issues)} issues found")
    """
    
    def __init__(self, base_url: str):
        """
        Initialize ModelTotal client.
        
        Args:
            base_url: Base URL of the ModelTotal API server
        """
        self.base_url = base_url.rstrip('/')
    
    async def _request(self, method: str, path: str, timeout: int = DEFAULT_TIMEOUT, **kwargs):
        """
        Make an HTTP request with a fresh session.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: API endpoint path
            timeout: Request timeout in seconds
            **kwargs: Additional arguments for the request (json, data, etc.)
            
        Returns:
            Response data as dict
            
        Raises:
            aiohttp.ClientError: If the request fails
        """
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=30
        )
        
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.request(
                method,
                f"{self.base_url}/{path}",
                timeout=aiohttp.ClientTimeout(total=timeout),
                **kwargs
            ) as response:
                response.raise_for_status()
                return await response.json()
    
    async def _upload_file(self, path: str, file_path: str, timeout: int = DEFAULT_TIMEOUT):
        """
        Upload a file with a fresh session.

        Args:
            path: API endpoint path
            file_path: Path to the file to upload
            timeout: Request timeout in seconds

        Returns:
            Response data as dict

        Raises:
            aiohttp.ClientError: If the request fails
        """
        import os

        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=30
        )

        with open(file_path, 'rb') as f:
            data = aiohttp.FormData()
            data.add_field('file', f, filename=os.path.basename(file_path), content_type='application/gzip')

            # Use extended timeout for large file uploads
            timeout_config = aiohttp.ClientTimeout(
                total=timeout,
                sock_read=300  # 5 minutes read timeout for large uploads
            )

            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.post(
                    f"{self.base_url}/{path}",
                    data=data,
                    timeout=timeout_config
                ) as response:
                    response.raise_for_status()
                    return await response.json()
    
    async def scan_artifact(
        self,
        model_id: str,
        model_name: str,
        model_version: str,
        model_url: str,
        org_id: str,
        model_metadata: Optional[Dict[str, Any]] = None,
        timeout: int = DEFAULT_TIMEOUT
    ) -> StaticScanResult:
        """
        Scan a model artifact for security vulnerabilities and issues.
        
        Args:
            model_id: Unique identifier for the model
            model_name: Name of the model
            model_version: Version of the model
            model_url: URL to download the model
            org_id: Organization identifier
            model_metadata: Optional metadata about the model
            timeout: Request timeout in seconds
            
        Returns:
            StaticScanResult containing scan results
            
        Raises:
            aiohttp.ClientError: If the API request fails
            ValueError: If the scan fails or returns an error
        """
        # Create scan request
        scan_request = StaticScanInitiationRequest(
            model_id=model_id,
            model_name=model_name,
            model_version=model_version,
            model_url=model_url,
            model_metadata=model_metadata,
            org_id=org_id
        )
        
        response_data = await self._request(
            "POST",
            "static-scan",
            timeout=timeout,
            json=scan_request.model_dump()
        )
        scan_response = StaticScanInitiationResponse(**response_data)
        
        if not scan_response.success:
            raise ValueError(f"Scan initiation failed: {scan_response.error}")
        
        operation_id = scan_response.operation_id
        
        # Poll for completion
        while True:
            status = await self.get_scan_status(operation_id, timeout)
            
            if status.error:
                raise ValueError(f"Scan failed: {status.error}")
            
            # Log progress for visibility
            logger.info(f"Scan progress: {status.progress}%")
            
            if status.status == "SUCCESS":
                break
            elif status.status == "FAILURE":
                error_msg = status.error or "Unknown error occurred"
                raise ValueError(f"Scan failed: {error_msg}")
            
            # Wait before polling again
            await asyncio.sleep(5)
        
        # Get results
        return await self.get_scan_results(operation_id, timeout)
    
    async def update_trivy_db(self, db_file_path: str, timeout: int = DEFAULT_TIMEOUT) -> TrivyDBUpdateResult:
        """
        Update the Trivy vulnerability database. (Supports trivy db v2 only)
        File uploaded should be a .tar.gz/.tgz containing both metadata.json and trivy.db
        
        Args:
            db_file_path: Path to the Trivy database .tgz file
            timeout: Request timeout in seconds
            
        Returns:
            TrivyDBUpdateResult with status, message, and timestamp
            
        Raises:
            aiohttp.ClientError: If the API request fails
            FileNotFoundError: If the database file doesn't exist
            ValueError: If the file format is invalid or update fails
        """
        import os
        
        if not os.path.exists(db_file_path):
            raise FileNotFoundError(f"Database file not found: {db_file_path}")
        
        if not db_file_path.endswith(('.tgz', '.tar.gz')):
            raise ValueError("Database file must be a .tgz or .tar.gz file")
        
        response_data = await self._upload_file("trivy/", db_file_path, timeout)
        return TrivyDBUpdateResult(**response_data)
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        pass
    
    async def close(self):
        """Close the HTTP session."""
        pass

    async def get_scan_status(self, operation_id: str, timeout: int = DEFAULT_TIMEOUT) -> StaticScanStatus:
        """
        Get the current status of a scan operation.
        
        Args:
            operation_id: The operation ID returned from scan_artifact
            timeout: Request timeout in seconds
            
        Returns:
            StaticScanStatus with progress information
        """
        response_data = await self._request(
            "GET",
            f"static-scan/{operation_id}/status",
            timeout=timeout
        )
        return StaticScanStatus(**response_data)

    async def get_scan_results(self, operation_id: str, timeout: int = DEFAULT_TIMEOUT) -> StaticScanResult:
        """
        Get the results of a completed scan operation.
        
        Args:
            operation_id: The operation ID returned from scan_artifact
            timeout: Request timeout in seconds
            
        Returns:
            StaticScanResult containing scan results
            
        Raises:
            aiohttp.ClientError: If the API request fails
        """
        results_data = await self._request(
            "GET",
            f"static-scan/{operation_id}/results",
            timeout=timeout
        )
        return StaticScanResult(**results_data)
