import logging
import os
import time
import tarfile
import io
from typing import List, Dict, Any, Optional
from types import SimpleNamespace

try:
    from picklescan.scanner import scan_file_path, scan_pickle_bytes, scan_zip_bytes, ScanResult
    PICKLESCAN_AVAILABLE = True
except ImportError:
    PICKLESCAN_AVAILABLE = False
    scan_file_path = None
    scan_pickle_bytes = None
    scan_zip_bytes = None
    ScanResult = None

from datetime import datetime
from app.models import (
    Issue, IssueType, Severity, Affected, AffectedType, TechnicalDetails,
    PickleScanResult as BasePickleScanResult, BaseScanner
)
from app.static_scan.exceptions import PickleScanError, ScannerNotAvailableError
from app.static_scan.common import normalize_severity, get_scanner_type

logger = logging.getLogger(__name__)


class PickleScanResult(BasePickleScanResult):
    """PickleScan specific result with full to_issues() implementation."""
    
    def to_issues(self) -> List[Issue]:
        """
        Convert PickleScan findings to standardized Issue objects.
        
        IMPORTANT: We filter out INNOCUOUS and SUSPICIOUS findings as they
        generate too many false positives. Only DANGEROUS findings are
        reported as actual security issues.
        
        Returns:
            List of Issue objects for dangerous findings only
        """
        issues = []
        
        # Get globals from scanner_data
        globals_found = self.scanner_data.get('globals', [])
        
        for global_info in globals_found:
            # Get severity from picklescan
            picklescan_severity = str(global_info.get('severity', '')).lower()
            
            # IMPORTANT: Skip innocuous and suspicious findings to avoid false positives
            # Only report DANGEROUS findings as actual security issues
            if picklescan_severity in ['innocuous', 'suspicious']:
                continue
            
            # Map dangerous to CRITICAL
            severity = Severity.CRITICAL if picklescan_severity == 'dangerous' else Severity.HIGH
            
            # Create affected objects
            affected = []
            if global_info.get('file_path'):
                affected.append(Affected(
                    kind=AffectedType.FILE,
                    ref=global_info.get('file_path')
                ))
            
            module = global_info.get('module')
            name = global_info.get('name')
            
            # Create technical details with ALL raw data from scanner
            # Ensure module and operator exist for aggregation (if they have values)
            tech_details_dict = global_info.copy()
            if 'module' not in tech_details_dict and module:
                tech_details_dict['module'] = module
            if 'operator' not in tech_details_dict and name:
                tech_details_dict['operator'] = name  # picklescan uses 'name' as operator
            tech_details = TechnicalDetails(**tech_details_dict)
            
            # Build title/description with available information
            if module and name:
                title = f"Dangerous pickle operation: {name} from {module}"
                description = f"Detected dangerous pickle operation '{name}' from module '{module}'"
            elif name:
                title = f"Dangerous pickle operation: {name}"
                description = f"Detected dangerous pickle operation '{name}'"
            elif module:
                title = f"Dangerous pickle operation from {module}"
                description = f"Detected dangerous pickle operation from module '{module}'"
            else:
                title = "Dangerous pickle operation detected"
                description = "Detected dangerous pickle operation"
            
            issue = Issue(
                id=Issue.generate_id(IssueType.MALICIOUS_CODE),
                type=IssueType.MALICIOUS_CODE,
                title=title,
                description=description,
                severity=severity,
                cvss={},
                affected=affected,
                technical_details=tech_details,
                recommendation="Review and validate pickle file contents for security risks",
                references=[],
                detected_by=get_scanner_type(self.scanner_name),
                detected_at=datetime.now()
            )
            issues.append(issue)
        
        return issues


class PickleScanScanner(BaseScanner):
    """Scanner for pickle files using the picklescan library with enhanced torch support."""
    
    def __init__(self):
        super().__init__()
        self.scanned_files = []
    
    def scan(self, path: str) -> PickleScanResult:
        """
        Run picklescan on the specified path with recursive scanning.
        Scans archives without extracting them to disk.
        
        Args:
            path: File system path to scan
            
        Returns:
            PickleScanResult that can be converted to Issue objects
        """
        start_time = time.time()
        if not PICKLESCAN_AVAILABLE:
            logger.error("Picklescan library not available")
            raise ScannerNotAvailableError("PickleScan", "Library not installed", None)
        
        try:
            logger.info(f"Running picklescan on path: {path}")
            
            # Reset tracking
            self.scanned_files = []
            
            globals_found = []
            infected_files = []
            scan_errors = []
            total_issues = 0
            
            # Find all files to scan (including archives)
            files_to_scan = self._find_all_scannable_files(path)
            
            if not files_to_scan:
                return PickleScanResult(
                    scanner_name=self.scanner_name,
                    verdict="SAFE",
                    issues_count=0,
                    files_scanned=[],
                    affected_files=[],
                    scanner_data={},
                    raw_output={"message": "No files found to scan"}
                )
            
            logger.info(f"Found {len(files_to_scan)} files to scan")
            
            # Scan each file
            for file_path in files_to_scan:
                try:
                    scan_result = None
                    
                    # Check if it's an archive
                    if self.is_zip_archive(file_path):
                        # Scan ZIP directly using picklescan's built-in support
                        with open(file_path, 'rb') as f:
                            data = f.read()
                            # scan_zip_bytes expects a file-like object, not raw bytes
                            scan_result = scan_zip_bytes(io.BytesIO(data), file_path)
                        self.scanned_files.append(file_path)
                        
                    elif self.is_tar_archive(file_path):
                        # Scan TAR contents without extraction
                        scan_result = self._scan_tar_archive(file_path)
                        self.scanned_files.append(file_path)
                        
                    else:
                        # Regular file scan
                        scan_result = scan_file_path(file_path)
                        self.scanned_files.append(file_path)
                    
                    # Process scan results with safe attribute access
                    if scan_result:
                        issues_count = getattr(scan_result, 'issues_count', 0)
                        globals_list = getattr(scan_result, 'globals', [])
                        
                        if issues_count > 0 or len(globals_list) > 0:
                            infected_files.append(file_path)
                            total_issues += issues_count
                        
                        # Process globals found
                        for g in globals_list:
                            globals_found.append({
                                'module': g.module if hasattr(g, 'module') else 'unknown',
                                'name': g.name if hasattr(g, 'name') else 'unknown',
                                'severity': g.safety.value if hasattr(g, 'safety') else 'unknown',
                                'file_path': file_path
                            })
                    
                except Exception as e:
                    logger.exception(f"Failed to scan {file_path}")
                    scan_errors.append(f"{file_path}: {str(e)}")
            
            duration = time.time() - start_time
            logger.info(f"Picklescan completed: {len(infected_files)} infected files found")
            
            # Store raw scanner output
            raw_output = {
                "total_files_scanned": len(self.scanned_files),
                "infected_files": infected_files,
                "total_issues": total_issues,
                "globals_found": globals_found,
                "scan_errors": scan_errors
            }
            
            # Determine verdict based on findings
            verdict = "SAFE"
            if infected_files:
                verdict = "MALICIOUS"
            
            return PickleScanResult(
                scanner_name=self.scanner_name,
                verdict=verdict,
                issues_count=total_issues,
                files_scanned=self.scanned_files,
                affected_files=infected_files,
                scanner_data={'globals': globals_found, 'infected_files': infected_files},
                scan_duration=duration,
                raw_output=raw_output,
                errors=scan_errors if scan_errors else []
            )
            
        except ImportError as e:
            logger.exception("Picklescan library not available")
            return PickleScanResult(
                scanner_name=self.scanner_name,
                verdict="SAFE",
                issues_count=0,
                files_scanned=[],
                affected_files=[],
                scanner_data={},
                errors=[f"Import error: {str(e)}"]
            )
        except Exception as e:
            logger.exception("Picklescan scan failed")
            return PickleScanResult(
                scanner_name=self.scanner_name,
                verdict="SAFE",
                issues_count=0,
                files_scanned=self.scanned_files,
                affected_files=[],
                scanner_data={},
                errors=[f"Scan failed: {str(e)}"]
            )
    
    def _find_all_scannable_files(self, path: str, max_depth: int = 10) -> List[str]:
        """
        Recursively find all files. Let picklescan decide what's scannable.
        
        Args:
            path: Directory or file path to search
            max_depth: Maximum directory recursion depth (default 10)
            
        Returns:
            List of file paths to scan
        """
        scannable_files = []
        
        if os.path.isfile(path):
            # Single file - let picklescan decide if it's scannable
            scannable_files.append(path)
        else:
            # Directory - walk recursively
            for root, dirs, files in os.walk(path):
                # Limit recursion depth
                depth = root[len(path):].count(os.sep)
                if depth >= max_depth:
                    dirs[:] = []  # Don't recurse further
                    continue
                
                for file in files:
                    file_path = os.path.join(root, file)
                    scannable_files.append(file_path)
        
        return scannable_files
    
    
    def _scan_tar_archive(self, archive_path: str) -> Any:
        """
        Scan TAR archive contents without extracting to disk.
        
        Args:
            archive_path: Path to TAR file
            
        Returns:
            Combined scan result from all contents
        """
        # Create a combined result using SimpleNamespace
        combined_result = SimpleNamespace(
            globals=[],
            scanned_files=[],
            issues_count=0
        )
        
        try:
            with tarfile.open(archive_path, 'r') as tf:
                for member in tf.getmembers():
                    if member.isfile():
                        name_lower = member.name.lower()
                        # Check if it's a serialized file (pickle or ML model)
                        if self.is_serialized_file(name_lower):
                            try:
                                with tf.extractfile(member) as f:
                                    if f:
                                        data = f.read()
                                        result = scan_pickle_bytes(data, member.name)
                                        # Safe attribute access
                                        if hasattr(result, 'scanned_files'):
                                            combined_result.scanned_files += result.scanned_files
                                        if hasattr(result, 'issues_count'):
                                            combined_result.issues_count += result.issues_count
                                        if hasattr(result, 'globals'):
                                            combined_result.globals.extend(result.globals)
                            except Exception as e:
                                logger.debug(f"Could not scan {member.name} in archive: {e}")
        except Exception as e:
            logger.warning(f"Error scanning TAR archive {archive_path}: {e}")
        
        return combined_result
    
