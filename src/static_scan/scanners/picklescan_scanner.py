import io
import logging
import os
import tarfile
import tempfile
import time
import zipfile
from datetime import datetime
from types import SimpleNamespace
from typing import List, Dict, Any, Optional

try:
    from picklescan.scanner import scan_file_path, scan_pickle_bytes
    PICKLESCAN_AVAILABLE = True
except ImportError:
    PICKLESCAN_AVAILABLE = False

from src.models import (
    Issue, IssueType, Affected, AffectedType, TechnicalDetails,
    PickleScanResult as BasePickleScanResult, BaseScanner
)
from src.static_scan.exceptions import PickleScanError, ScannerNotAvailableError
from src.static_scan.common import normalize_severity, get_scanner_type

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
            picklescan_severity = str(global_info.get('severity', '')).upper()

            # IMPORTANT: Skip innocuous and suspicious findings to avoid false positives
            # Only report DANGEROUS findings as actual security issues
            if picklescan_severity in ['INNOCUOUS', 'SUSPICIOUS']:
                continue

            # Normalize severity using common mapping
            severity = normalize_severity(picklescan_severity, 'picklescan')
            
            # Create affected objects with full archive path
            affected = []
            archives = global_info.get('archives', [])
            file_path = global_info.get('file_path')

            if file_path:
                # Construct full path from archives hierarchy
                if archives:
                    full_path = ':'.join(archives) + ':' + file_path
                else:
                    full_path = file_path

                affected.append(Affected(
                    kind=AffectedType.FILE,
                    ref=full_path
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
            self.scan_errors = []

            globals_found = []
            infected_files = []
            total_issues = 0
            
            # Find all files to scan with their types
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

            # Scan each file based on its type
            for file_path, file_type in files_to_scan.items():
                try:
                    scan_result = None

                    if file_type in (self.FileType.ZIP, self.FileType.TAR):
                        scan_result = self._scan_archive(file_path)
                        self.scanned_files.append(file_path)
                    elif file_type == self.FileType.SERIALIZED:
                        scan_result = scan_file_path(file_path)
                        self.scanned_files.append(file_path)

                    if scan_result:
                        issues_count = getattr(scan_result, 'issues_count', 0)
                        globals_list = getattr(scan_result, 'globals', [])
                        scan_err = getattr(scan_result, 'scan_err', False)

                        logger.debug(f"Scan result for {file_path}: issues={issues_count}, "
                                   f"globals={len(globals_list)}, scan_err={scan_err}")

                        if scan_err:
                            error_msg = f"{file_path}: Pickle parsing error"
                            self.scan_errors.append(error_msg)
                            logger.debug(f"Picklescan error for {file_path}")

                        if issues_count > 0 or len(globals_list) > 0:
                            total_issues += issues_count

                        for g in globals_list:
                            individual_file = g.file_path if hasattr(g, 'file_path') else file_path
                            archives = g.archives if hasattr(g, 'archives') else []

                            globals_found.append({
                                'module': g.module if hasattr(g, 'module') else 'unknown',
                                'name': g.name if hasattr(g, 'name') else 'unknown',
                                'severity': g.safety.value if hasattr(g, 'safety') else 'unknown',
                                'file_path': individual_file,
                                'archives': archives
                            })

                            # Build full hierarchical path: outer.tar:inner.zip:file.pkl
                            full_file_path = ':'.join(archives) + ':' + individual_file if archives else individual_file
                            if full_file_path not in infected_files:
                                infected_files.append(full_file_path)

                except OSError as e:
                    # Non-seekable files or invalid file operations (expected for non-pickle files)
                    if "Invalid argument" in str(e):
                        logger.debug(f"Skipping non-pickle file {file_path}: {e}")
                    else:
                        logger.error(f"OS error scanning {file_path}: {e}")
                        self.scan_errors.append(f"{file_path}: {str(e)}")
                except (IOError, MemoryError) as e:
                    # Critical errors that should be logged
                    logger.error(f"Critical error scanning {file_path}: {e}")
                    self.scan_errors.append(f"{file_path}: {str(e)}")
                except Exception as e:
                    # Other errors - log at debug level (likely parsing errors)
                    logger.debug(f"Could not scan {file_path}: {e}")
                    self.scan_errors.append(f"{file_path}: {str(e)}")
            
            duration = time.time() - start_time
            logger.info(f"Picklescan completed: {len(infected_files)} infected files found")

            raw_output = {
                "total_files_scanned": len(self.scanned_files),
                "infected_files": infected_files,
                "total_issues": total_issues,
                "globals_found": globals_found,
                "scan_errors": self.scan_errors
            }

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
                errors=self.scan_errors if self.scan_errors else []
            )
            
        except Exception as e:
            logger.exception("Picklescan scan failed")
            raise PickleScanError(f"Scan failed: {str(e)}", e) from e
    
    def _find_all_scannable_files(self, path: str, max_depth: int = 10) -> Dict[str, 'FileType']:
        """
        Recursively find scannable files (serialized files and archives).

        Args:
            path: Directory or file path to search
            max_depth: Maximum directory recursion depth (default 10)

        Returns:
            Dict mapping file paths to FileType enum values
        """
        scannable_files = {}

        if os.path.isfile(path):
            # Single file - classify it
            file_type = self.classify_file(path)
            if file_type != self.FileType.OTHER:
                scannable_files[path] = file_type
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
                    file_type = self.classify_file(file_path)
                    if file_type != self.FileType.OTHER:
                        scannable_files[file_path] = file_type

        return scannable_files
    
    
    def _merge_scan_result(self, combined_result: SimpleNamespace, result: Any) -> None:
        """Merge a scan result into the combined result."""
        if result:
            if hasattr(result, 'issues_count'):
                combined_result.issues_count += result.issues_count
            if hasattr(result, 'globals'):
                combined_result.globals.extend(result.globals)

    def _process_archive_member(self, member_name: str, member_data: bytes, current_archives: List[str], depth: int, max_depth: int) -> Optional[Any]:
        """
        Process a single archive member (works for both ZIP and TAR).

        Args:
            member_name: Name of the member file
            member_data: Raw bytes of the member
            current_archives: Current archive hierarchy
            depth: Current nesting depth
            max_depth: Maximum nesting depth

        Returns:
            Scan result or None if skipped
        """
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(member_name)[1]) as tmp:
            tmp.write(member_data)
            tmp_path = tmp.name

        try:
            file_type = self.classify_file(tmp_path)

            if file_type in (self.FileType.ZIP, self.FileType.TAR):
                return self._scan_archive(tmp_path, depth + 1, max_depth, current_archives, archive_name=member_name)

            elif file_type == self.FileType.SERIALIZED:
                result = scan_pickle_bytes(io.BytesIO(member_data), member_name)
                # Track archive hierarchy: ['outer.tar', 'inner.zip'] for path construction
                if hasattr(result, 'globals'):
                    for g in result.globals:
                        g.file_path = member_name
                        if not hasattr(g, 'archives'):
                            g.archives = []
                        g.archives = current_archives
                return result

            else:
                logger.debug(f"Skipping non-scannable file: {member_name}")
                return None

        finally:
            os.unlink(tmp_path)

    def _scan_archive_by_type(self, archive_path: str, archive_type: 'BaseScanner.FileType', current_archives: List[str], depth: int, max_depth: int) -> SimpleNamespace:
        """
        Scan archive contents by type (ZIP or TAR).

        Args:
            archive_path: Path to archive file
            archive_type: FileType.ZIP or FileType.TAR
            current_archives: Current archive hierarchy
            depth: Current nesting depth
            max_depth: Maximum nesting depth

        Returns:
            Combined scan result
        """
        combined_result = SimpleNamespace(globals=[], scanned_files=[], issues_count=0)

        try:
            if archive_type == self.FileType.TAR:
                with tarfile.open(archive_path, 'r') as tf:
                    for member in tf.getmembers():
                        if not member.isfile():
                            continue

                        try:
                            with tf.extractfile(member) as f:
                                if not f:
                                    continue
                                data = f.read()

                            result = self._process_archive_member(member.name, data, current_archives, depth, max_depth)
                            self._merge_scan_result(combined_result, result)

                        except Exception as e:
                            logger.debug(f"Could not scan {member.name}: {e}")

            elif archive_type == self.FileType.ZIP:
                with zipfile.ZipFile(archive_path, 'r') as zf:
                    for member_name in zf.namelist():
                        if member_name.endswith('/'):
                            continue

                        try:
                            data = zf.read(member_name)
                            result = self._process_archive_member(member_name, data, current_archives, depth, max_depth)
                            self._merge_scan_result(combined_result, result)

                        except Exception as e:
                            logger.debug(f"Could not scan {member_name}: {e}")

        except Exception as e:
            logger.debug(f"Error scanning {archive_type.name} archive {archive_path}: {e}")

        return combined_result

    def _scan_archive(self, archive_path: str, depth: int = 0, max_depth: int = 3, parent_archives: Optional[List[str]] = None, archive_name: Optional[str] = None) -> Any:
        """
        Scan archive contents (ZIP or TAR) recursively without extracting to disk.

        Args:
            archive_path: Path to archive file (may be temp file)
            depth: Current nesting depth (0 = top level)
            max_depth: Maximum nesting depth to prevent zip bombs (default: 3)
            parent_archives: List of parent archive names in hierarchy
            archive_name: Logical archive name (if different from basename of archive_path)

        Returns:
            Combined scan result from all contents
        """
        if parent_archives is None:
            parent_archives = []

        # Use provided archive name or derive from path
        if archive_name is None:
            archive_name = os.path.basename(archive_path)

        # Prevent zip bombs and infinite recursion
        if depth > max_depth:
            logger.warning(f"Max archive depth ({max_depth}) exceeded: {archive_name}")
            self.scan_errors.append(f"{archive_name}: Max archive depth ({max_depth}) exceeded")
            return SimpleNamespace(globals=[], scanned_files=[], issues_count=0)

        # Build archive hierarchy: parent path + current archive name
        # e.g., [] + ['outer.tar'] = ['outer.tar'], then ['outer.tar'] + ['inner.zip'] = ['outer.tar', 'inner.zip']
        current_archives = parent_archives + [archive_name]

        # Check TAR before ZIP since TAR files containing ZIP data can be opened as ZIP
        if self.is_tar_archive(archive_path):
            return self._scan_archive_by_type(archive_path, self.FileType.TAR, current_archives, depth, max_depth)
        elif self.is_zip_archive(archive_path):
            return self._scan_archive_by_type(archive_path, self.FileType.ZIP, current_archives, depth, max_depth)
        else:
            return SimpleNamespace(globals=[], scanned_files=[], issues_count=0)
    
