import logging
import os
import re
import time
import pickle
import struct
import zipfile
import tarfile
from datetime import datetime
from io import BytesIO
from typing import List, Dict, Any, Tuple

try:
    import fickling
    import fickling.exception
    from fickling.polyglot import find_file_properties
    FICKLING_AVAILABLE = True
except ImportError:
    FICKLING_AVAILABLE = False
    fickling = None

from src.models import (
    Issue, IssueType, Severity, Affected, AffectedType, TechnicalDetails,
    FicklingResult as BaseFicklingResult, BaseScanner
)
from src.static_scan.exceptions import FicklingScanError, ScannerNotAvailableError
from src.static_scan.common import normalize_severity, get_scanner_type, strip_temp_path

logger = logging.getLogger(__name__)


class FicklingResult(BaseFicklingResult):
    """Fickling specific result with full to_issues() implementation."""

    def to_issues(self) -> List[Issue]:
        """
        Convert Fickling findings to standardized Issue objects.

        Returns:
            List of Issue objects
        """
        issues = []

        # Get data from scanner_data
        unsafe_files = self.scanner_data.get('unsafe_files', [])
        error_files = self.scanner_data.get('error_files', [])
        details = self.scanner_data.get('details', {})

        # Create issues for unsafe files
        for unsafe_file in unsafe_files:
            # Get all file details
            file_details = details.get(unsafe_file, {})

            # Extract filename - handle archive members (format: archive.zip#member.pkl)
            if '#' in unsafe_file:
                # Archive member
                archive_path, member_name = unsafe_file.split('#', 1)
                filename = member_name
                display_path = unsafe_file  # Show full path with archive
            else:
                # Regular file
                filename = os.path.basename(unsafe_file)
                display_path = unsafe_file

            # Strip temp path and create affected object
            clean_ref = strip_temp_path(display_path)
            affected = [Affected(kind=AffectedType.FILE, ref=clean_ref)]

            # Use split findings if available
            split_findings = file_details.get('split_findings', [])
            if split_findings:
                # Create separate issue for each finding type
                for finding in split_findings:
                    severity = normalize_severity(finding['severity'], 'fickling')
                    issues.append(Issue(
                        id=Issue.generate_id(IssueType.MALICIOUS_CODE),
                        type=IssueType.MALICIOUS_CODE,
                        title=f"{finding['title_suffix']} in {filename}",
                        description=finding['description'],
                        severity=severity,
                        cvss={},
                        affected=affected,
                        recommendation="Do not load this file as it may contain malicious code",
                        references=[],
                        detected_by=get_scanner_type(self.scanner_name),
                        technical_details=TechnicalDetails(**file_details) if file_details else None,
                        detected_at=datetime.now()
                    ))
            else:
                # Fallback: create single issue
                severity_text = file_details.get("severity", "LIKELY_UNSAFE")
                severity = normalize_severity(severity_text, 'fickling')
                analysis = file_details.get("analysis", "")

                issues.append(Issue(
                    id=Issue.generate_id(IssueType.MALICIOUS_CODE),
                    type=IssueType.MALICIOUS_CODE,
                    title=f"Unsafe pickle operations in {filename}",
                    description=analysis or f"File {filename} contains potentially unsafe operations",
                    severity=severity,
                    cvss={},
                    affected=affected,
                    recommendation="Do not load this file as it may contain malicious code",
                    references=[],
                    detected_by=get_scanner_type(self.scanner_name),
                    technical_details=TechnicalDetails(**file_details) if file_details else None,
                    detected_at=datetime.now()
                ))
        
        # Create issues for files with errors
        for error_file in error_files:
            file_details = details.get(error_file, {})
            error_msg = file_details.get("error", "Unknown error")

            # Skip "not_pickle" errors - these are not real errors
            if file_details.get("status") == "not_pickle":
                continue

            filename = os.path.basename(error_file)

            # Strip temp path and create affected object
            clean_ref = strip_temp_path(error_file)
            affected = [Affected(kind=AffectedType.FILE, ref=clean_ref)]
            
            issue = Issue(
                id=Issue.generate_id(IssueType.RISK),
                type=IssueType.RISK,
                title=f"Scan Error: {filename}",
                description=f"Error scanning pickle file {filename}: {error_msg}",
                severity=Severity.MEDIUM,
                cvss={},
                affected=affected,
                recommendation="Manual review required",
                references=[],
                detected_by=get_scanner_type(self.scanner_name),
                technical_details=TechnicalDetails(**file_details) if file_details else None,
                detected_at=datetime.now()
            )
            issues.append(issue)
        
        return issues
    
    def _generate_issue_title(self, file_details: Dict[str, Any], filename: str) -> str:
        """
        Generate a descriptive title based on the security finding.
        
        Args:
            file_details: Raw fickling output for the file
            filename: Name of the file
            
        Returns:
            Descriptive title for the issue
        """
        # Check detailed_results for specific attack patterns
        detailed = file_details.get("detailed_results", {})
        if detailed:
            analysis_result = detailed.get("AnalysisResult", {})
            
            # Check for specific dangerous operations based on fickling's analysis types
            if "OvertlyBadEvals" in analysis_result:
                return f"Eval Injection in {filename}"
            elif "BadCalls" in analysis_result:
                return f"Dangerous Function Call in {filename}"
            elif "UnsafeImports" in analysis_result:
                return f"Unsafe Import in {filename}"
            elif "UnsafeImportsML" in analysis_result:
                return f"Unsafe ML Import in {filename}"
            elif "NonStandardImports" in analysis_result:
                return f"Non-Standard Import in {filename}"
            elif "InvalidOpcode" in analysis_result:
                return f"Invalid Pickle Opcode in {filename}"
            elif "DuplicateProtoAnalysis" in analysis_result or "MisplacedProtoAnalysis" in analysis_result:
                return f"Protocol Manipulation in {filename}"
            elif "UnusedVariables" in analysis_result:
                return f"Suspicious Unused Code in {filename}"
        
        # Default title
        return f"Unsafe Pickle Operations in {filename}"


class FicklingScanner(BaseScanner):
    """Scanner for pickle files using the fickling library."""
    
    def __init__(self):
        super().__init__()
        # Note: trusted_modules and enable_trusted_filter are inherited from BaseScanner
    
    def scan(self, path: str) -> FicklingResult:
        """
        Run fickling on the specified path and return parsed results.
        
        Args:
            path: File system path to scan
            
        Returns:
            FicklingResult that can be converted to Issue objects
            
        Raises:
            Exception: If fickling fails or is not available
        """
        start_time = time.time()
        
        if not FICKLING_AVAILABLE:
            logger.error("Fickling library not available")
            raise ScannerNotAvailableError("Fickling", "Library not installed", None)
            
        try:
            logger.info(f"Running fickling scan on path: {path}")
            
            unsafe_files = []
            error_files = []
            details = {}
            overall_safe = True
            
            # Find all files - let fickling decide what's scannable
            all_files = self._find_all_files(path)
            
            if not all_files:
                logger.info("No files found")
                return FicklingResult(
                    scanner_name=self.scanner_name,
                    verdict="SAFE",
                    issues_count=0,
                    files_scanned=[],
                    affected_files=[],
                    scanner_data={},
                    raw_output={"message": "No files found"},
                    scan_duration=time.time() - start_time
                )
            
            logger.info(f"Found {len(all_files)} files to check")
            
            # Check each file - fickling will determine if it's scannable
            files_scanned = []
            for file_path in all_files:
                try:
                    check_result = self._check_file_safety(file_path)
                    
                    # Skip files that are not pickle-based (empty result)
                    if not check_result:
                        logger.debug(f"Skipping non-pickle file: {file_path}")
                        continue
                    
                    files_scanned.append(file_path)
                    logger.debug(f"Fickling check result for {file_path}: {check_result}")
                    
                    # Handle archive results - flatten unsafe_members
                    if check_result.get("is_archive") and "unsafe_members" in check_result:
                        # Process each unsafe member as a separate file
                        for member_result in check_result["unsafe_members"]:
                            member_name = member_result.get("member", "unknown")
                            # Create full path for archive member
                            member_path = f"{file_path}#{member_name}"
                            details[member_path] = member_result
                            unsafe_files.append(member_path)
                            overall_safe = False
                    elif check_result.get("is_archive") and check_result.get("safe", False):
                        # Safe archive - just record it was scanned
                        details[file_path] = check_result
                    else:
                        # Regular file result
                        details[file_path] = check_result
                        
                        if "error" in check_result:
                            error_files.append(file_path)
                            overall_safe = False
                        elif not check_result.get("safe", False):
                            unsafe_files.append(file_path)
                            overall_safe = False
                        
                except Exception as e:
                    logger.exception(f"Failed to scan file {file_path}")
                    error_files.append(file_path)
                    details[file_path] = {"status": "error", "error": str(e)}
                    overall_safe = False
            
            duration = time.time() - start_time
            logger.info(f"Fickling scan completed: {len(files_scanned)}/{len(all_files)} files scanned, "
                       f"{len(unsafe_files)} unsafe, {len(error_files)} errors")
            
            # Raw output is the details from fickling itself
            raw_output = details
            
            # Determine verdict
            verdict = "SAFE" if overall_safe else "MALICIOUS"
            issues_count = len(unsafe_files) + len(error_files)
            affected = unsafe_files + error_files
            
            return FicklingResult(
                scanner_name=self.scanner_name,
                verdict=verdict,
                issues_count=issues_count,
                files_scanned=files_scanned,
                affected_files=affected,
                scanner_data={
                    'safe': overall_safe,
                    'unsafe_files': unsafe_files,
                    'error_files': error_files,
                    'details': details
                },
                raw_output=raw_output,
                scan_duration=duration
            )
            
        except Exception as e:
            logger.exception("Fickling scan failed")
            raise FicklingScanError(f"Scan failed: {str(e)}", e) from e
    
    
    def _check_file_safety(self, file_path: str) -> Dict[str, Any]:
        """
        Check file safety using fickling, with special handling for archives.
        
        Args:
            file_path: Path to file to check
            
        Returns:
            Dictionary with safety results
        """
        # Check if it's an archive
        if self.is_zip_archive(file_path):
            return self._check_archive_safety(file_path, 'zip')
        elif self.is_tar_archive(file_path):
            return self._check_archive_safety(file_path, 'tar')
        
        # For non-archive files, open and check
        try:
            with open(file_path, 'rb') as f:
                return self._check_stream_with_fickling(f)
        except (pickle.UnpicklingError, EOFError, ValueError, struct.error) as e:
            # Not a scannable file - these are known decode/unpickle failures
            logger.debug(f"Not a scannable file: {file_path}")
            return {}  # No output from fickling for non-pickle files
        except Exception as e:
            # Real error - log it
            logger.error(f"Error opening file {file_path}: {e}")
            return {
                "error": str(e),
                "safe": False
            }
    
    def _check_stream_with_fickling(self, file_handle) -> Dict[str, Any]:
        """
        Check a file stream using fickling.
        
        Args:
            file_handle: File handle to check
            
        Returns:
            Dictionary with safety results from fickling
        """
        with fickling.check_safety():
            try:
                fickling.load(file_handle)
                # If no exception, file is safe - no raw output from fickling
                return {"safe": True}
            except fickling.exception.UnsafeFileError as e:
                # Process and filter findings
                if hasattr(e, 'info') and e.info:
                    result = e.info.copy()
                else:
                    result = {"analysis": str(e), "severity": "LIKELY_UNSAFE"}

                # Split and filter findings
                result = self._process_fickling_result(result)

                return result

    def _process_fickling_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process fickling result: filter trusted modules, aggregate findings, split by type.

        Stores processed findings in result['split_findings'] for to_issues() to use.
        """
        analysis = result.get('analysis', '')
        detailed_results = result.get('detailed_results', {})
        analysis_result = detailed_results.get('AnalysisResult', {})

        # Split analysis by lines and filter/aggregate
        findings = [line.strip() for line in analysis.split('\n') if line.strip()]

        # Filter trusted modules and aggregate
        import_by_module = {}
        assigned_by_func = {}
        other_findings = set()

        for finding in findings:
            if self.is_trusted_module_issue(finding):
                continue

            # Categorize
            if finding.startswith('`from ') and ' import ' in finding:
                try:
                    module = finding.split('`from ')[1].split(' import ')[0]
                    if module not in import_by_module:
                        import_by_module[module] = []
                    import_by_module[module].append(finding)
                except (IndexError, AttributeError):
                    other_findings.add(finding)
            elif 'is assigned value `' in finding and '(...)`' in finding:
                try:
                    func = finding.split('is assigned value `')[1].split('(...)`')[0]
                    if func not in assigned_by_func:
                        assigned_by_func[func] = {'finding': finding, 'count': 0}
                    assigned_by_func[func]['count'] += 1
                except (IndexError, AttributeError):
                    other_findings.add(finding)
            else:
                other_findings.add(finding)

        # Build filtered analysis
        filtered_findings = []
        for module, imports in import_by_module.items():
            if len(imports) == 1:
                filtered_findings.append(imports[0])
            else:
                filtered_findings.append(f"{imports[0]} ({len(imports)} imports from this module)")

        for func, data in assigned_by_func.items():
            if data['count'] == 1:
                filtered_findings.append(data['finding'])
            else:
                filtered_findings.append(f"{data['finding']} ({data['count']} occurrences)")

        filtered_findings.extend(sorted(other_findings))

        # Update result
        result['analysis'] = '\n'.join(filtered_findings) if filtered_findings else ''
        result['safe'] = not bool(filtered_findings)

        # Store split findings by type for to_issues()
        result['split_findings'] = self._split_findings_by_type(analysis_result, filtered_findings)

        return result

    def _split_findings_by_type(self, analysis_result: Dict[str, Any], filtered_lines: List[str]) -> List[Dict[str, Any]]:
        """Split findings into separate dicts by type for to_issues()."""
        findings = []

        finding_configs = {
            "UnsafeImports": {"title_suffix": "Unsafe imports", "severity": "CRITICAL"},
            "UnsafeImportsML": {"title_suffix": "Unsafe ML-specific imports", "severity": "CRITICAL"},
            "NonStandardImports": {"title_suffix": "Non-standard imports", "severity": "HIGH"},
            "UnusedVariables": {"title_suffix": "Suspicious unused code", "severity": "HIGH"},
            "OvertlyBadEvals": {"title_suffix": "Eval injection", "severity": "CRITICAL"},
            "BadCalls": {"title_suffix": "Dangerous function calls", "severity": "CRITICAL"},
        }

        for finding_type, config in finding_configs.items():
            if finding_type in analysis_result:
                result_value = analysis_result[finding_type]

                # Skip if from trusted module
                if isinstance(result_value, str) and 'from ' in result_value and ' import ' in result_value:
                    try:
                        module_name = result_value.split('from ')[1].split(' import ')[0].strip()
                        if self.is_trusted_module_issue(module_name):
                            continue
                    except (IndexError, AttributeError):
                        pass

                # Extract description from filtered lines
                description = self._extract_lines_matching(filtered_lines, result_value)

                if description:
                    findings.append({
                        'title_suffix': config['title_suffix'],
                        'description': description,
                        'severity': config['severity']
                    })

        return findings

    def _extract_lines_matching(self, lines: List[str], result_value: Any) -> str:
        """Extract lines matching the result value."""
        search_terms = []
        if isinstance(result_value, list):
            for item in result_value:
                if isinstance(item, (list, tuple)):
                    search_terms.extend(item)
                else:
                    search_terms.append(item)
        elif isinstance(result_value, tuple):
            search_terms = list(result_value)
        else:
            search_terms = [result_value]

        relevant_lines = []
        for line in lines:
            for term in search_terms:
                if str(term) in line:
                    relevant_lines.append(line)
                    break

        return '\n'.join(relevant_lines) if relevant_lines else str(result_value)

    def _check_archive_safety(self, archive_path: str, archive_type: str) -> Dict[str, Any]:
        """
        Check safety of archive contents using streaming to handle large files.
        
        Args:
            archive_path: Path to archive file
            archive_type: Type of archive ('zip' or 'tar')
            
        Returns:
            Aggregated safety result for the archive
        """
        overall_safe = True
        archive_results = []
        
        try:
            if archive_type == 'zip':
                with zipfile.ZipFile(archive_path, 'r') as zf:
                    for name in zf.namelist():
                        # Check ALL files in archives, not just those with known extensions
                        # Attackers may use pickle files without proper extensions
                        try:
                            with zf.open(name) as f:
                                result = self._check_stream_with_fickling(f)
                                if result and not result.get("safe", False):
                                    # Store member name for reference
                                    result["member"] = name
                                    overall_safe = False
                                    archive_results.append(result)
                        except Exception as e:
                            logger.debug(f"Could not check {name} in archive: {e}")
                            
            elif archive_type == 'tar':
                with tarfile.open(archive_path, 'r') as tf:
                    for member in tf.getmembers():
                        if member.isfile():
                            # Check ALL files in archives, not just those with known extensions
                            # Attackers may use pickle files without proper extensions
                            try:
                                # Use context manager for tar file extraction
                                with tf.extractfile(member) as f:
                                    if f:
                                        result = self._check_stream_with_fickling(f)
                                        if result and not result.get("safe", False):
                                            # Store member name for reference
                                            result["member"] = member.name
                                            overall_safe = False
                                            archive_results.append(result)
                            except Exception as e:
                                logger.debug(f"Could not check {member.name} in archive: {e}")
                                
        except Exception as e:
            logger.warning(f"Error checking {archive_type.upper()} archive {archive_path}: {e}")
            return {"error": str(e), "safe": False}
        
        # For archives, return aggregated raw outputs from fickling
        if archive_results:
            # Archive with unsafe members - return the raw results
            return {
                "unsafe_members": archive_results,
                "safe": False,
                "is_archive": True,
                "archive_type": archive_type
            }
        else:
            # Safe archive or no pickle content
            return {
                "safe": True,
                "is_archive": True,
                "archive_type": archive_type
            }
    
    
    def _find_all_files(self, path: str) -> List[str]:
        """
        Find all files recursively. Let fickling decide what's scannable.
        
        Args:
            path: Directory or file path to search
        Returns:
            List of all file paths
        """
        if not os.path.exists(path):
            return []

        if os.path.isfile(path):
            return [path]

        all_files: List[str] = []
        dirs_to_visit: List[str] = [path]

        while dirs_to_visit:
            current_dir = dirs_to_visit.pop()
            try:
                with os.scandir(current_dir) as it:
                    for entry in it:
                        try:
                            if entry.is_file(follow_symlinks=False):
                                all_files.append(entry.path)
                            elif entry.is_dir(follow_symlinks=False):
                                dirs_to_visit.append(entry.path)
                        except OSError as e:
                            logger.debug(
                                f"Could not access {getattr(entry, 'path', str(entry))}: {e}"
                            )
            except OSError as e:
                logger.debug(
                    f"Could not scan directory {current_dir}: {e}"
                )

        return all_files