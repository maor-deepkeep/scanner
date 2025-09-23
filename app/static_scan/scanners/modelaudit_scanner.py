import logging
import os
import time
from datetime import datetime
from typing import List, Any

try:
    from modelaudit.core import scan_model_directory_or_file
    MODELAUDIT_AVAILABLE = True
except ImportError:
    MODELAUDIT_AVAILABLE = False
    scan_model_directory_or_file = None

from app.models import (
    Issue, IssueType, Affected, AffectedType, TechnicalDetails,
    ModelAuditResult as BaseModelAuditResult, BaseScanner
)
from app.static_scan.exceptions import (
    ModelAuditError, ScannerNotAvailableError
)
from app.static_scan.common import normalize_severity, get_scanner_type

logger = logging.getLogger(__name__)


class ModelAuditResult(BaseModelAuditResult):
    """ModelAudit specific result with full to_issues() implementation."""

    def to_issues(self) -> List[Issue]:
        """
        Convert ModelAudit findings to standardized Issue objects.

        Returns:
            List of Issue objects
        """
        result_issues = []
        
        # Get issues from scanner_data
        issues = self.scanner_data.get('issues', [])

        for issue in issues:
            # Get severity - handle both dict and object formats
            if isinstance(issue, dict):
                severity = issue.get('severity', 'warning')
            else:
                severity = getattr(issue, 'severity', 'warning')
            
            # If it's an enum, use its value
            if hasattr(severity, 'value'):
                severity = severity.value
            else:
                severity = str(severity)

            # Skip debug-level issues (usually non-model files like .git/config)
            # These are not security issues, just files ModelAudit can't parse
            if severity.lower() == 'debug':
                continue

            # Map severity to Severity enum
            severity_enum = normalize_severity(severity, 'modelaudit')

            # Extract key fields - handle both dict and object formats
            if isinstance(issue, dict):
                message = issue.get('message', 'Security issue detected')
                location = issue.get('location', '')
                details = issue.get('details', {})
                why = issue.get('why', '')
                issue_type = issue.get('type', 'unknown')
            else:
                message = getattr(issue, 'message', 'Security issue detected')
                location = getattr(issue, 'location', '')
                details = getattr(issue, 'details', {})
                why = getattr(issue, 'why', '')
                issue_type = getattr(issue, 'type', 'unknown')

            # Create affected objects
            affected = []
            if location:
                affected.append(Affected(
                    kind=AffectedType.FILE,
                    ref=location
                ))

            # Create technical details
            tech_details = None
            if details or why or issue_type:
                tech_details_dict = {}
                if isinstance(details, dict):
                    tech_details_dict.update(details)
                    # Map opcode to operator for aggregation (if it exists)
                    if 'opcode' in details:
                        tech_details_dict['operator'] = details['opcode']
                if why:
                    tech_details_dict['why'] = why
                if issue_type:
                    tech_details_dict['type'] = issue_type
                tech_details = TechnicalDetails(**tech_details_dict)

            # Create the issue
            issue_obj = Issue(
                id=Issue.generate_id(IssueType.MALICIOUS_CODE),
                type=IssueType.MALICIOUS_CODE,
                title=message,
                description=why if why else message,
                severity=severity_enum,
                cvss={},
                affected=affected,
                technical_details=tech_details,
                recommendation=("Review and validate model file for "
                               "potential security risks"),
                references=[],
                detected_by=get_scanner_type(self.scanner_name),
                detected_at=datetime.now()
            )
            result_issues.append(issue_obj)

        return result_issues


class ModelAuditScanner(BaseScanner):
    """Scanner for model files using the modelaudit library."""

    def scan(self, path: str) -> ModelAuditResult:
        """
        Run modelaudit on the specified path and return parsed results.

        Args:
            path: File system path to scan

        Returns:
            ModelAuditResult with issues that can be converted to Issue objects
        """
        if not MODELAUDIT_AVAILABLE:
            logger.error("ModelAudit library not available")
            raise ScannerNotAvailableError(
                "ModelAudit", "Library not installed", None
            )

        try:
            logger.info(f"Running modelaudit on path: {path}")

            start_time = time.time()

            # First, collect all files that will be scanned
            files_scanned = self._find_all_files(path)
            logger.info(f"Found {len(files_scanned)} files to scan in {path}")

            # ModelAudit handles both files and directories
            try:
                audit_result = scan_model_directory_or_file(path)
                issues, affected_files = self._process_audit_result(audit_result, path)
            except Exception:
                logger.exception(f"Failed to audit path {path}")
                issues = []
                affected_files = []

            duration = time.time() - start_time

            logger.info(f"ModelAudit completed: {len(issues)} issues found")
            
            # Determine verdict
            verdict = "SUSPICIOUS" if issues else "SAFE"
            
            return ModelAuditResult(
                scanner_name=self.scanner_name,
                verdict=verdict,
                issues_count=len(issues),
                files_scanned=files_scanned,
                affected_files=affected_files,
                scanner_data={'issues': issues},
                scan_duration=duration,
                raw_output={}
            )

        except Exception as e:
            logger.exception("ModelAudit scan failed")
            raise ModelAuditError(f"Scan failed: {str(e)}", e) from e

    def _process_audit_result(self, audit_result: Any,
                              file_path: str) -> tuple[List[Any], List[str]]:
        """
        Process audit result from modelaudit and filter trusted modules.

        Args:
            audit_result: Result from modelaudit
            file_path: Path to the audited file

        Returns:
            Tuple of (filtered issues, affected files)
        """
        issues = []
        affected_files = []

        try:
            # ModelAudit returns result with .issues attribute
            if hasattr(audit_result, 'issues'):
                audit_issues = audit_result.issues
            elif isinstance(audit_result, (list, tuple)):
                # Direct list of issues
                audit_issues = audit_result
            elif isinstance(audit_result, dict) and 'issues' in audit_result:
                audit_issues = audit_result['issues']
            else:
                logger.warning(
                    f"Unknown audit result format: {type(audit_result)}"
                )
                audit_issues = []

            # Filter issues and collect affected files in one pass
            for issue in audit_issues:
                if not self._is_trusted_module_issue(issue):
                    issues.append(issue)
                    
                    # Extract location from issue - handle both dict and object formats
                    location = None
                    if isinstance(issue, dict):
                        location = issue.get('location')
                        # Also check details for path information
                        if not location:
                            details = issue.get('details', {})
                            if isinstance(details, dict):
                                location = details.get('path')
                    else:
                        location = getattr(issue, 'location', None)
                        # Also check details for path information
                        if not location:
                            details = getattr(issue, 'details', {})
                            if isinstance(details, dict):
                                location = details.get('path')
                    
                    if location and location not in affected_files:
                        affected_files.append(location)

        except Exception:
            logger.exception(f"Failed to process audit result for {file_path}")

        return issues, affected_files

    def _is_trusted_module_issue(self, issue: Any) -> bool:
        """
        Check if an issue is from a trusted module and should be filtered.

        Args:
            issue: Issue object from modelaudit

        Returns:
            True if the issue should be filtered, False otherwise
        """
        if not self.enable_trusted_filter:
            return False

        # Check if issue has a module field
        if hasattr(issue, 'module'):
            module = str(issue.module)
            if self.is_trusted_module_issue(module):
                return True

        # Check details for module information
        details = getattr(issue, 'details', {})
        if isinstance(details, dict) and 'module' in details:
            module = str(details['module'])
            if self.is_trusted_module_issue(module):
                return True

        return False
    
    def _find_all_files(self, path: str) -> List[str]:
        """
        Find all files in path using os.scandir for efficiency.
        
        Args:
            path: File or directory path to scan
            
        Returns:
            List of file paths found
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
                logger.debug(f"Could not scan directory {current_dir}: {e}")
        
        return all_files

