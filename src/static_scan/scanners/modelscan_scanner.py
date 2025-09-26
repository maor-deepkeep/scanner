import logging
import time
from datetime import datetime
from typing import List

try:
    from modelscan.modelscan import ModelScan
    from modelscan.settings import DEFAULT_SETTINGS
    from modelscan.issues import IssueSeverity
    MODELSCAN_AVAILABLE = True
except ImportError:
    MODELSCAN_AVAILABLE = False
    ModelScan = None
    DEFAULT_SETTINGS = None
    IssueSeverity = None

from src.models import (
    Issue, IssueType, Affected, AffectedType, TechnicalDetails, 
    ModelScanResult as BaseModelScanResult, BaseScanner
)
from src.static_scan.exceptions import (
    ModelScanError, ScannerNotAvailableError
)
from src.static_scan.common import normalize_severity, get_scanner_type

logger = logging.getLogger(__name__)


class ModelScanResult(BaseModelScanResult):
    """ModelScan specific result with issues and full to_issues() implementation."""
    
    def to_issues(self) -> List[Issue]:
        """
        Convert ModelScan findings to standardized Issue objects.

        Returns:
            List of Issue objects
        """
        result_issues = []
        
        # Get issues from scanner_data
        issues = self.scanner_data.get('issues', [])

        for issue_dict in issues:
            # Map severity string to Severity enum
            severity = normalize_severity(
                issue_dict.get('severity', 'MEDIUM'),
                'modelscan'
            )

            # Get raw details for technical details
            raw_details = issue_dict.get('raw_details', {})

            module = raw_details.get('module', '')
            operator = raw_details.get('operator', '')
            source = raw_details.get('source', '')

            # Use description as both title and description
            description = issue_dict.get(
                'description',
                f'Detected unsafe operator: {operator} from {module} '
                f'in {source}'
            )
            title = description

            # Create affected objects
            affected = []
            if raw_details.get('source'):
                affected.append(Affected(
                    kind=AffectedType.FILE,
                    ref=raw_details.get('source')
                ))

            # Create technical details with ALL raw details from scanner
            tech_details = None
            if raw_details:
                # Ensure module and operator exist for aggregation
                tech_details_dict = raw_details.copy()
                if 'module' not in tech_details_dict and module:
                    tech_details_dict['module'] = module
                if 'operator' not in tech_details_dict and operator:
                    tech_details_dict['operator'] = operator
                tech_details = TechnicalDetails(**tech_details_dict)

            issue = Issue(
                id=Issue.generate_id(IssueType.MALICIOUS_CODE),
                type=IssueType.MALICIOUS_CODE,
                title=title,
                description=description,
                severity=severity,
                cvss={},
                affected=affected,
                technical_details=tech_details,
                recommendation=("Review and validate model file for "
                               "potential security risks"),
                references=[],
                detected_by=get_scanner_type(self.scanner_name),
                detected_at=datetime.now()
            )
            result_issues.append(issue)

        return result_issues


class ModelScanScanner(BaseScanner):
    """Scanner for model files using the modelscan library."""

    def scan(self, path: str) -> ModelScanResult:
        """
        Run modelscan on the specified path and return parsed results.

        Args:
            path: File system path to scan

        Returns:
            ModelScanResult with issues that can be converted to Issue objects

        Raises:
            Exception: If modelscan fails or is not available
        """
        if not MODELSCAN_AVAILABLE:
            logger.error("Modelscan library not available")
            raise ScannerNotAvailableError(
                "ModelScan", "Library not installed", None
            )

        start_time = time.time()

        try:
            logger.info(f"Running modelscan on path: {path}")

            # Initialize ModelScan with settings
            ms = ModelScan(settings=DEFAULT_SETTINGS)

            # Run scan
            scan_results = ms.scan(path)

            # Convert results
            issues = []
            files_scanned = []
            verdict = "SAFE"

            # Process scan results - scan_results is a dictionary
            if isinstance(scan_results, dict) and 'issues' in scan_results:
                issues_list = scan_results.get('issues', [])
                if not isinstance(issues_list, list):
                    logger.warning(
                        f"Unexpected issues format: {type(issues_list)}"
                    )
                    issues_list = []

                for issue in issues_list:
                    if not isinstance(issue, dict):
                        logger.warning(
                            f"Skipping non-dict issue: {type(issue)}"
                        )
                        continue

                    issue_dict = {}

                    # Pass severity through as-is
                    issue_dict['severity'] = issue.get('severity', 'MEDIUM')

                    # Use description directly
                    issue_dict['description'] = issue.get(
                        'description', 'Security issue detected'
                    )

                    # Store all issue fields as raw details
                    issue_dict['raw_details'] = issue

                    issues.append(issue_dict)
                    verdict = "SUSPICIOUS"

            # Get scanned files from summary
            if isinstance(scan_results, dict) and 'summary' in scan_results:
                summary = scan_results.get('summary', {})
                if ('scanned' in summary and
                        'scanned_files' in summary['scanned']):
                    files_scanned = summary['scanned']['scanned_files']

            duration = time.time() - start_time
            logger.info(
                f"Modelscan completed: {len(issues)} issues found, "
                f"{len(files_scanned)} files scanned"
            )

            # Extract affected files from issues if possible
            affected_files = []
            for issue_dict in issues:
                if 'raw_details' in issue_dict:
                    source = issue_dict['raw_details'].get('source')
                    if source and source not in affected_files:
                        affected_files.append(source)
            
            return ModelScanResult(
                scanner_name=self.scanner_name,
                verdict=verdict,
                issues_count=len(issues),
                files_scanned=files_scanned,
                affected_files=affected_files,
                scanner_data={'issues': issues},  # Store for to_issues()
                scan_duration=duration,
                raw_output=(scan_results if isinstance(scan_results, dict)
                           else {})
            )

        except Exception as e:
            logger.exception("Modelscan scan failed")
            raise ModelScanError(f"Scan failed: {str(e)}", e) from e