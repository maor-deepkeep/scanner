"""
Common utilities and shared functionality for static scanning.

This module contains shared utilities used across different scanners,
including severity normalization, issue aggregation, and other helpers.
"""

import logging
from typing import List
from collections import defaultdict
from src.models import (
    Issue, Severity, ScannerType, AffectedType, TechnicalDetails
)

logger = logging.getLogger(__name__)


# Severity normalization mappings for different scanners
SEVERITY_MAPPINGS = {
    'modelscan': {
        'LOW': Severity.LOW,
        'MEDIUM': Severity.MEDIUM,
        'HIGH': Severity.HIGH,
        'CRITICAL': Severity.CRITICAL
    },
    'picklescan': {
        'INNOCUOUS': Severity.LOW,
        'SUSPICIOUS': Severity.MEDIUM,
        'DANGEROUS': Severity.CRITICAL
    },
    'fickling': {
        'LIKELY_SAFE': Severity.LOW,
        'POSSIBLY_UNSAFE': Severity.MEDIUM,
        'SUSPICIOUS': Severity.MEDIUM,
        'LIKELY_UNSAFE': Severity.HIGH,
        'LIKELY_OVERTLY_MALICIOUS': Severity.CRITICAL,
        'OVERTLY_MALICIOUS': Severity.CRITICAL
    },
    'modelaudit': {
        'DEBUG': Severity.LOW,  # Actually filtered out in scanner
        'INFO': Severity.MEDIUM,
        'WARNING': Severity.HIGH,
        'CRITICAL': Severity.CRITICAL
    }
}


def normalize_severity(value: str, scanner: str) -> Severity:
    """
    Normalize severity from scanner-specific format to common Severity enum.

    Args:
        value: Scanner-specific severity value
        scanner: Name of the scanner (e.g., 'modelscan', 'picklescan')

    Returns:
        Normalized Severity enum value
    """
    if not value:
        return Severity.MEDIUM

    mapping = SEVERITY_MAPPINGS.get(scanner.lower(), {})
    return mapping.get(value.upper(), Severity.MEDIUM)


def aggregate_issues(issues: List[Issue]) -> List[Issue]:
    """
    Intelligently aggregate similar issues to reduce duplication.

    Groups issues by:
    1. Module + Operator (if available in technical_details)
    2. Title + Description (fallback for issues without module+operator)

    Aggregates:
    - Multiple files into affected list
    - Multiple scanners into detected_by list
    - Merges technical details
    - Uses highest severity
    - Prioritizes title/description by scanner preference

    Args:
        issues: List of Issue objects to aggregate

    Returns:
        List of aggregated Issue objects
    """
    if not issues:
        return []

    # Scanner priority for title/description selection
    scanner_priority = {
        ScannerType.MODELSCAN: 1,
        ScannerType.MODELAUDIT: 2,
        ScannerType.PICKLESCAN: 3,
        ScannerType.FICKLING: 4
    }

    # Group issues - prefer module+operator if available,
    # otherwise title+description
    groups = defaultdict(list)

    for issue in issues:
        # Try to group by module + operator first
        key = None
        if issue.technical_details:
            module = getattr(issue.technical_details, 'module', None)
            operator = getattr(issue.technical_details, 'operator', None)
            if module and operator:
                key = ('module_op', module, operator)

        # Fallback to title + description
        if not key:
            key = ('title_desc', issue.title, issue.description)

        groups[key].append(issue)

    # Process each group
    aggregated_issues = []
    severity_order = {
        Severity.CRITICAL: 4,
        Severity.HIGH: 3,
        Severity.MEDIUM: 2,
        Severity.LOW: 1
    }

    for key, group_issues in groups.items():
        if not group_issues:
            continue

        # Sort issues by scanner priority to choose best title/description
        def _scanner_rank(issue: Issue) -> int:
            """Return priority rank for an issue's primary scanner."""
            detected = issue.detected_by
            primary = (
                detected[0] if isinstance(detected, list) and detected
                else detected
            )
            return scanner_priority.get(primary, 999)

        sorted_by_priority = sorted(group_issues, key=_scanner_rank)
        base_issue = sorted_by_priority[0]

        # Collect all unique scanners
        scanners = []
        seen_scanners = set()
        for issue in group_issues:
            if isinstance(issue.detected_by, list):
                for scanner in issue.detected_by:
                    if scanner not in seen_scanners:
                        scanners.append(scanner)
                        seen_scanners.add(scanner)
            else:
                if issue.detected_by not in seen_scanners:
                    scanners.append(issue.detected_by)
                    seen_scanners.add(issue.detected_by)

        # Collect all unique affected files
        # (preserving location info when available)
        affected_map = {}  # ref -> Affected object
        for issue in group_issues:
            for affected in issue.affected:
                if affected.kind == AffectedType.FILE:
                    # If we haven't seen this file, or if this one has
                    # location info and the existing doesn't
                    if (affected.ref not in affected_map or
                            (affected.location and
                             not affected_map[affected.ref].location)):
                        affected_map[affected.ref] = affected

        # Merge technical details from all issues
        merged_tech_details = {}
        for issue in group_issues:
            if issue.technical_details:
                tech_dict = issue.technical_details.model_dump(
                    exclude_none=True
                )
                for key, value in tech_dict.items():
                    if key not in merged_tech_details:
                        merged_tech_details[key] = value

        # Find highest severity
        highest_severity = max(
            (issue.severity for issue in group_issues),
            key=lambda s: severity_order.get(s, 0)
        )

        # Update the base issue with aggregated data
        base_issue.detected_by = scanners if len(scanners) > 1 else scanners[0]
        base_issue.severity = highest_severity
        base_issue.occurrences = len(group_issues)  # Count how many issues were aggregated
        
        # If multiple occurrences, update title to show count
        if len(group_issues) > 1:
            base_issue.title = f"{base_issue.title} ({len(group_issues)} occurrences)"

        if affected_map:
            # Sort by ref for consistent ordering
            base_issue.affected = [
                affected for _, affected in sorted(affected_map.items())
            ]

        if merged_tech_details:
            base_issue.technical_details = TechnicalDetails(
                **merged_tech_details
            )

        aggregated_issues.append(base_issue)

    # Sort by severity (highest first) and then by title
    aggregated_issues.sort(
        key=lambda x: (-severity_order.get(x.severity, 0), x.title)
    )

    logger.info(
        f"Aggregated {len(issues)} issues into "
        f"{len(aggregated_issues)} unique issues"
    )

    return aggregated_issues


def get_scanner_type(scanner_name: str) -> ScannerType:
    """
    Map scanner name to ScannerType enum.

    Args:
        scanner_name: Name of the scanner

    Returns:
        Corresponding ScannerType enum value
    """
    scanner_map = {
        'modelscan': ScannerType.MODELSCAN,
        'picklescan': ScannerType.PICKLESCAN,
        'fickling': ScannerType.FICKLING,
        'modelaudit': ScannerType.MODELAUDIT,
        'trivy': ScannerType.TRIVY,
        'model_total': ScannerType.MODEL_TOTAL
    }
    return scanner_map.get(scanner_name.lower(), ScannerType.MODEL_TOTAL)
