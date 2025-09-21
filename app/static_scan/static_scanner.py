import uuid
import httpx
import os
import zipfile
import tempfile
import datetime
import logging

from typing import Callable
from models import StaticScanInitiationRequest, ModelArtifact, ModelMetadata, StaticScanResult, Issue, ValidationResult, \
        TrivyScanningResult, IssueType, Verdict, Severity, ScannerType, Affected, AffectedType, LicensesScanningResult, \
        LicenseWithClassification, RiskLevel, License
from .validation.validator import Validator
from .scanners.trivy_scanner import TrivyScanner
from .scanners.pypi_license_scanner import PypiLicenseScanner
from .classifiers.license_classifier import LicenseClassifier

logger = logging.getLogger(__name__)

class StaticScanner:

    @staticmethod
    def _download_and_extract_zip(download_url: str, temp_dir: str):
        """
        Downloads a ZIP from `url`, extracts into `temp_dir`, and returns the path.
        """
        run_id = uuid.uuid4()
        zip_path = os.path.join(temp_dir, f"{run_id}.zip")

        # Download file
        with httpx.stream("GET", download_url) as response:
            response.raise_for_status()
            with open(zip_path, "wb") as f:
                for chunk in response.iter_bytes():
                    f.write(chunk)

        # Extract the zip contents
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(temp_dir)

        # Remove the original zip file
        os.remove(zip_path)

    def _create_issues(self, validation_result: ValidationResult, trivy_scanning_result: TrivyScanningResult, licenses_classifications: list[LicenseWithClassification]) -> list[Issue]:
        issues = []
        # Create vulnerabilities issues
        for vulnerability in trivy_scanning_result.vulnerabilities:
            vulnerability_issue = Issue(id=vulnerability.id, affected=vulnerability.affected,
                                         type=IssueType.VULNERABILITY, title=vulnerability.title, description=vulnerability.description, severity=vulnerability.severity,
                                        cvss=vulnerability.cvss, recommendation="", references=vulnerability.references, detected_by=vulnerability.detected_by, detected_at=vulnerability.detect_at)
            issues.append(vulnerability_issue)


        # Check if model is tampered
        if validation_result.verdict == Verdict.TAMPERED:
            tampered_issue = Issue(id=str(uuid.uuid4()), affected=[Affected(kind=AffectedType.FILE, ref=file_path) for file_path in validation_result.changed_files],
                                   type=IssueType.TAMPER, title='Unexpected file created', description="New files appeared during the scan", severity=Severity.MEDIUM,
                                   cvss={}, recommendation="Quarantine artifact; re-run in stricter sandbox", references=[], detected_by=ScannerType.MODEL_TOTAL, detected_at=validation_result.validated_at)
            issues.append(tampered_issue)

        for license_classification in licenses_classifications:
            if license_classification.risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH]:
                severity = Severity.HIGH if license_classification.risk_level == RiskLevel.HIGH else Severity.MEDIUM
                license_issue = Issue(
                    id=f"iss-lic-{str(uuid.uuid4())[:8]}",
                    affected=[Affected(
                        kind=AffectedType.PACKAGE, 
                        ref=f"pkg:pypi/{license_classification.license.package.name}@{license_classification.license.package.version}",
                        version=license_classification.license.package.version
                    )],
                    type=IssueType.LICENSE,
                    title=f"{license_classification.license.name} flagged",
                    description=f"{license_classification.license.name} obligations may affect distribution of {license_classification.license.package.name}",
                    severity=severity,
                    cvss={},
                    recommendation="Replace with a permissive alternative" if license_classification.risk_level == RiskLevel.HIGH else "Review license obligations",
                    references=[f"https://spdx.org/licenses/{license_classification.license.name}.html"] if license_classification.license.name != "Unknown" else [],
                    detected_by=ScannerType.MODEL_TOTAL,
                    detected_at=datetime.datetime.now()
                )
                issues.append(license_issue)
        
        return issues
    
    def _classify_licenses(self, licenses_scanning_result: LicensesScanningResult) -> list[LicenseWithClassification]:
        license_classifier = LicenseClassifier()
        classifications = []
        for license in licenses_scanning_result.licenses:
            license_with_classification = license_classifier.classify_license(license)
            classifications.append(license_with_classification)

        return classifications
    
    def _enrich_sbom_with_licenses(self, sbom: dict, licenses: list[License]) -> dict:
        """
        Enrich SBOM with license information from license classifications.
        
        Args:
            sbom: The SBOM dictionary from Trivy
            licenses: List of licenses
            
        Returns:
            Enriched SBOM with license information
        """
        if not sbom or 'components' not in sbom:
            return sbom
            
        # Create a lookup map for licenses by package name
        license_map = {}
        for license in licenses:
            package_name = license.package.name
            license_map[package_name] = {
                'name': license.name,
            }
        
        # Enrich components with license information
        enriched_sbom = sbom.copy()
        for component in enriched_sbom.get('components', []):
            component_name = component.get('name')
            if component_name and component_name in license_map:
                license_info = license_map[component_name]
                component['licenses'] = [{
                    'license': {
                        'id': license_info['name'],
                    }
                }]
        return enriched_sbom
    
    def scan(self, request: StaticScanInitiationRequest, operation_id: str, progress_callback: Callable[[int], None]) -> StaticScanResult:
        generated_at = datetime.datetime.now()
        offline_mode = os.environ.get('OFFLINE_MODE', 'false').lower() == 'true'
        logger.info(f"Running scan task: {request}")
        progress_callback(0)
        
        validator = Validator(request.org_id)
        trivy_scanner = TrivyScanner(offline_mode=offline_mode)
        license_scanner = PypiLicenseScanner()
        model_metadata = ModelMetadata(model_id=request.model_id, model_name=request.model_name, model_version=request.model_version, model_metadata=request.model_metadata)

        with tempfile.TemporaryDirectory() as temp_dir:
            progress_callback(10)
            logger.info(f"Downloading & extracting file from: {request.model_url}")
            self._download_and_extract_zip(request.model_url, temp_dir)
            
            # temp_dir now holds our extracted model files
            model_artifact = ModelArtifact(metadata=model_metadata, folder_path=temp_dir)
            
            progress_callback(30)
            logger.info("Validating model artifact")
            validation_result = validator.validate(model_artifact)
            logger.info(f"Model validated, verdict: {validation_result.verdict}")

            progress_callback(40)
            logger.info(f"Scanning model artifact using Trivy")
            trivy_scanning_result = trivy_scanner.scan(temp_dir)
            logger.info(f"Model scanned for vulnerabilities/sbom, result: {trivy_scanning_result}")

            license_classifications = []
            sbom = trivy_scanning_result.sbom
            if not offline_mode:
                progress_callback(60)
                logger.info(f"Scanning model artifact using PypiLicenseScanner")
                license_scanning_result = license_scanner.scan(trivy_scanning_result.packages)
                logger.info(f"Model scanned for licenses, result: {license_scanning_result}")

                progress_callback(80)
                license_classifications = self._classify_licenses(license_scanning_result)
                logger.info(f"Model licenses classified: {license_classifications}")

                logger.info("Enriching SBOM with license information")
                sbom = self._enrich_sbom_with_licenses(sbom, license_scanning_result.licenses)
            else:
                logger.warning("Skipping license scanning because offline mode is enabled")
                
            progress_callback(90)
            issues = self._create_issues(validation_result, trivy_scanning_result, license_classifications)
            
            progress_callback(100)
            return StaticScanResult(operation_id=operation_id, issues=issues, s_bom=sbom, ml_bom={}, generated_at=generated_at).model_dump(mode='json')
