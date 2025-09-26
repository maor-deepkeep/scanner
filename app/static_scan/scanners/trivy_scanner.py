
import json
import subprocess
import logging
import datetime
import os

from app.models import TrivyScanningResult, Vulnerability, Package, PackageManager, ScannerType, Severity, Affected, AffectedType

logger = logging.getLogger(__name__)

class TrivyScanner:

    def __init__(self, offline_mode=False):
        self._offline_mode = offline_mode

    def scan(self, path: str) -> TrivyScanningResult:
        """
        Run Trivy scanner on the specified path and return parsed results.
        
        Args:
            path: File system path to scan
            
        Returns:
            TrivyScanningResult with parsed vulnerabilities and packages
            
        Raises:
            subprocess.CalledProcessError: If Trivy scan fails
            json.JSONDecodeError: If Trivy output is not valid JSON
        """
        try:
            scanning_time = datetime.datetime.now()
            
            # Get Trivy cache directory from environment variable
            cache_dir = os.getenv('TRIVY_CACHE_DIR')

            logger.info(f"Running trivy, offline_mode={self._offline_mode}")

            scan_vulnerabilities_command = [
                'trivy',
                'fs',
                '--cache-dir', cache_dir,
                '--format', 'json',
                '--scanners', 'vuln',
                '--quiet',
                path
            ]

            generate_sbom_command = [
                'trivy',
                'fs',
                '--cache-dir', cache_dir,
                '--format', 'cyclonedx',
                '--quiet',
                path
            ]

            if self._offline_mode:
                scan_vulnerabilities_command.append('--skip-db-update')
                generate_sbom_command.append('--skip-db-update')

            # Run Trivy with JSON output format for vulnerabilities
            logger.info(f"Running Trivy vulnerability scan with command: {' '.join(scan_vulnerabilities_command[:6])}...")
            vuln_result = subprocess.run(scan_vulnerabilities_command, capture_output=True, text=True, check=True)
            logger.info(f"Trivy vulnerability scan completed, output size: {len(vuln_result.stdout)} bytes")
            
            # Run Trivy for SBOM generation
            logger.info(f"Running Trivy SBOM generation with command: {' '.join(generate_sbom_command[:6])}...")
            sbom_result = subprocess.run(generate_sbom_command, capture_output=True, text=True, check=True)
            logger.info(f"Trivy SBOM generation completed, output size: {len(sbom_result.stdout)} bytes")
            
            # Parse JSON results
            logger.info("Parsing Trivy JSON results...")
            try:
                trivy_output = json.loads(vuln_result.stdout)
                sbom_output = json.loads(sbom_result.stdout)
                logger.info("Successfully parsed Trivy JSON results")
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Trivy output: {e}")
                logger.error(f"Vuln stdout preview: {vuln_result.stdout[:500]}")
                logger.error(f"SBOM stdout preview: {sbom_result.stdout[:500]}")
                raise

            # Log summary instead of full output
            vuln_count = 0
            if 'Results' in trivy_output:
                for result in trivy_output.get('Results', []):
                    vuln_count += len(result.get('Vulnerabilities', []))
            
            component_count = len(sbom_output.get('components', []))
            
            logger.info(f"Trivy scan completed: found {vuln_count} vulnerabilities")
            logger.info(f"Trivy SBOM generated: {component_count} components")
            logger.debug(f"Trivy output size: vuln={len(vuln_result.stdout)} bytes, sbom={len(sbom_result.stdout)} bytes")
            
            # Extract vulnerabilities from Trivy output
            vulnerabilities = []
            
            if 'Results' in trivy_output:
                for result_item in trivy_output['Results']:
                    # Parse vulnerabilities
                    if 'Vulnerabilities' in result_item:
                        for vuln in result_item['Vulnerabilities']:
                            vulnerability = Vulnerability(
                                id=vuln.get('VulnerabilityID', ''),
                                affected=[Affected(kind=AffectedType.PACKAGE, ref=vuln.get('PkgIdentifier', {}).get('PURL', ''), version=vuln.get('InstalledVersion'))],
                                detect_at=scanning_time,
                                detected_by=ScannerType.TRIVY,
                                title=vuln.get('Title', ''),
                                description=vuln.get('Description', ''),
                                severity=Severity[vuln.get('Severity', 'NONE')],
                                references=vuln.get('References', []),
                                cvss=vuln.get('CVSS', {})
                            )
                            vulnerabilities.append(vulnerability)
            
            # Extract packages from SBOM
            packages = []
            if 'components' in sbom_output:
                for component in sbom_output['components']:
                    component_name = component.get('name', '')
                    component_version = component.get('version', '')
                    if component_name and component_version:
                        # Detect package manager from component type or purl
                        package_manager = self._detect_package_manager(component)
                        package = Package(
                            name=component_name, 
                            version=component_version,
                            package_manager=package_manager
                        )
                        packages.append(package)
                
            logger.info(f"Found {len(vulnerabilities)} vulnerabilities and {len(packages)} packages")
            
            # Enrich SBOM with vulnerability information
            enriched_sbom = self._enrich_sbom_with_vulnerabilities(sbom_output, vulnerabilities)
            
            return TrivyScanningResult(vulnerabilities=vulnerabilities, packages=packages, sbom=enriched_sbom)
            
        except subprocess.CalledProcessError as e:
            raise subprocess.CalledProcessError(
                e.returncode, 
                e.cmd, 
                f"Trivy scan failed: {e.stderr}"
            )
        except json.JSONDecodeError as e:
            raise json.JSONDecodeError(
                f"Failed to parse Trivy output as JSON: {e.msg}",
                e.doc,
                e.pos
            )

    def _detect_package_manager(self, component: dict) -> PackageManager:
        """
        Detect package manager from SBOM component information.
        
        Args:
            component: SBOM component dictionary
            
        Returns:
            PackageManager enum value
        """
        # Check purl (Package URL) for package manager type
        purl = component.get('purl', '')
        if purl:
            if 'pkg:pypi/' in purl:
                return PackageManager.PIP
        
        # Check component type
        component_type = component.get('type', '')
        if component_type == 'library':
            # Additional heuristics based on name patterns or other properties
            name = component.get('name', '').lower()
            if any(python_indicator in name for python_indicator in ['python', 'py-']):
                return PackageManager.PIP
        
        return PackageManager.UNKNOWN

    def _enrich_sbom_with_vulnerabilities(self, sbom: dict, vulnerabilities: list) -> dict:
        """
        Enrich SBOM with vulnerability information in CycloneDX format.
        
        Args:
            sbom: Original SBOM dictionary
            vulnerabilities: List of Vulnerability objects
            
        Returns:
            Enriched SBOM with vulnerabilities section
        """
        if not vulnerabilities:
            return sbom
        
        # Create a mapping from component purl to bom-ref for vulnerability references
        component_purl_to_ref = {}
        if 'components' in sbom:
            for component in sbom['components']:
                purl = component.get('purl', '')
                bom_ref = component.get('bom-ref', '')
                if purl and bom_ref:
                    component_purl_to_ref[purl] = bom_ref
        
        # Convert vulnerabilities to CycloneDX format
        cyclone_vulns = []
        for vuln in vulnerabilities:
            # Find matching component reference from affected packages
            component_ref = None
            for affected in vuln.affected:
                if affected.kind == AffectedType.PACKAGE and affected.ref:
                    component_ref = component_purl_to_ref.get(affected.ref)
                    if component_ref:
                        break
            
            # Map severity to CycloneDX format
            severity_mapping = {
                Severity.NONE: "none",
                Severity.LOW: "low", 
                Severity.MEDIUM: "medium",
                Severity.HIGH: "high",
                Severity.CRITICAL: "critical"
            }
            
            cyclone_vuln = {
                "id": vuln.id,
                "description": vuln.description or vuln.title,
                "ratings": [{
                    "severity": severity_mapping.get(vuln.severity, "none"),
                    "method": "other"
                }]
            }
            
            # Add component reference if found
            if component_ref:
                cyclone_vuln["affects"] = [{"ref": component_ref}]
            
            # Add CVSS information if available
            if vuln.cvss:
                cvss_rating = {
                    "method": "CVSSv3" if "V3" in str(vuln.cvss) else "CVSSv2"
                }
                if isinstance(vuln.cvss, dict):
                    for key, value in vuln.cvss.items():
                        if key.lower() in ['score', 'basescore']:
                            cvss_rating["score"] = float(value) if value else 0.0
                            break
                cyclone_vuln["ratings"].append(cvss_rating)
            
            # Add references
            if vuln.references:
                cyclone_vuln["advisories"] = [{"url": ref} for ref in vuln.references if ref]
            
            cyclone_vulns.append(cyclone_vuln)
        
        # Add vulnerabilities to SBOM
        enriched_sbom = sbom.copy()
        enriched_sbom["vulnerabilities"] = cyclone_vulns
        
        logger.info(f"Enriched SBOM with {len(cyclone_vulns)} vulnerabilities")
        
        return enriched_sbom