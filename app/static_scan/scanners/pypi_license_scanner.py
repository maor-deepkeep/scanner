import json
import logging
import re
import urllib.request
from typing import List

from models import LicensesScanningResult, License, Package, PackageManager

logger = logging.getLogger(__name__)

class PypiLicenseScanner:

    def __init__(self):
        pass

    def scan(self, packages: List[Package]) -> LicensesScanningResult:
        """
        Query PyPI for license information for the provided packages.
        
        Args:
            packages: List of Package objects to scan for licenses
            
        Returns:
            LicensesScanningResult with parsed licenses from PyPI
            
        Raises:
            Exception: If PyPI query fails
        """
        try:
            # Filter to only Python packages (pip)
            python_packages = [pkg for pkg in packages if pkg.package_manager == PackageManager.PIP]
            
            logger.info(f"Scanning {len(python_packages)} Python packages out of {len(packages)} total packages for license information")
            
            licenses = []
            
            for package in python_packages:
                logger.debug(f"Querying license for package: {package.name}@{package.version}")
                license_info = self._query_pypi_license(package.name)
                if license_info:
                    normalized_license = self._normalize_license_name(license_info)
                    license_obj = License(
                        name=normalized_license,
                        package=package,
                    )
                    licenses.append(license_obj)
            
            logger.info(f"Found licenses for {len(licenses)} packages")
            
            return LicensesScanningResult(licenses=licenses)
            
        except Exception as e:
            logger.error(f"PyPI license scan failed: {str(e)}")
            raise Exception(f"PyPI license scan failed: {str(e)}")


    def _query_pypi_license(self, package_name: str) -> str:
        """
        Query PyPI API for package license information.
        
        Args:
            package_name: Name of the package
            
        Returns:
            License string or None if not found
        """
        try:
            url = f"https://pypi.org/pypi/{package_name}/json"
            
            with urllib.request.urlopen(url, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))
                info = data.get('info', {})
                
                # Try to get license from info.license first
                license_info = info.get('license')
                if license_info and license_info.strip():
                    return license_info.strip()
                
                # Try to get from info.license_expression (newer PyPI field)
                license_expression = info.get('license_expression')
                if license_expression and license_expression.strip():
                    return license_expression.strip()
                
                # Try to get from classifiers
                classifiers = info.get('classifiers', [])
                for classifier in classifiers:
                    if classifier.startswith('License ::'):
                        # Extract license name from classifier
                        license_parts = classifier.split(' :: ')
                        if len(license_parts) >= 3:
                            return license_parts[-1]
                
                # If no license found, return "Unknown"
                return "Unknown"
                
        except Exception as e:
            logger.warning(f"Failed to query PyPI for package {package_name}: {str(e)}")
            return "Unknown"

    def _normalize_license_name(self, license_name: str) -> str:
        """
        Normalize license name for comparison.
        
        Args:
            license_name: Original license name
            
        Returns:
            Normalized license name
        """
        if not license_name:
            return ""
        
        # Strip whitespace but preserve case
        normalized = license_name.strip()
        
        # Remove common prefixes/suffixes (case insensitive)
        normalized = re.sub(r'^(the\s+|license\s*:?\s*)', '', normalized, flags=re.IGNORECASE)
        normalized = re.sub(r'\s*(license|licence)(\s+v?[\d.]+)?$', '', normalized, flags=re.IGNORECASE)
        
        # Replace common separators with hyphens
        normalized = re.sub(r'[\s_]+', '-', normalized)
        
        # Remove extra hyphens
        normalized = re.sub(r'-+', '-', normalized)
        normalized = normalized.strip('-')
        
        return normalized