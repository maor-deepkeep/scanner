"""Unit tests for PypiLicenseScanner."""
import pytest
import tempfile
import os
import sys
import json
from unittest.mock import patch, MagicMock
from pathlib import Path
import urllib.error

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.static_scan.scanners.pypi_license_scanner import PypiLicenseScanner
from app.models import Package, PackageManager, LicensesScanningResult


class TestPypiLicenseScanner:
    """Unit tests for PyPI License scanner."""
    
    @pytest.fixture
    def scanner(self):
        """Create scanner instance."""
        return PypiLicenseScanner()
    
    @pytest.fixture
    def python_packages(self):
        """Create test Package objects for Python packages."""
        return [
            Package(
                name="django",
                version="2.2.0",
                package_manager=PackageManager.PIP
            ),
            Package(
                name="flask",
                version="2.3.2",
                package_manager=PackageManager.PIP
            ),
            Package(
                name="requests",
                version="2.31.0",
                package_manager=PackageManager.PIP
            ),
        ]
    
    @pytest.fixture
    def mixed_packages(self):
        """Create Package objects with mixed package managers."""
        return [
            Package(
                name="django",
                version="2.2.0",
                package_manager=PackageManager.PIP
            ),
            Package(
                name="express",
                version="4.18.0",
                package_manager=PackageManager.UNKNOWN
            ),
            Package(
                name="spring-core",
                version="5.3.0",
                package_manager=PackageManager.UNKNOWN
            ),
        ]
    
    # ===== REAL API TESTS (with actual PyPI queries) =====
    
    def test_real_pypi_query_common_packages(self, scanner):
        """Test actual PyPI API queries for common packages."""
        # Use well-known packages that should always exist on PyPI
        packages = [
            Package(name="requests", version="2.31.0", package_manager=PackageManager.PIP),
            Package(name="numpy", version="1.24.0", package_manager=PackageManager.PIP),
        ]
        
        result = scanner.scan(packages)
        
        # Should get real licenses from PyPI
        assert len(result.licenses) == 2
        
        # Check that we got actual license data
        for license in result.licenses:
            assert license.name is not None
            assert len(license.name) > 0
            # Common packages should have known licenses
            assert any(lic in license.name.upper() for lic in ['APACHE', 'MIT', 'BSD', 'LICENSE'])
    
    def test_real_pypi_query_nonexistent_package(self, scanner):
        """Test handling of packages that don't exist on PyPI."""
        packages = [
            Package(name="this-package-definitely-does-not-exist-12345", version="0.0.0", package_manager=PackageManager.PIP),
        ]
        
        # Should handle gracefully by returning "Unknown" license
        result = scanner.scan(packages)
        
        # Should return "Unknown" license for non-existent package
        assert len(result.licenses) == 1
        assert result.licenses[0].name == "Unknown"
    
    @patch('urllib.request.urlopen')
    def test_pypi_api_timeout(self, mock_urlopen, scanner):
        """Test handling of PyPI API timeouts."""
        # Simulate timeout
        mock_urlopen.side_effect = urllib.error.URLError("timeout")
        
        packages = [
            Package(name="requests", version="2.31.0", package_manager=PackageManager.PIP),
        ]
        
        # Should handle timeout gracefully by returning "Unknown"
        result = scanner.scan(packages)
        assert len(result.licenses) == 1
        assert result.licenses[0].name == "Unknown"
    
    @patch('urllib.request.urlopen')
    def test_pypi_api_malformed_response(self, mock_urlopen, scanner):
        """Test handling of malformed PyPI API responses."""
        # Mock malformed JSON response
        mock_response = MagicMock()
        mock_response.read.return_value = b"not valid json{{"
        mock_urlopen.return_value.__enter__.return_value = mock_response
        
        packages = [
            Package(name="requests", version="2.31.0", package_manager=PackageManager.PIP),
        ]
        
        # Should handle malformed response gracefully by returning "Unknown"
        result = scanner.scan(packages)
        assert len(result.licenses) == 1
        assert result.licenses[0].name == "Unknown"
    
    # ===== MOCKED TESTS (for specific license scenarios) =====
    
    @patch('app.static_scan.scanners.pypi_license_scanner.PypiLicenseScanner._query_pypi_license')
    def test_scan_gpl_licenses(self, mock_query, scanner):
        """Test detection of GPL-licensed packages."""
        # Mock PyPI responses for GPL packages
        mock_query.side_effect = ["GPL-3.0", "GPL-2.0", "GPLv3"]
        
        packages = [
            Package(name="PyGTK", version="2.24.0", package_manager=PackageManager.PIP),
            Package(name="mysql-connector-python", version="8.0.33", package_manager=PackageManager.PIP),
            Package(name="pyqt5", version="5.15.9", package_manager=PackageManager.PIP),
        ]
        
        result = scanner.scan(packages)
        
        # Should detect GPL licenses
        assert len(result.licenses) == 3
        assert all('GPL' in license.name for license in result.licenses)
    
    @patch('app.static_scan.scanners.pypi_license_scanner.PypiLicenseScanner._query_pypi_license')
    def test_scan_mixed_licenses(self, mock_query, scanner, mixed_packages):
        """Test scanning of mixed license types."""
        # Mock different license types
        mock_query.return_value = "BSD-3-Clause"
        
        result = scanner.scan(mixed_packages)
        
        # Should only scan Python packages
        assert len(result.licenses) == 1  # Only django (pip package)
        assert result.licenses[0].package.name == "django"
    
    @patch('app.static_scan.scanners.pypi_license_scanner.PypiLicenseScanner._query_pypi_license')
    def test_scan_commercial_restrictions(self, mock_query, scanner):
        """Test detection of packages with commercial restrictions."""
        # Mock commercial/proprietary licenses
        mock_query.side_effect = ["Commercial", "Proprietary", "Custom License"]
        
        packages = [
            Package(name="oracle-database", version="19.3.0", package_manager=PackageManager.PIP),
            Package(name="matlab-engine", version="9.13.0", package_manager=PackageManager.PIP),
            Package(name="qt5-commercial", version="5.15.0", package_manager=PackageManager.PIP),
        ]
        
        result = scanner.scan(packages)
        
        # Should flag commercial restrictions
        assert len(result.licenses) == 3
        license_names = [license.name for license in result.licenses]
        assert "Commercial" in license_names or "Proprietary" in license_names
    
    @patch('app.static_scan.scanners.pypi_license_scanner.PypiLicenseScanner._query_pypi_license')
    def test_scan_permissive_licenses(self, mock_query, scanner, python_packages):
        """Test scanning of permissive licenses (MIT, Apache, BSD)."""
        # Mock permissive licenses
        mock_query.side_effect = ["MIT", "Apache-2.0", "BSD-3-Clause"]
        
        result = scanner.scan(python_packages)
        
        # Should detect permissive licenses
        assert len(result.licenses) == 3
        license_names = [license.name for license in result.licenses]
        assert "MIT" in license_names
        assert "Apache-2.0" in license_names
    
    @patch('app.static_scan.scanners.pypi_license_scanner.PypiLicenseScanner._query_pypi_license')
    def test_scan_agpl_detection(self, mock_query, scanner):
        """Test detection of AGPL (strongest copyleft)."""
        # Mock AGPL license
        mock_query.return_value = "AGPL-3.0"
        
        packages = [
            Package(name="mongodb", version="3.12.3", package_manager=PackageManager.PIP),
            Package(name="some-agpl-package", version="1.0.0", package_manager=PackageManager.PIP),
        ]
        
        result = scanner.scan(packages)
        
        # Should detect AGPL
        assert len(result.licenses) == 2
        assert all('AGPL' in license.name for license in result.licenses)
    
    @patch('app.static_scan.scanners.pypi_license_scanner.PypiLicenseScanner._query_pypi_license')
    def test_scan_license_conflicts(self, mock_query, scanner):
        """Test detection of license conflicts."""
        # Mock conflicting licenses
        mock_query.side_effect = ["GPL-3.0", "MIT", "Apache-2.0"]
        
        packages = [
            Package(name="PyGTK", version="2.24.0", package_manager=PackageManager.PIP),
            Package(name="flask", version="2.3.2", package_manager=PackageManager.PIP),
            Package(name="requests", version="2.31.0", package_manager=PackageManager.PIP),
        ]
        
        result = scanner.scan(packages)
        
        # Should detect different licenses
        assert len(result.licenses) == 3
        license_names = [license.name for license in result.licenses]
        assert "GPL-3.0" in license_names
        assert "MIT" in license_names
    
    @patch('app.static_scan.scanners.pypi_license_scanner.PypiLicenseScanner._query_pypi_license')
    def test_scan_unknown_licenses(self, mock_query, scanner):
        """Test handling of packages with unknown licenses."""
        # Mock unknown/None licenses
        mock_query.side_effect = [None, "", "UNKNOWN"]
        
        packages = [
            Package(name="custom-internal-lib", version="0.1.0", package_manager=PackageManager.PIP),
            Package(name="legacy-package", version="0.0.1", package_manager=PackageManager.PIP),
            Package(name="experimental-tool", version="2.0.0-alpha", package_manager=PackageManager.PIP),
        ]
        
        result = scanner.scan(packages)
        
        # Should handle unknown licenses
        # Only packages with non-None licenses are included
        assert len(result.licenses) == 1  # Only "UNKNOWN" is kept
        assert result.licenses[0].name == "UNKNOWN"
    
    def test_scan_empty_package_list(self, scanner):
        """Test scanning empty package list."""
        result = scanner.scan([])
        
        assert len(result.licenses) == 0
        assert isinstance(result, LicensesScanningResult)
    
    @patch('app.static_scan.scanners.pypi_license_scanner.PypiLicenseScanner._query_pypi_license')
    def test_scan_license_metadata(self, mock_query, scanner):
        """Test extraction of license metadata."""
        # Mock detailed license response
        mock_query.side_effect = [
            "MIT License",
            "BSD 3-Clause License",
            "Apache Software License 2.0"
        ]
        
        packages = [
            Package(name="test-package", version="1.0.0", package_manager=PackageManager.PIP),
            Package(name="numpy", version="1.24.0", package_manager=PackageManager.PIP),
            Package(name="pandas", version="2.0.0", package_manager=PackageManager.PIP),
        ]
        
        result = scanner.scan(packages)
        
        # Should extract license metadata
        assert len(result.licenses) == 3
        # Check normalization worked
        for license in result.licenses:
            assert license.name != ""
            assert license.package is not None
    
    def test_scan_result_format(self, scanner):
        """Test that scan results match expected format."""
        # Use real PyPI for this test - requests should have MIT license
        packages = [
            Package(name="requests", version="2.31.0", package_manager=PackageManager.PIP),
        ]
        
        result = scanner.scan(packages)
        
        # Verify result structure for LicensesScanningResult
        assert isinstance(result, LicensesScanningResult)
        assert hasattr(result, 'licenses')
        assert isinstance(result.licenses, list)
        
        # If we got a license (should for requests)
        if len(result.licenses) > 0:
            license = result.licenses[0]
            assert hasattr(license, 'name')
            assert hasattr(license, 'package')
            assert isinstance(license.package, Package)
    
    def test_non_python_packages_filtered(self, scanner):
        """Test that non-Python packages are filtered out."""
        packages = [
            Package(name="express", version="4.18.0", package_manager=PackageManager.UNKNOWN),
            Package(name="spring-core", version="5.3.0", package_manager=PackageManager.UNKNOWN),
            Package(name="rack", version="2.0.6", package_manager=PackageManager.UNKNOWN),
        ]
        
        result = scanner.scan(packages)
        
        # Should filter out non-Python packages
        assert len(result.licenses) == 0
    
    @patch('urllib.request.urlopen')
    def test_pypi_response_parsing(self, mock_urlopen, scanner):
        """Test parsing of different PyPI API response formats."""
        # Test different response structures
        responses = [
            # Standard license field
            {
                "info": {
                    "license": "MIT License",
                    "name": "package1"
                }
            },
            # License in classifier only
            {
                "info": {
                    "license": "",
                    "classifiers": [
                        "License :: OSI Approved :: Apache Software License",
                        "Programming Language :: Python :: 3"
                    ],
                    "name": "package2"
                }
            },
            # No license info
            {
                "info": {
                    "name": "package3"
                }
            }
        ]
        
        # Mock responses for each package
        def mock_response(index):
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps(responses[index]).encode('utf-8')
            return mock_resp
        
        mock_urlopen.return_value.__enter__.side_effect = [
            mock_response(0), mock_response(1), mock_response(2)
        ]
        
        packages = [
            Package(name="package1", version="1.0.0", package_manager=PackageManager.PIP),
            Package(name="package2", version="1.0.0", package_manager=PackageManager.PIP),
            Package(name="package3", version="1.0.0", package_manager=PackageManager.PIP),
        ]
        
        result = scanner.scan(packages)
        
        # Should handle different response formats
        assert len(result.licenses) >= 1  # At least the first one with clear license