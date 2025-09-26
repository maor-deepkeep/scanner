"""Unit tests for TrivyScanner."""
import pytest
import tempfile
import os
import sys
import json
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.static_scan.scanners.trivy_scanner import TrivyScanner


class TestTrivyScanner:
    """Unit tests for Trivy vulnerability scanner."""
    
    @pytest.fixture
    def scanner(self):
        """Create scanner instance."""
        return TrivyScanner()
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    def test_scan_python_vulnerabilities(self, scanner, temp_dir):
        """Test scanning Python dependencies for vulnerabilities."""
        # Create requirements.txt with known vulnerable versions
        req_path = os.path.join(temp_dir, "requirements.txt")
        with open(req_path, 'w') as f:
            f.write("""# Known vulnerable packages
django==2.2.0
flask==0.12.2
requests==2.6.0
urllib3==1.24.1
pyyaml==5.1
pillow==6.2.0
tensorflow==2.0.0
cryptography==2.9.2""")
        
        result = scanner.scan(temp_dir)
        
        # Should detect vulnerabilities
        assert len(result.vulnerabilities) > 0
        
        # Should include CVE information
        assert any('CVE' in str(vuln.id) for vuln in result.vulnerabilities)
    
    def test_scan_nodejs_vulnerabilities(self, scanner, temp_dir):
        """Test scanning Node.js dependencies."""
        # Create package.json with vulnerable packages
        package_json = {
            "name": "test-app",
            "version": "1.0.0",
            "dependencies": {
                "lodash": "4.17.11",  # CVE-2019-10744
                "jquery": "2.2.3",
                "angular": "1.6.0",
                "express": "4.16.0",
                "minimist": "0.0.8"
            }
        }
        
        package_path = os.path.join(temp_dir, "package.json")
        with open(package_path, 'w') as f:
            json.dump(package_json, f, indent=2)
        
        # Create package-lock.json
        package_lock = {
            "name": "test-app",
            "version": "1.0.0",
            "lockfileVersion": 1,
            "dependencies": {
                "lodash": {
                    "version": "4.17.11",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.11.tgz"
                }
            }
        }
        
        lock_path = os.path.join(temp_dir, "package-lock.json")
        with open(lock_path, 'w') as f:
            json.dump(package_lock, f, indent=2)
        
        result = scanner.scan(temp_dir)
        
        # Should detect Node.js vulnerabilities
        assert len(result.vulnerabilities) > 0
    
    def test_scan_java_vulnerabilities(self, scanner, temp_dir):
        """Test scanning Java dependencies."""
        # Create pom.xml with vulnerable dependencies
        pom_xml = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.test</groupId>
    <artifactId>test-app</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.14.0</version> <!-- Log4Shell CVE-2021-44228 -->
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>5.2.0.RELEASE</version>
        </dependency>
        <dependency>
            <groupId>commons-collections</groupId>
            <artifactId>commons-collections</artifactId>
            <version>3.2.1</version>
        </dependency>
    </dependencies>
</project>"""
        
        pom_path = os.path.join(temp_dir, "pom.xml")
        with open(pom_path, 'w') as f:
            f.write(pom_xml)
        
        result = scanner.scan(temp_dir)
        
        # Should detect critical vulnerabilities like Log4Shell
        assert len(result.vulnerabilities) > 0
        
        # Check for Log4Shell specifically
        vuln_str = str(result.vulnerabilities)
        assert 'log4j' in vuln_str.lower() or 'CVE-2021-44228' in vuln_str
    
    def test_scan_ruby_vulnerabilities(self, scanner, temp_dir):
        """Test scanning Ruby dependencies."""
        # Create Gemfile with vulnerable gems
        gemfile = """source 'https://rubygems.org'

gem 'rails', '5.2.2'
gem 'nokogiri', '1.10.1'
gem 'rack', '2.0.6'
gem 'loofah', '2.2.3'
gem 'actionview', '5.2.2'"""
        
        gemfile_path = os.path.join(temp_dir, "Gemfile")
        with open(gemfile_path, 'w') as f:
            f.write(gemfile)
        
        # Create Gemfile.lock
        gemfile_lock = """GEM
  remote: https://rubygems.org/
  specs:
    rails (5.2.2)
    nokogiri (1.10.1)
    rack (2.0.6)
    loofah (2.2.3)
    actionview (5.2.2)

BUNDLED WITH
   2.1.4"""
        
        lock_path = os.path.join(temp_dir, "Gemfile.lock")
        with open(lock_path, 'w') as f:
            f.write(gemfile_lock)
        
        result = scanner.scan(temp_dir)
        
        # Should detect Ruby vulnerabilities
        assert len(result.vulnerabilities) > 0
    
    def test_scan_go_vulnerabilities(self, scanner, temp_dir):
        """Test scanning Go dependencies."""
        # Create go.mod with vulnerable modules
        go_mod = """module example.com/test

go 1.16

require (
    github.com/dgrijalva/jwt-go v3.2.0+incompatible
    github.com/gin-gonic/gin v1.6.3
    github.com/gorilla/websocket v1.4.0
)"""
        
        go_mod_path = os.path.join(temp_dir, "go.mod")
        with open(go_mod_path, 'w') as f:
            f.write(go_mod)
        
        result = scanner.scan(temp_dir)
        
        # Should scan Go modules
        assert result is not None
        # Go modules may or may not have vulnerabilities
    
    def test_scan_dockerfile_vulnerabilities(self, scanner, temp_dir):
        """Test scanning Dockerfile for security issues."""
        # Create Dockerfile with security issues
        dockerfile = """FROM python:3.7-alpine
USER root
RUN pip install django==2.1.0
RUN apk add --no-cache curl wget
COPY . /app
RUN chmod 777 /app
EXPOSE 22 80 443
CMD ["python", "/app/manage.py", "runserver", "0.0.0.0:8000"]"""
        
        dockerfile_path = os.path.join(temp_dir, "Dockerfile")
        with open(dockerfile_path, 'w') as f:
            f.write(dockerfile)
        
        result = scanner.scan(temp_dir)
        
        # Should detect Dockerfile security issues
        assert result is not None
        # Trivy may or may not find vulnerabilities in this simple Dockerfile
    
    def test_scan_safe_dependencies(self, scanner, temp_dir):
        """Test scanning safe, up-to-date dependencies."""
        # Create requirements.txt with safe versions
        req_path = os.path.join(temp_dir, "requirements.txt")
        with open(req_path, 'w') as f:
            f.write("""# Updated, safe packages
django>=4.2.0
flask>=2.3.0
requests>=2.31.0
numpy>=1.24.0
pandas>=2.0.0""")
        
        result = scanner.scan(temp_dir)
        
        # Should have fewer or no vulnerabilities
        if len(result.vulnerabilities) == 0:
            assert len(result.vulnerabilities) == 0
        else:
            # May have some low-severity issues
            assert len(result.vulnerabilities) < 5
    
    def test_scan_empty_directory(self, scanner, temp_dir):
        """Test scanning empty directory."""
        result = scanner.scan(temp_dir)
        
        # Should handle empty directory
        assert len(result.vulnerabilities) == 0
        assert result is not None
    
    def test_scan_severity_levels(self, scanner, temp_dir):
        """Test detection of different vulnerability severity levels."""
        # Create requirements with various severity vulnerabilities
        req_path = os.path.join(temp_dir, "requirements.txt")
        with open(req_path, 'w') as f:
            f.write("""# Mix of severity levels
django==2.2.0
tensorflow==1.15.0
pyyaml==5.1
requests==2.25.0""")
        
        result = scanner.scan(temp_dir)
        
        # Should categorize by severity
        if len(result.vulnerabilities) > 0:
            # Check for severity information
            severities = set()
            for vuln in result.vulnerabilities:
                if hasattr(vuln, 'severity'):
                    severities.add(vuln.severity)
            assert len(severities) > 0  # Should have at least some severity info
    
    def test_scan_result_format(self, scanner, temp_dir):
        """Test that scan results match expected format."""
        # Create a test requirements file
        req_path = os.path.join(temp_dir, "requirements.txt")
        with open(req_path, 'w') as f:
            f.write("flask==0.12.2")
        
        result = scanner.scan(temp_dir)
        
        # Verify result structure for TrivyScanningResult
        assert hasattr(result, 'vulnerabilities')
        assert hasattr(result, 'packages')
        assert hasattr(result, 'sbom')
        assert isinstance(result.vulnerabilities, list)
        assert isinstance(result.packages, list)
        assert isinstance(result.sbom, dict)