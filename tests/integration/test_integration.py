import pytest
import os
import tempfile
import zipfile
import subprocess
import asyncio
from model_total import IssueType


class TestModelTotalIntegration:
    """
    Integration tests for ModelTotal client with Docker Compose backend.
    """

    @pytest.mark.asyncio
    async def test_scan_artifact_success(self, docker_compose_setup, model_total_client, test_file_server):
        """
        Test successful artifact scanning workflow.
        """
        server_url, temp_dir = test_file_server
        # Create test model zip file
        model_dir = os.path.join(temp_dir, "test_model")
        os.makedirs(model_dir, exist_ok=True)
        
        # Create test files
        with open(os.path.join(model_dir, "model.py"), "w") as f:
            f.write("""
import torch
import numpy as np

class TestModel(torch.nn.Module):
    def __init__(self):
        super().__init__()
        self.linear = torch.nn.Linear(10, 1)
    
    def forward(self, x):
        return self.linear(x)
""")
        
        with open(os.path.join(model_dir, "requirements.txt"), "w") as f:
            f.write("""torch==1.9.0
numpy==1.21.0
requests==2.25.1
PyGTK==2.24.2
""")
        
        # Create ZIP file
        zip_path = os.path.join(temp_dir, "test_model.zip")
        with zipfile.ZipFile(zip_path, "w",
                            zipfile.ZIP_DEFLATED) as zip_file:
            for root, _, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zip_file.write(file_path, arcname)
        # Test scan artifact
        async with model_total_client as client:
            result = await client.scan_artifact(
                model_id="test-model-123",
                model_name="integration-test-model",
                model_version="1.0.0",
                model_url=f"{server_url}/test_model.zip",
                org_id="test-org-456",
                model_metadata={
                    "description": "Integration test model",
                    "framework": "pytorch"
                }
            )
        # Verify some expected vulnerabilities are found (given old package versions)
        vulnerability_issues = [issue for issue in result.issues if issue.type.value == IssueType.VULNERABILITY.value]
        assert len(vulnerability_issues) > 0, "Expected to find some vulnerabilities in old packages"

        # Verify some expected license issues are found
        license_issues = [issue for issue in result.issues if issue.type.value == IssueType.LICENSE.value]
        assert len(license_issues) > 0, "Expected to find some license issues"
        # Verify SBOM contains expected components
        if 'components' in result.s_bom:
            component_names = [comp.get('name', '') for comp in result.s_bom['components']]
            assert any('torch' in name.lower() for name in component_names)
            assert any('numpy' in name.lower() for name in component_names)
            assert any('requests' in name.lower() for name in component_names)
            assert any('pygtk' in name.lower() for name in component_names)

    @pytest.mark.asyncio
    async def test_trivy_db_update(self, docker_compose_setup, model_total_client, test_file_server):
        """
        Test Trivy database update functionality with real database download.
        Downloads the actual Trivy DB, uploads it via API, and verifies vulnerability detection in offline mode.
        """
        server_url, temp_dir = test_file_server

        with tempfile.TemporaryDirectory() as db_temp_dir:
            # Step 1: Download the actual Trivy database using ORAS
            print("Downloading Trivy database using ORAS...")
            try:
                # Check if oras is installed
                oras_check = subprocess.run(['which', 'oras'], capture_output=True, text=True)
                if oras_check.returncode != 0:
                    pytest.skip("ORAS not installed, skipping real DB test")

                # Pull the Trivy database
                result = subprocess.run(
                    ['oras', 'pull', 'ghcr.io/aquasecurity/trivy-db:2'],
                    cwd=db_temp_dir,
                    capture_output=True,
                    text=True,
                    timeout=120  # 2 minutes timeout for download
                )

                if result.returncode != 0:
                    print(f"ORAS pull failed: {result.stderr}")
                    pytest.skip(f"Failed to download Trivy DB: {result.stderr}")

                # Verify the downloaded file exists
                db_tar_path = os.path.join(db_temp_dir, 'db.tar.gz')
                if not os.path.exists(db_tar_path):
                    pytest.skip("Downloaded Trivy DB file not found")

                print(f"Successfully downloaded Trivy DB: {os.path.getsize(db_tar_path)} bytes")

            except subprocess.TimeoutExpired:
                pytest.skip("Trivy DB download timed out")
            except Exception as e:
                pytest.skip(f"Failed to download Trivy DB: {e}")

            # Step 2: Upload the database via API
            async with model_total_client as client:
                print("Uploading Trivy DB via API...")
                result = await client.update_trivy_db(db_tar_path)
                assert result.success is True
                assert result.updated_at is not None
                print("Successfully uploaded Trivy DB")

            # Step 3: Create a test model with known vulnerable packages
            model_dir = os.path.join(temp_dir, "vuln_test_model")
            os.makedirs(model_dir, exist_ok=True)

            # Create requirements.txt with packages known to have vulnerabilities
            with open(os.path.join(model_dir, "requirements.txt"), "w") as f:
                f.write("""
# Old versions with known vulnerabilities
requests==2.6.0
urllib3==1.21.1
pyyaml==3.13
django==1.11.0
flask==0.12.2
sqlalchemy==1.2.0
cryptography==2.1.4
paramiko==2.0.0
jinja2==2.10
werkzeug==0.11.11
pillow==5.1.0
numpy==1.13.0
tensorflow==1.0.0
keras==2.0.8
scikit-learn==0.19.0
""")

            # Create a Python file
            with open(os.path.join(model_dir, "model.py"), "w") as f:
                f.write("""
import requests
import urllib3
import yaml
import django
import flask

print("Test model with vulnerable dependencies")
""")

            # Create ZIP file
            zip_path = os.path.join(temp_dir, "vuln_test_model.zip")
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zip_file:
                for root, dirs, files in os.walk(model_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, temp_dir)
                        zip_file.write(file_path, arcname)

            # Step 4: Scan the model and verify vulnerabilities are detected
            print("Scanning model with vulnerable packages...")
            async with model_total_client as client:
                result = await client.scan_artifact(
                    model_id="trivy-vuln-test",
                    model_name="trivy-vulnerability-test",
                    model_version="1.0.0",
                    model_url=f"{server_url}/vuln_test_model.zip",
                    org_id="trivy-test-org",
                    model_metadata={
                        "description": "Test model with known vulnerable dependencies",
                        "test_mode": "offline_vulnerability_detection"
                    }
                )

            # Step 5: Verify vulnerabilities were detected
            vulnerability_issues = [issue for issue in result.issues if issue.type.value == IssueType.VULNERABILITY.value]
            print(f"Found {len(vulnerability_issues)} vulnerabilities")

            # Assert we found a significant number of vulnerabilities
            assert len(vulnerability_issues) >= 10, f"Expected at least 10 vulnerabilities in old packages, found {len(vulnerability_issues)}"

            # Verify some specific known vulnerabilities
            vuln_descriptions = [issue.description for issue in vulnerability_issues]
            vuln_text = ' '.join(vuln_descriptions).lower()

            # Check for known vulnerable packages
            vulnerable_packages = ['requests', 'urllib3', 'pyyaml', 'django', 'flask']
            found_packages = []
            for pkg in vulnerable_packages:
                if pkg in vuln_text:
                    found_packages.append(pkg)

            print(f"Detected vulnerabilities in packages: {found_packages}")
            assert len(found_packages) >= 3, f"Expected vulnerabilities in at least 3 known packages, found in: {found_packages}"

            # Verify SBOM contains the vulnerable components
            if 'components' in result.s_bom:
                component_names = [comp.get('name', '').lower() for comp in result.s_bom['components']]
                for pkg in vulnerable_packages:
                    assert any(pkg in name for name in component_names), f"Expected {pkg} in SBOM components"

            print("Successfully verified Trivy vulnerability detection with real database in offline mode")


    @pytest.mark.asyncio
    async def test_organization_isolation(self, docker_compose_setup, model_total_client, test_file_server):
        """
        Test that different organizations have isolated data and tampering doesn't affect other orgs.
        """
        server_url, temp_dir = test_file_server
        # Create test model
        model_dir = os.path.join(temp_dir, "org_test_model")
        os.makedirs(model_dir, exist_ok=True)
        
        with open(os.path.join(model_dir, "test.py"), "w") as f:
            f.write("print('Organization test')")
        zip_path = os.path.join(temp_dir, "org_test_model.zip")
        with zipfile.ZipFile(zip_path, "w",
                            zipfile.ZIP_DEFLATED) as zip_file:
            for root, _, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zip_file.write(file_path, arcname)
        # Scan with first organization
        async with model_total_client as client:
            result_org1 = await client.scan_artifact(
                model_id="org-test-model-org1",
                model_name="org-isolation-test",
                model_version="1.0.0",
                model_url=f"{server_url}/org_test_model.zip",
                org_id="org-1"
            )
            # Tamper with the zip file by modifying a file inside it
            tampered_zip_path = os.path.join(temp_dir, "org_test_model_tampered.zip")
            with zipfile.ZipFile(zip_path, "r") as original_zip:
                with zipfile.ZipFile(tampered_zip_path, "w", zipfile.ZIP_DEFLATED) as tampered_zip:
                    for item in original_zip.infolist():
                        data = original_zip.read(item.filename)
                        if item.filename.endswith("test.py"):
                            # Modify the content of test.py
                            data = b"print('TAMPERED - This file has been modified!')"
                        tampered_zip.writestr(item, data)
            
            # Replace the original zip with the tampered one
            os.replace(tampered_zip_path, zip_path)
            # Scan with second organization (should not detect tampering from org-1's perspective)
            result_org2 = await client.scan_artifact(
                model_id="org-test-model-org2",
                model_name="org-isolation-test",
                model_version="1.0.0",
                model_url=f"{server_url}/org_test_model.zip",
                org_id="org-2"
            )
        
        # Verify that org-2 doesn't see tampering (since it's isolated from org-1)
        # The tampering should only be detected if there's cross-org contamination
        tampering_issues_org2 = [issue for issue in result_org2.issues if issue.type.value == IssueType.TAMPER.value]
        assert len(tampering_issues_org2) == 0, "Second organization should not detect tampering from first organization"

    @pytest.mark.asyncio
    async def test_tampering_detection(self, docker_compose_setup, model_total_client, test_file_server):
        """
        Test that tampering is properly detected when a file is modified.
        """
        server_url, temp_dir = test_file_server
        # Create test model
        model_dir = os.path.join(temp_dir, "tamper_test_model")
        os.makedirs(model_dir, exist_ok=True)
        
        with open(os.path.join(model_dir, "original.py"), "w") as f:
            f.write("print('Original content')")
        
        with open(os.path.join(model_dir, "metadata.json"), "w") as f:
            f.write('{"name": "test-model", "version": "1.0"}')
        
        # Create original ZIP file
        zip_path = os.path.join(temp_dir, "tamper_test_model.zip")
        with zipfile.ZipFile(zip_path, "w",
                            zipfile.ZIP_DEFLATED) as zip_file:
            for root, _, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zip_file.write(file_path, arcname)
        # First scan to establish baseline
        async with model_total_client as client:
            result_original = await client.scan_artifact(
                model_id="tamper-test-model",
                model_name="tampering-detection-test",
                model_version="1.0.0",
                model_url=f"{server_url}/tamper_test_model.zip",
                org_id="tamper-test-org"
            )
            # Tamper with the zip file by modifying a file inside it
            tampered_zip_path = os.path.join(temp_dir, "tamper_test_model_tampered.zip")
            with zipfile.ZipFile(zip_path, "r") as original_zip:
                with zipfile.ZipFile(tampered_zip_path, "w", zipfile.ZIP_DEFLATED) as tampered_zip:
                    for item in original_zip.infolist():
                        data = original_zip.read(item.filename)
                        if item.filename.endswith("original.py"):
                            # Modify the content to simulate tampering
                            data = b"print('MALICIOUS CODE INJECTED - This is tampering!')\nimport os\nos.system('rm -rf /')"
                        tampered_zip.writestr(item, data)
            
            # Replace the original zip with the tampered one
            os.replace(tampered_zip_path, zip_path)
            # Second scan with the tampered file
            result_tampered = await client.scan_artifact(
                model_id="tamper-test-model",
                model_name="tampering-detection-test",
                model_version="1.0.0",
                model_url=f"{server_url}/tamper_test_model.zip",
                org_id="tamper-test-org"
            )
        
        # Verify that tampering is detected
        tampering_issues = [
            issue for issue in result_tampered.issues
            if issue.type.value == IssueType.TAMPER.value
        ]
        assert len(tampering_issues) > 0, \
            "Expected to detect tampering in the modified file"

    @pytest.mark.asyncio
    async def test_concurrent_trivy_scans_offline(
            self, docker_compose_setup, model_total_client, test_file_server
    ):
        """
        Test concurrent Trivy scans with shared cache.
        First downloads and uploads Trivy DB, then runs concurrent scans.
        """
        server_url, temp_dir = test_file_server

        # First ensure we have the Trivy DB
        import tempfile
        with tempfile.TemporaryDirectory() as db_temp_dir:
            try:
                # Download the Trivy database
                print("Downloading Trivy database for concurrent test...")
                oras_check = subprocess.run(
                    ['which', 'oras'],
                    capture_output=True,
                    text=True
                )
                if oras_check.returncode != 0:
                    pytest.skip("ORAS not installed, skipping concurrent test")

                # Pull the Trivy database
                result = subprocess.run(
                    ['oras', 'pull', 'ghcr.io/aquasecurity/trivy-db:2'],
                    cwd=db_temp_dir,
                    capture_output=True,
                    text=True,
                    timeout=120
                )

                if result.returncode != 0:
                    pytest.skip(f"Failed to download Trivy DB: {result.stderr}")

                db_tar_path = os.path.join(db_temp_dir, 'db.tar.gz')
                if not os.path.exists(db_tar_path):
                    pytest.skip("Downloaded Trivy DB file not found")

                print(f"Successfully downloaded Trivy DB: "
                      f"{os.path.getsize(db_tar_path)} bytes")

                # Upload the database
                async with model_total_client as client:
                    print("Uploading Trivy DB...")
                    result = await client.update_trivy_db(db_tar_path)
                    assert result.success is True
                    print("Successfully uploaded Trivy DB")

            except subprocess.TimeoutExpired:
                pytest.skip("Trivy DB download timed out")
            except Exception as e:
                pytest.skip(f"Failed to setup Trivy DB: {e}")

        # Create multiple test models with vulnerable packages
        models = []
        for i in range(3):
            model_dir = os.path.join(temp_dir, f"concurrent_model_{i}")
            os.makedirs(model_dir, exist_ok=True)

            # Create requirements with varying vulnerable packages
            with open(os.path.join(model_dir, "requirements.txt"), "w") as f:
                f.write(f"""
# Model {i} - Old versions with known vulnerabilities
requests==2.{i}.0
django==1.{8+i}.0
flask==0.{10+i}.0
pyyaml==3.{10+i}
cryptography==2.{i}.0
pillow=={5+i}.0.0
""")

            # Create a Python file
            with open(os.path.join(model_dir, "model.py"), "w") as f:
                f.write(f"""
import requests
print("Concurrent test model {i}")
""")

            # Create ZIP file
            zip_path = os.path.join(temp_dir, f"concurrent_model_{i}.zip")
            with zipfile.ZipFile(
                zip_path, "w", zipfile.ZIP_DEFLATED
            ) as zip_file:
                for root, _, files in os.walk(model_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, temp_dir)
                        zip_file.write(file_path, arcname)

            models.append((i, zip_path))

        # Run concurrent scans
        print("Running concurrent Trivy scans...")
        async with model_total_client as client:
            tasks = []
            for i, _ in models:
                # Use unique org_id for each scan to avoid bucket conflicts
                unique_org_id = f"concurrent-test-org-{i}"
                task = client.scan_artifact(
                    model_id=f"concurrent-trivy-test-{i}",
                    model_name=f"concurrent-trivy-model-{i}",
                    model_version="1.0.0",
                    model_url=f"{server_url}/concurrent_model_{i}.zip",
                    org_id=unique_org_id,
                    model_metadata={
                        "description": f"Concurrent test model {i}",
                        "test_mode": "concurrent_offline_scan"
                    }
                )
                tasks.append(task)

            # Execute all scans concurrently
            results = await asyncio.gather(*tasks)

        # Verify all scans completed successfully
        print(f"Completed {len(results)} concurrent scans")
        assert len(results) == 3, "Expected 3 scan results"

        # Verify each scan found vulnerabilities
        for i, result in enumerate(results):
            vulnerability_issues = [
                issue for issue in result.issues
                if issue.type.value == IssueType.VULNERABILITY.value
            ]
            print(f"Model {i}: Found {len(vulnerability_issues)} "
                  f"vulnerabilities")
            assert len(vulnerability_issues) > 0, \
                f"Expected vulnerabilities in model {i}"

            # Verify vulnerability details
            from model_total import Severity
            valid_severities = [Severity.CRITICAL, Severity.HIGH,
                              Severity.MEDIUM, Severity.LOW]
            for vuln in vulnerability_issues[:3]:  # Check first 3 vulns
                assert vuln.severity in valid_severities, \
                    f"Invalid severity: {vuln.severity}"
                assert vuln.description, "Vulnerability missing description"
                # file_path is optional for some vulns
                assert hasattr(vuln, 'description'), "Missing description attr"

            # Check that we found vulnerabilities in expected packages
            vuln_descriptions = ' '.join([v.description.lower()
                                        for v in vulnerability_issues])
            vulnerable_packages = ['requests', 'django', 'flask', 'pyyaml',
                                 'cryptography', 'pillow']
            found_packages = [pkg for pkg in vulnerable_packages
                            if pkg in vuln_descriptions]
            print(f"  Found vulnerabilities in: {found_packages}")
            assert len(found_packages) >= 2, \
                f"Expected vulns in at least 2 packages, found: {found_packages}"

            # Verify final verdict is set based on vulnerabilities
            assert result.final_verdict in ['CRITICAL', 'HIGH', 'MEDIUM',
                                           'LOW', 'SAFE'], \
                f"Invalid final verdict: {result.final_verdict}"
            # With these vulnerable packages, verdict should be critical or high
            assert result.final_verdict in ['CRITICAL', 'HIGH'], \
                f"Expected CRITICAL/HIGH verdict, got: {result.final_verdict}"

            # Verify SBOM contains expected components
            if 'components' in result.s_bom:
                component_names = [
                    comp.get('name', '').lower()
                    for comp in result.s_bom['components']
                ]
                assert any('requests' in name
                          for name in component_names), \
                    f"Expected requests in model {i} SBOM"

        print("✅ Successfully verified concurrent Trivy scans with shared cache")
        print("✅ All scans properly detected and marked vulnerabilities")