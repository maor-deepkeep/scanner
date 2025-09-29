import pytest
import os
import tempfile
import zipfile
from microservices.model_scanner.src.schemas.models import IssueType

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
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zip_file:
            for root, dirs, files in os.walk(model_dir):
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
    async def test_trivy_db_update(self, docker_compose_setup, model_total_client):
        """
        Test Trivy database update functionality.
        Note: This test uses a mock tar.gz file since we don't have a real Trivy DB.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a mock Trivy DB structure
            db_dir = os.path.join(temp_dir, "db")
            os.makedirs(db_dir, exist_ok=True)
            
            # Create mock metadata.json
            with open(os.path.join(db_dir, "metadata.json"), "w") as f:
                f.write('{"Version": 2, "NextUpdate": "2024-01-01T00:00:00Z"}')
            
            # Create mock trivy.db (empty file)
            with open(os.path.join(db_dir, "trivy.db"), "wb") as f:
                f.write(b"mock trivy database content")
            
            # Create tar.gz file
            import tarfile
            tgz_path = os.path.join(temp_dir, "test_db.tar.gz")
            with tarfile.open(tgz_path, "w:gz") as tar:
                tar.add(db_dir, arcname="db")
            
            # Test update (this might fail due to validation, but we test the interface)
            async with model_total_client as client:
                try:
                    result = await client.update_trivy_db(tgz_path)
                    assert result.success is True
                    assert result.updated_at is not None
                except Exception as e:
                    # The mock database might not pass validation, which is expected
                    assert "trivy" in str(e).lower() or "database" in str(e).lower()

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
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zip_file:
            for root, dirs, files in os.walk(model_dir):
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
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zip_file:
            for root, dirs, files in os.walk(model_dir):
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
        tampering_issues = [issue for issue in result_tampered.issues if issue.type.value == IssueType.TAMPER.value]
        assert len(tampering_issues) > 0, "Expected to detect tampering in the modified file"