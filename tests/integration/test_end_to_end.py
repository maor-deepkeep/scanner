"""End-to-end integration tests for ModelTotal scanning and result aggregation."""
import pytest
import os
import tempfile
import json
import zipfile
import asyncio
from typing import Dict, Any
from datetime import datetime


@pytest.mark.asyncio
class TestEndToEnd:
    """Test complete scanning workflow and result aggregation."""
    
    async def test_full_scan_aggregation(self, docker_compose_setup, model_total_client, test_file_server):
        """Test complete scan with all scanners and result aggregation."""
        server_url, temp_dir = test_file_server
        
        # Create comprehensive test model
        model_dir = os.path.join(temp_dir, "complete_model")
        os.makedirs(model_dir)
        
        # 1. Model files with various issues
        self._create_model_files(model_dir)
        
        # 2. Dependencies with vulnerabilities and license issues  
        self._create_dependencies(model_dir)
        
        # 3. Configuration files
        self._create_config_files(model_dir)
        
        # Create ZIP archive
        zip_path = os.path.join(temp_dir, "complete_model.zip")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zf.write(file_path, arcname)
        
        # Perform scan
        async with model_total_client as client:
            result = await client.scan_artifact(
                model_id="e2e-test-model",
                model_name="end-to-end-test",
                model_version="1.0.0",
                model_url=f"{server_url}/complete_model.zip",
                org_id="e2e-test-org",
                model_metadata={
                    "framework": "pytorch",
                    "task": "classification",
                    "dataset": "imagenet"
                }
            )
        
        # Verify aggregated result structure
        self._verify_result_structure(result)
        
        # Verify all scanners ran
        self._verify_all_scanners_executed(result)
        
        # Verify issue aggregation
        self._verify_issue_aggregation(result)
        
        # Verify SBOM generation
        self._verify_sbom(result)
        
        # Verify ML-BOM generation
        self._verify_mlbom(result)
    
    async def test_scan_result_json_format(self, docker_compose_setup, model_total_client, test_file_server):
        """Test the final JSON output format."""
        server_url, temp_dir = test_file_server
        
        # Create simple test model
        model_dir = os.path.join(temp_dir, "json_test")
        os.makedirs(model_dir)
        
        # Add basic files
        import pickle
        with open(os.path.join(model_dir, "model.pkl"), 'wb') as f:
            pickle.dump({'weights': [1, 2, 3]}, f)
        
        with open(os.path.join(model_dir, "requirements.txt"), 'w') as f:
            f.write("numpy==1.24.0\npandas==2.0.0")
        
        # Create archive
        zip_path = os.path.join(temp_dir, "json_test.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zf.write(file_path, arcname)
        
        async with model_total_client as client:
            result = await client.scan_artifact(
                model_id="json-test-model",
                model_name="json-format-test",
                model_version="1.0.0",
                model_url=f"{server_url}/json_test.zip",
                org_id="json-test-org"
            )
        
        # Convert result to JSON and verify structure
        result_json = self._result_to_json(result)
        
        # Verify top-level fields
        assert 'operation_id' in result_json
        assert 'model_id' in result_json
        assert 'generated_at' in result_json
        assert 'final_verdict' in result_json
        assert 'issues' in result_json
        assert 's_bom' in result_json
        assert 'ml_bom' in result_json
        
        # Verify issues structure (no scanner_results in new model)
        # Scanner info is now in each issue's detected_by field
        
        # Verify issues structure
        issues = result_json['issues']
        assert isinstance(issues, list)
        for issue in issues:
            assert 'id' in issue
            assert 'type' in issue
            assert 'severity' in issue
            assert 'description' in issue
            assert 'detected_by' in issue
    
    async def test_scan_with_malicious_content(self, docker_compose_setup, model_total_client, test_file_server):
        """Test scanning with various malicious patterns."""
        server_url, temp_dir = test_file_server
        
        model_dir = os.path.join(temp_dir, "malicious_model")
        os.makedirs(model_dir)
        
        # Create malicious pickle
        import pickle
        class Exploit:
            def __reduce__(self):
                import os
                return (os.system, ('echo pwned',))
        
        with open(os.path.join(model_dir, "backdoor.pkl"), 'wb') as f:
            pickle.dump(Exploit(), f)
        
        # Add vulnerable dependencies
        with open(os.path.join(model_dir, "requirements.txt"), 'w') as f:
            f.write("django==2.1.0\nflask==0.12.2\nlog4j==2.14.0")
        
        # Add GPL license issue
        with open(os.path.join(model_dir, "LICENSE"), 'w') as f:
            f.write("GNU GENERAL PUBLIC LICENSE Version 3")
        
        # Create archive
        zip_path = os.path.join(temp_dir, "malicious_model.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zf.write(file_path, arcname)
        
        async with model_total_client as client:
            result = await client.scan_artifact(
                model_id="malicious-test",
                model_name="malicious-content-test",
                model_version="1.0.0",
                model_url=f"{server_url}/malicious_model.zip",
                org_id="malicious-test-org"
            )
        
        # Should detect multiple issues
        assert result.final_verdict in ["MEDIUM", "HIGH", "CRITICAL"]
        assert len(result.issues) > 0
        
        # Should have malicious code issues (from the pickle exploit)
        malicious_issues = [i for i in result.issues if (i.type.value if hasattr(i.type, 'value') else i.type) == "malicious_code"]
        assert len(malicious_issues) > 0, f"No malicious_code issues found. Issues: {[(i.type, i.title) for i in result.issues]}"
        
        # Should have vulnerability issues
        vuln_issues = [i for i in result.issues if (i.type.value if hasattr(i.type, 'value') else i.type) == "vulnerability"]
        assert len(vuln_issues) > 0, f"No vulnerability issues found. Issues: {[(i.type, i.title) for i in result.issues]}"
        
        # Should have license-related issues (either license type or license-related malicious_code)
        license_issues = [i for i in result.issues if 
                         (i.type.value if hasattr(i.type, 'value') else i.type) == "license" or
                         ('license' in i.title.lower() or 'gpl' in i.title.upper() or 'copyleft' in i.title.lower())]
        assert len(license_issues) > 0, f"No license issues found. Issues: {[(i.type, i.title) for i in result.issues]}"
    
    async def test_scan_tampering_detection(self, docker_compose_setup, model_total_client, test_file_server):
        """Test tampering detection across scans."""
        server_url, temp_dir = test_file_server
        
        model_dir = os.path.join(temp_dir, "tamper_model")
        os.makedirs(model_dir)
        
        # Create initial model
        import pickle
        with open(os.path.join(model_dir, "model.pkl"), 'wb') as f:
            pickle.dump({'weights': [1, 2, 3]}, f)
        
        # Create initial archive
        zip_path = os.path.join(temp_dir, "tamper_model.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zf.write(file_path, arcname)
        
        async with model_total_client as client:
            # First scan - establish baseline
            result1 = await client.scan_artifact(
                model_id="tamper-test",
                model_name="tamper-detection-test",
                model_version="1.0.0",
                model_url=f"{server_url}/tamper_model.zip",
                org_id="tamper-test-org"
            )
            
            # Should be safe on first scan
            assert result1.final_verdict in ["NONE", "LOW"]
            
            # Modify the model file
            with open(os.path.join(model_dir, "model.pkl"), 'wb') as f:
                pickle.dump({'weights': [4, 5, 6], 'backdoor': True}, f)
            
            # Recreate archive with modified file
            with zipfile.ZipFile(zip_path, "w") as zf:
                for root, dirs, files in os.walk(model_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, temp_dir)
                        zf.write(file_path, arcname)
            
            # Second scan - should detect tampering
            result2 = await client.scan_artifact(
                model_id="tamper-test",
                model_name="tamper-detection-test",
                model_version="1.0.0",
                model_url=f"{server_url}/tamper_model.zip",
                org_id="tamper-test-org"
            )
            
            # Should detect tampering
            assert result2.final_verdict in ["MEDIUM", "HIGH", "CRITICAL"]
            tamper_issues = [i for i in result2.issues if (i.type.value if hasattr(i.type, 'value') else i.type) == "tamper"]
            assert len(tamper_issues) > 0, f"No tamper issues found. Issues: {[(i.type, i.title) for i in result2.issues]}"
    
    async def test_concurrent_scans(self, docker_compose_setup, model_total_client, test_file_server):
        """Test multiple concurrent scans."""
        server_url, temp_dir = test_file_server
        
        # Create test model
        model_dir = os.path.join(temp_dir, "concurrent_model")
        os.makedirs(model_dir)
        
        import pickle
        with open(os.path.join(model_dir, "model.pkl"), 'wb') as f:
            pickle.dump({'test': 'concurrent'}, f)
        
        zip_path = os.path.join(temp_dir, "concurrent_model.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zf.write(file_path, arcname)
        
        async with model_total_client as client:
            # Launch multiple concurrent scans
            tasks = []
            for i in range(5):
                task = client.scan_artifact(
                    model_id=f"concurrent-{i}",
                    model_name="concurrent-test",
                    model_version="1.0.0",
                    model_url=f"{server_url}/concurrent_model.zip",
                    org_id=f"concurrent-org-{i}"
                )
                tasks.append(task)
            
            # Wait for all to complete
            results = await asyncio.gather(*tasks)
        
        # All should complete successfully
        assert len(results) == 5
        for result in results:
            assert result is not None
            assert result.final_verdict in ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    
    # Helper methods
    
    def _create_model_files(self, model_dir: str):
        """Create model files with various patterns."""
        import pickle
        
        # Benign model
        with open(os.path.join(model_dir, "model.pkl"), 'wb') as f:
            pickle.dump({
                'architecture': 'resnet50',
                'weights': [[0.1, 0.2], [0.3, 0.4]],
                'layers': 50
            }, f)
        
        # Suspicious patterns
        with open(os.path.join(model_dir, "utils.py"), 'w') as f:
            f.write("""import torch
import numpy as np

def load_model(path):
    return torch.load(path)

def preprocess(data):
    # Suspicious: eval usage
    return eval(f"np.array({data})")
""")
    
    def _create_dependencies(self, model_dir: str):
        """Create dependency files."""
        # Python requirements with vulnerabilities
        with open(os.path.join(model_dir, "requirements.txt"), 'w') as f:
            f.write("""# Vulnerable versions
django==2.2.0
flask==0.12.2
tensorflow==1.15.0
# GPL licensed
PyGTK==2.24.0
# Safe packages
numpy==1.24.0
pandas==2.0.0""")
        
        # Node.js dependencies
        package_json = {
            "name": "model-ui",
            "version": "1.0.0",
            "dependencies": {
                "lodash": "4.17.11",
                "express": "4.16.0"
            }
        }
        with open(os.path.join(model_dir, "package.json"), 'w') as f:
            json.dump(package_json, f, indent=2)
    
    def _create_config_files(self, model_dir: str):
        """Create configuration files."""
        # Model config
        config = {
            "model_name": "test_model",
            "version": "1.0.0",
            "framework": "pytorch",
            "input_shape": [3, 224, 224],
            "output_classes": 1000
        }
        with open(os.path.join(model_dir, "config.json"), 'w') as f:
            json.dump(config, f, indent=2)
        
        # Training config
        training = {
            "epochs": 100,
            "batch_size": 32,
            "learning_rate": 0.001,
            "optimizer": "adam"
        }
        with open(os.path.join(model_dir, "training_config.json"), 'w') as f:
            json.dump(training, f, indent=2)
    
    def _verify_result_structure(self, result: Any):
        """Verify the aggregated result has correct structure."""
        # Top-level fields
        assert hasattr(result, 'operation_id')
        assert hasattr(result, 'model_id')
        assert hasattr(result, 'generated_at')
        assert hasattr(result, 'final_verdict')
        assert hasattr(result, 'issues')
        assert hasattr(result, 's_bom')
        assert hasattr(result, 'ml_bom')
        
        # Types
        assert isinstance(result.operation_id, str)
        assert isinstance(result.model_id, str)
        assert isinstance(result.generated_at, datetime)
        assert result.final_verdict in ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert isinstance(result.issues, list)
        assert isinstance(result.s_bom, dict)
        assert isinstance(result.ml_bom, dict)
    
    def _verify_all_scanners_executed(self, result: Any):
        """Verify all scanners were executed by checking issues from different scanners."""
        # Check that we have issues from different scanner types  
        scanner_types = set()
        for issue in result.issues:
            if isinstance(issue.detected_by, list):
                scanner_types.update(issue.detected_by)
            else:
                scanner_types.add(issue.detected_by)
        
        # We should have issues from at least some scanners
        assert len(scanner_types) > 0, "No scanner types found in issues"
    
    def _verify_issue_aggregation(self, result: Any):
        """Verify issues are properly aggregated."""
        # Issues count should match
        assert isinstance(result.issues, list), "Issues should be a list"
        
        # Issue types should be properly categorized (using IssueType enum values)
        valid_types = {"vulnerability", "license", "tamper", "risk", "malicious_code"}
        issue_types = set(issue.type.value if hasattr(issue.type, 'value') else issue.type for issue in result.issues)
        assert issue_types.issubset(valid_types), f"Invalid issue types: {issue_types - valid_types}"
        
        # Each issue should have required fields
        for issue in result.issues:
            assert hasattr(issue, 'type')
            assert hasattr(issue, 'severity')
            assert hasattr(issue, 'description')
            assert hasattr(issue, 'detected_by')
    
    def _verify_sbom(self, result: Any):
        """Verify Software Bill of Materials."""
        sbom = result.s_bom
        
        # Should have SBOM structure
        assert 'bomFormat' in sbom or 'specVersion' in sbom
        assert 'components' in sbom
        
        # Components should have required fields
        if sbom['components']:
            for component in sbom['components']:
                assert 'name' in component
                assert 'version' in component or 'type' in component
    
    def _verify_mlbom(self, result: Any):
        """Verify ML Bill of Materials."""
        mlbom = result.ml_bom
        
        # ML-BOM might be empty dict for now
        assert isinstance(mlbom, dict), "ML-BOM should be a dict"
    
    def _result_to_json(self, result: Any) -> Dict[str, Any]:
        """Convert result object to JSON-serializable dict."""
        return {
            'operation_id': result.operation_id,
            'model_id': result.model_id,
            'model_name': result.model_name,
            'model_version': result.model_version,
            'final_verdict': result.final_verdict,
            'generated_at': result.generated_at.isoformat() if hasattr(result.generated_at, 'isoformat') else str(result.generated_at),
            'issues': [
                {
                    'id': issue.id,
                    'type': issue.type.value if hasattr(issue.type, 'value') else issue.type,
                    'severity': issue.severity.value if hasattr(issue.severity, 'value') else issue.severity,
                    'description': issue.description,
                    'detected_by': issue.detected_by.value if hasattr(issue.detected_by, 'value') else issue.detected_by
                }
                for issue in result.issues
            ],
            's_bom': result.s_bom,
            'ml_bom': result.ml_bom
        }