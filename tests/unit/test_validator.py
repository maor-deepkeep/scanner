"""Unit tests for Validator (tampering detection)."""
import pytest
import tempfile
import os
import sys
import hashlib
import json
import pickle
import zipfile
import datetime
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.static_scan.validation.validator import Validator
from app.models import ModelArtifact, ModelMetadata, ValidationResult, Verdict


class TestValidator:
    """Unit tests for Validator tampering detection."""
    
    @pytest.fixture
    def validator(self):
        """Create validator instance."""
        return Validator(org_id="test-org")
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    def test_first_scan_baseline(self, validator, temp_dir):
        """Test creation of baseline hashes on first scan."""
        # Create test files
        file1_path = os.path.join(temp_dir, "model.pkl")
        with open(file1_path, 'wb') as f:
            pickle.dump({'weights': [1, 2, 3]}, f)
        
        file2_path = os.path.join(temp_dir, "config.json")
        with open(file2_path, 'w') as f:
            json.dump({'version': '1.0'}, f)
        
        # Create ModelArtifact
        metadata = ModelMetadata(
            model_id="test-model",
            model_name="test-model",
            model_version="1.0.0",
            model_metadata={}
        )
        artifact = ModelArtifact(
            metadata=metadata,
            folder_path=temp_dir
        )
        
        # First validate should create baseline
        result = validator.validate(artifact)
        
        # Should be valid on first scan (first scan is always VALID)
        assert result.verdict == Verdict.VALID
        assert result.changed_files == []
    
    def test_detect_file_modification(self, validator, temp_dir):
        """Test detection of modified files."""
        # Create original file
        file_path = os.path.join(temp_dir, "model.pkl")
        with open(file_path, 'wb') as f:
            pickle.dump({'weights': [1, 2, 3]}, f)
        
        # Create ModelArtifact
        metadata = ModelMetadata(
            model_id="test-model-tamper",
            model_name="test-model-tamper",
            model_version="1.0.0",
            model_metadata={}
        )
        artifact = ModelArtifact(
            metadata=metadata,
            folder_path=temp_dir
        )
        
        # First validate to establish baseline
        result1 = validator.validate(artifact)
        assert result1.verdict == Verdict.VALID
        
        # Modify the file
        with open(file_path, 'wb') as f:
            pickle.dump({'weights': [4, 5, 6], 'backdoor': 'malicious'}, f)
        
        # Second validate should detect tampering
        result2 = validator.validate(artifact)
        
        # Should detect tampering
        assert result2.verdict == Verdict.TAMPERED
        assert len(result2.changed_files) > 0
    
    def test_detect_new_files(self, validator, temp_dir):
        """Test detection of new files added after baseline."""
        # Create original files
        file1_path = os.path.join(temp_dir, "model.pkl")
        with open(file1_path, 'wb') as f:
            pickle.dump({'weights': [1, 2, 3]}, f)
        
        metadata = ModelMetadata(
            model_id="test-model-new",
            model_name="test-model-new",
            model_version="1.0.0",
            model_metadata={}
        )
        artifact = ModelArtifact(
            metadata=metadata,
            folder_path=temp_dir
        )
        
        # First validate
        result1 = validator.validate(artifact)
        assert result1.verdict == Verdict.VALID
        
        # Add new file
        file2_path = os.path.join(temp_dir, "backdoor.py")
        with open(file2_path, 'w') as f:
            f.write("import os; os.system('echo pwned')")
        
        # Second validate should detect new file
        result2 = validator.validate(artifact)
        
        # Should detect new file as tampering
        assert result2.verdict == Verdict.TAMPERED
        assert len(result2.changed_files) > 0
    
    def test_detect_deleted_files(self, validator, temp_dir):
        """Test detection of deleted files."""
        # Create original files
        file1_path = os.path.join(temp_dir, "model.pkl")
        with open(file1_path, 'wb') as f:
            pickle.dump({'weights': [1, 2, 3]}, f)
        
        file2_path = os.path.join(temp_dir, "config.json")
        with open(file2_path, 'w') as f:
            json.dump({'version': '1.0'}, f)
        
        # Create ModelArtifact
        metadata = ModelMetadata(
            model_id="test-model-delete",
            model_name="test-model-delete",
            model_version="1.0.0",
            model_metadata={}
        )
        artifact = ModelArtifact(
            metadata=metadata,
            folder_path=temp_dir
        )
        
        # First scan
        result1 = validator.validate(artifact)
        assert result1.verdict == Verdict.VALID
        
        # Delete a file
        os.remove(file2_path)
        
        # Second scan should detect deletion
        result2 = validator.validate(artifact)
        
        # Should detect missing file
        assert result2.verdict == Verdict.TAMPERED
        assert len(result2.changed_files) > 0
    
    def test_no_tampering_same_files(self, validator, temp_dir):
        """Test that unchanged files are not flagged."""
        # Create files
        file_path = os.path.join(temp_dir, "model.pkl")
        with open(file_path, 'wb') as f:
            pickle.dump({'weights': [1, 2, 3]}, f)
        
        # Create ModelArtifact
        metadata = ModelMetadata(
            model_id="test-model-same",
            model_name="test-model-same",
            model_version="1.0.0",
            model_metadata={}
        )
        artifact = ModelArtifact(
            metadata=metadata,
            folder_path=temp_dir
        )
        
        # First scan
        result1 = validator.validate(artifact)
        assert result1.verdict == Verdict.VALID
        
        # Second scan with same files
        result2 = validator.validate(artifact)
        
        # Should still be valid
        assert result2.verdict == Verdict.VALID
        assert len(result2.changed_files) == 0
    
    def test_organization_isolation(self, temp_dir):
        """Test that different organizations have isolated baselines."""
        # Create file
        file_path = os.path.join(temp_dir, "model.pkl")
        with open(file_path, 'wb') as f:
            pickle.dump({'weights': [1, 2, 3]}, f)
        
        # Create ModelArtifact
        metadata = ModelMetadata(
            model_id="shared-model",
            model_name="shared-model",
            model_version="1.0.0",
            model_metadata={}
        )
        artifact = ModelArtifact(
            metadata=metadata,
            folder_path=temp_dir
        )
        
        # Create validator for org1
        validator_org1 = Validator(org_id="org1")
        
        # Scan for org1
        result1_org1 = validator_org1.validate(artifact)
        assert result1_org1.verdict == Verdict.VALID
        
        # Modify file
        with open(file_path, 'wb') as f:
            pickle.dump({'weights': [4, 5, 6]}, f)
        
        # Create validator for org2
        validator_org2 = Validator(org_id="org2")
        
        # Scan for org2 (should be first scan for this org)
        result1_org2 = validator_org2.validate(artifact)
        assert result1_org2.verdict == Verdict.VALID  # First scan for org2
        
        # Scan again for org1 (should detect tampering)
        result2_org1 = validator_org1.validate(artifact)
        assert result2_org1.verdict == Verdict.TAMPERED
    
    def test_hash_computation(self, validator, temp_dir):
        """Test correct hash computation for files."""
        # Create file with known content
        content = b"test content for hashing"
        file_path = os.path.join(temp_dir, "test.txt")
        with open(file_path, 'wb') as f:
            f.write(content)
        
        # Compute expected hash
        expected_hash = hashlib.sha256(content).hexdigest()
        
        # Create ModelArtifact
        metadata = ModelMetadata(
            model_id="test-hash",
            model_name="test-hash",
            model_version="1.0.0",
            model_metadata={}
        )
        artifact = ModelArtifact(
            metadata=metadata,
            folder_path=temp_dir
        )
        
        # Scan and check hash
        result = validator.validate(artifact)
        
        assert result.new_manifest
        assert result.new_manifest.files
        
        # Find the test.txt hash
        test_file_entry = next(
            (f for f in result.new_manifest.files if 'test.txt' in f.path),
            None
        )
        
        assert test_file_entry is not None
        assert test_file_entry.hash == expected_hash
    
    def test_scan_nested_directories(self, validator, temp_dir):
        """Test validation of files in nested directories."""
        # Create nested structure
        nested_dir = os.path.join(temp_dir, "models", "v1")
        os.makedirs(nested_dir)
        
        # Add files at different levels
        file1 = os.path.join(temp_dir, "root.pkl")
        with open(file1, 'wb') as f:
            pickle.dump({'level': 'root'}, f)
        
        file2 = os.path.join(nested_dir, "nested.pkl")
        with open(file2, 'wb') as f:
            pickle.dump({'level': 'nested'}, f)
        
        # Create ModelArtifact
        metadata = ModelMetadata(
            model_id="test-nested",
            model_name="test-nested",
            model_version="1.0.0",
            model_metadata={}
        )
        artifact = ModelArtifact(
            metadata=metadata,
            folder_path=temp_dir
        )
        
        # First scan
        result1 = validator.validate(artifact)
        assert result1.verdict == Verdict.VALID
        assert len(result1.new_manifest.files) == 2
        
        # Modify nested file
        with open(file2, 'wb') as f:
            pickle.dump({'level': 'modified'}, f)
        
        # Should detect tampering in nested file
        result2 = validator.validate(artifact)
        assert result2.verdict == Verdict.TAMPERED
        assert any('nested.pkl' in f for f in result2.changed_files)
    
    def test_scan_large_files(self, validator, temp_dir):
        """Test validation of large files."""
        # Create large file (5MB)
        large_content = b'0' * (5 * 1024 * 1024)
        file_path = os.path.join(temp_dir, "large_model.bin")
        with open(file_path, 'wb') as f:
            f.write(large_content)
        
        # Create ModelArtifact
        metadata = ModelMetadata(
            model_id="test-large",
            model_name="test-large",
            model_version="1.0.0",
            model_metadata={}
        )
        artifact = ModelArtifact(
            metadata=metadata,
            folder_path=temp_dir
        )
        
        # Should handle large files
        import time
        start = time.time()
        result = validator.validate(artifact)
        duration = time.time() - start
        
        assert result.verdict == Verdict.VALID
        assert duration < 10  # Should be reasonably fast
    
    def test_scan_result_format(self, validator, temp_dir):
        """Test that scan results match expected format."""
        # Create test file
        file_path = os.path.join(temp_dir, "test.pkl")
        with open(file_path, 'wb') as f:
            pickle.dump({'test': 'data'}, f)
        
        # Create ModelArtifact
        metadata = ModelMetadata(
            model_id="test-format",
            model_name="test-format",
            model_version="1.0.0",
            model_metadata={}
        )
        artifact = ModelArtifact(
            metadata=metadata,
            folder_path=temp_dir
        )
        
        result = validator.validate(artifact)
        
        # Verify result structure
        assert result.verdict in [Verdict.VALID, Verdict.TAMPERED]
        assert isinstance(result.changed_files, list)
        assert isinstance(result.validated_at, datetime.datetime)
        assert result.new_manifest is not None
        assert isinstance(result.new_manifest.files, list)
        assert isinstance(result.new_manifest.manifest_hash, str)