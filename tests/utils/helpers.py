"""Test helper utilities for ModelTotal test suite."""
import os
import tempfile
import zipfile
import tarfile
import pickle
import json
from pathlib import Path
from typing import Dict, List, Any, Optional


class TestFileGenerator:
    """Helper class for generating test files."""
    
    @staticmethod
    def create_nested_archive(
        levels: int = 3,
        content: bytes = b"malicious content",
        archive_type: str = "zip"
    ) -> bytes:
        """
        Create nested archive with content at innermost level.
        
        Args:
            levels: Number of nesting levels
            content: Content for innermost file
            archive_type: Type of archive ("zip" or "tar")
            
        Returns:
            Bytes of the outermost archive
        """
        import io
        
        current_content = content
        
        for level in range(levels):
            buffer = io.BytesIO()
            
            if archive_type == "zip":
                with zipfile.ZipFile(buffer, 'w') as zf:
                    if level == 0:
                        zf.writestr("payload.dat", current_content)
                    else:
                        zf.writestr(f"level_{level}.zip", current_content)
            else:  # tar
                with tarfile.open(fileobj=buffer, mode='w:gz') as tf:
                    if level == 0:
                        info = tarfile.TarInfo(name="payload.dat")
                        info.size = len(current_content)
                        tf.addfile(info, io.BytesIO(current_content))
                    else:
                        info = tarfile.TarInfo(name=f"level_{level}.tar")
                        info.size = len(current_content)
                        tf.addfile(info, io.BytesIO(current_content))
            
            current_content = buffer.getvalue()
        
        return current_content
    
    @staticmethod
    def create_pytorch_model(
        malicious: bool = False,
        size_mb: int = 1
    ) -> bytes:
        """
        Create PyTorch model file.
        
        Args:
            malicious: Whether to include malicious code
            size_mb: Approximate size in megabytes
            
        Returns:
            Bytes of PyTorch model file
        """
        import io
        
        model_data = {
            'model_state_dict': {
                f'layer_{i}': [[0.1] * 100 for _ in range(10)]
                for i in range(max(1, size_mb * 10))
            },
            'optimizer_state_dict': {},
            'epoch': 100,
            'loss': 0.001
        }
        
        if malicious:
            # Add malicious __reduce__ method
            class Exploit:
                def __reduce__(self):
                    import os
                    return (os.system, ('echo pwned',))
            
            model_data['backdoor'] = Exploit()
        
        # Create PyTorch ZIP structure
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as zf:
            zf.writestr('version', b'3\n')
            zf.writestr('data.pkl', pickle.dumps(model_data))
        
        return buffer.getvalue()
    
    @staticmethod
    def create_tensorflow_model(
        model_type: str = "savedmodel"
    ) -> Dict[str, bytes]:
        """
        Create TensorFlow model files.
        
        Args:
            model_type: Type of model ("savedmodel" or "h5")
            
        Returns:
            Dictionary of filename to content bytes
        """
        files = {}
        
        if model_type == "savedmodel":
            files['saved_model.pb'] = b'\x08\x01\x12\x00'  # Minimal protobuf
            files['variables/variables.index'] = b'TF_INDEX_V1'
            files['variables/variables.data-00000-of-00001'] = b'TF_DATA'
        else:  # h5
            # HDF5 format
            files['model.h5'] = b'\x89HDF\r\n\x1a\n' + b'\x00' * 1024
        
        return files
    
    @staticmethod
    def create_zip_bomb(
        compression_ratio: int = 1000,
        final_size_mb: int = 100
    ) -> bytes:
        """
        Create a zip bomb for testing.
        
        Args:
            compression_ratio: Target compression ratio
            final_size_mb: Uncompressed size in MB
            
        Returns:
            Compressed zip bomb bytes
        """
        import io
        
        # Create highly compressible data
        data = b'0' * (final_size_mb * 1024 * 1024)
        
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            for i in range(10):
                zf.writestr(f'bomb_{i}.txt', data)
        
        return buffer.getvalue()


class TestResultValidator:
    """Helper class for validating scan results."""
    
    @staticmethod
    def validate_scan_result(result: Any) -> bool:
        """
        Validate that scan result has correct structure.
        
        Args:
            result: Scan result object
            
        Returns:
            True if valid, False otherwise
        """
        required_fields = [
            'scanner_name',
            'scan_duration',
            'verdict',
            'issues_count',
            'files_scanned',
            'affected_files',
            'scanner_data'
        ]
        
        for field in required_fields:
            if not hasattr(result, field):
                return False
        
        # Validate field types
        if result.verdict not in ["SAFE", "SUSPICIOUS", "MALICIOUS"]:
            return False
        
        if not isinstance(result.issues_count, int) or result.issues_count < 0:
            return False
        
        if not isinstance(result.scan_duration, (int, float)) or result.scan_duration < 0:
            return False
        
        if not isinstance(result.files_scanned, list):
            return False
        
        if not isinstance(result.affected_files, list):
            return False
        
        if not isinstance(result.scanner_data, dict):
            return False
        
        return True
    
    @staticmethod
    def assert_malicious_detected(
        result: Any,
        min_issues: int = 1,
        expected_files: Optional[List[str]] = None
    ):
        """
        Assert that malicious content was detected.
        
        Args:
            result: Scan result object
            min_issues: Minimum number of issues expected
            expected_files: List of files that should be flagged
        """
        assert result.verdict in ["SUSPICIOUS", "MALICIOUS"], \
            f"Expected SUSPICIOUS or MALICIOUS verdict, got {result.verdict}"
        
        assert result.issues_count >= min_issues, \
            f"Expected at least {min_issues} issues, got {result.issues_count}"
        
        if expected_files:
            for expected_file in expected_files:
                assert any(expected_file in f for f in result.affected_files), \
                    f"Expected {expected_file} in affected files"
    
    @staticmethod
    def assert_safe(result: Any):
        """
        Assert that content was marked safe.
        
        Args:
            result: Scan result object
        """
        assert result.verdict == "SAFE", \
            f"Expected SAFE verdict, got {result.verdict}"
        
        assert result.issues_count == 0, \
            f"Expected 0 issues for safe content, got {result.issues_count}"


class TestDataCleaner:
    """Helper for cleaning up test data."""
    
    @staticmethod
    def cleanup_test_files(directory: str):
        """
        Clean up test files from directory.
        
        Args:
            directory: Directory to clean
        """
        import shutil
        
        test_patterns = [
            '*.pkl',
            '*.pth',
            '*.pt',
            '*.h5',
            '*.onnx',
            '*.npy',
            '*.npz',
            'test_*',
            'malicious_*',
            'exploit_*'
        ]
        
        for pattern in test_patterns:
            for file_path in Path(directory).glob(pattern):
                if file_path.is_file():
                    file_path.unlink()
                elif file_path.is_dir():
                    shutil.rmtree(file_path)


def compare_scan_results(result1: Any, result2: Any) -> Dict[str, Any]:
    """
    Compare two scan results for consistency.
    
    Args:
        result1: First scan result
        result2: Second scan result
        
    Returns:
        Dictionary with comparison details
    """
    comparison = {
        'verdict_match': result1.verdict == result2.verdict,
        'issues_diff': abs(result1.issues_count - result2.issues_count),
        'files_only_in_1': set(result1.affected_files) - set(result2.affected_files),
        'files_only_in_2': set(result2.affected_files) - set(result1.affected_files),
        'common_files': set(result1.affected_files) & set(result2.affected_files)
    }
    
    return comparison


def create_test_model_directory(
    base_dir: str,
    include_malicious: bool = False,
    include_vulnerable_deps: bool = False
) -> str:
    """
    Create a test model directory with various files.
    
    Args:
        base_dir: Base directory for test data
        include_malicious: Whether to include malicious files
        include_vulnerable_deps: Whether to include vulnerable dependencies
        
    Returns:
        Path to created directory
    """
    model_dir = os.path.join(base_dir, "test_model")
    os.makedirs(model_dir, exist_ok=True)
    
    # Add model files
    model_path = os.path.join(model_dir, "model.pkl")
    if include_malicious:
        class Exploit:
            def __reduce__(self):
                import os
                return (os.system, ('echo test',))
        model_data = {'weights': [1, 2, 3], 'exploit': Exploit()}
    else:
        model_data = {'weights': [1, 2, 3], 'config': {'layers': 3}}
    
    with open(model_path, 'wb') as f:
        pickle.dump(model_data, f)
    
    # Add requirements.txt
    if include_vulnerable_deps:
        requirements = """django==2.1.0
flask==0.12.2
tensorflow==1.15.0
PyGTK==2.24.0"""
    else:
        requirements = """numpy>=1.21.0
pandas>=1.3.0
scikit-learn>=1.0.0"""
    
    with open(os.path.join(model_dir, "requirements.txt"), 'w') as f:
        f.write(requirements)
    
    # Add config file
    config = {
        'name': 'test_model',
        'version': '1.0.0',
        'framework': 'pytorch'
    }
    with open(os.path.join(model_dir, "config.json"), 'w') as f:
        json.dump(config, f)
    
    return model_dir