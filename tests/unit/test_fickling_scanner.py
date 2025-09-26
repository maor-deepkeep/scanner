"""Unit tests for FicklingScanner."""
import pytest
import tempfile
import os
import sys
import pickle
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.static_scan.scanners.fickling_scanner import FicklingScanner
from tests.fixtures.malicious_pickles import (
    generate_malicious_pickles,
    generate_benign_pickles,
    generate_polyglot_pickles,
    PickleExploits
)

# Module-level classes for test_scan_pickle_with_custom_classes
class FicklingSafeClass:
    def __init__(self):
        self.value = "safe"

class FicklingUnsafeClass:
    def __reduce__(self):
        return (eval, ("print('executed')",))


class TestFicklingScanner:
    """Unit tests for Fickling scanner."""
    
    @pytest.fixture
    def scanner(self):
        """Create scanner instance."""
        return FicklingScanner()
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    def test_scan_malicious_pickles(self, scanner, temp_dir):
        """Test detection of malicious pickle operations."""
        malicious = generate_malicious_pickles()
        
        # Write various malicious pickles (os.system exploits)
        for name, data in list(malicious.items())[:5]:
            file_path = os.path.join(temp_dir, f"{name}.pkl")
            with open(file_path, 'wb') as f:
                f.write(data)
        
        result = scanner.scan(temp_dir)
        
        # Fickling should detect these as malicious
        assert result.verdict == "MALICIOUS", f"Expected MALICIOUS verdict, got {result.verdict}"
        assert result.issues_count >= 5, f"Expected at least 5 issues, got {result.issues_count}"
        assert len(result.affected_files) >= 5, f"Expected at least 5 affected files, got {len(result.affected_files)}"
        
        # Verify Fickling's specific detection patterns
        scanner_data_str = str(result.scanner_data)
        details = result.scanner_data.get('details', {})
        
        # Check that files are marked as unsafe with proper severity
        for file_path in result.affected_files:
            file_details = details.get(file_path, {})
            assert file_details.get('safe') is False, f"File {file_path} should be marked unsafe"
            # Fickling uses severity levels like LIKELY_OVERTLY_MALICIOUS for os.system
            severity = file_details.get('severity', '')
            assert 'MALICIOUS' in severity or 'UNSAFE' in severity, f"Expected malicious/unsafe severity for {file_path}, got {severity}"
            
        # Verify specific dangerous patterns are detected
        # Fickling detects: UnsafeImports, UnsafeImportsML, posix.system usage
        expected_detections = ['UnsafeImports', 'posix', 'system']
        found_detections = [d for d in expected_detections if d in scanner_data_str]
        assert len(found_detections) > 0, f"Expected to find at least one of {expected_detections} in scanner output"
    
    @pytest.mark.xfail(reason="Fickling has a bug parsing set pickles - 'Opcode Stop attempted to pop from an empty stack'")
    def test_scan_benign_pickles(self, scanner, temp_dir):
        """Test that benign pickles are marked safe."""
        benign = generate_benign_pickles()
        
        for name, data in benign.items():
            file_path = os.path.join(temp_dir, f"{name}.pkl")
            with open(file_path, 'wb') as f:
                f.write(data)
        
        result = scanner.scan(temp_dir)
        
        # Benign files should be safe or have minimal issues
        assert result.verdict in ["SAFE", "SUSPICIOUS"]
        if result.verdict == "SUSPICIOUS":
            # Some benign operations might still be flagged as potentially risky
            assert result.issues_count < 5
    
    def test_scan_benign_pickles_without_set(self, scanner, temp_dir):
        """Test that benign pickles (excluding problematic set) are marked safe."""
        benign = generate_benign_pickles()
        
        files_written = []
        for name, data in benign.items():
            # Skip set.pkl which causes Fickling parsing errors
            if name == 'set':
                continue
            file_path = os.path.join(temp_dir, f"{name}.pkl")
            files_written.append(file_path)
            with open(file_path, 'wb') as f:
                f.write(data)
        
        result = scanner.scan(temp_dir)
        
        # All benign files should be marked safe by Fickling
        assert result.verdict == "SAFE", f"Benign pickles should be SAFE, got {result.verdict}"
        assert result.issues_count == 0, f"Benign pickles should have 0 issues, got {result.issues_count}"
        assert len(result.affected_files) == 0, f"No files should be affected, got {result.affected_files}"
        
        # Verify all scanned files are marked as safe
        details = result.scanner_data.get('details', {})
        for file_path in files_written:
            if file_path in details:
                file_details = details[file_path]
                assert file_details.get('safe', False) is True, f"Benign file {file_path} should be marked safe"
    
    def test_scan_polyglot_files(self, scanner, temp_dir):
        """Test detection of polyglot files (pickle hidden in other formats)."""
        polyglots = generate_polyglot_pickles()
        
        for name, data in polyglots.items():
            # Use appropriate extension
            if 'zip' in name:
                ext = '.zip'
            elif 'pdf' in name:
                ext = '.pdf'
            elif 'jpeg' in name:
                ext = '.jpg'
            else:
                ext = '.dat'
            
            file_path = os.path.join(temp_dir, f"{name}{ext}")
            with open(file_path, 'wb') as f:
                f.write(data)
        
        result = scanner.scan(temp_dir)
        
        # Fickling might detect pickle data in polyglot files
        assert result is not None
    
    def test_analyze_pickle_bytecode(self, scanner, temp_dir):
        """Test analysis of pickle bytecode operations with os.system."""
        # Build a pickle that calls os.system using raw opcodes
        # This creates: os.system('echo test')
        pickle_data = (
            pickle.MARK +
            pickle.GLOBAL + b'os\nsystem\n' +  # Import os.system
            pickle.MARK +
            pickle.UNICODE + b'echo test\n' +  # Argument for system call
            pickle.TUPLE +  # Make tuple of arguments
            pickle.REDUCE +  # Call the function
            pickle.STOP
        )
        
        file_path = os.path.join(temp_dir, "bytecode_test.pkl")
        with open(file_path, 'wb') as f:
            f.write(pickle_data)
        
        result = scanner.scan(temp_dir)
        
        # Fickling should detect this as malicious
        assert result.verdict == "MALICIOUS", f"os.system bytecode should be MALICIOUS, got {result.verdict}"
        assert result.issues_count > 0, "Should have at least one issue"
        
        # Verify Fickling detects the specific threat
        details = result.scanner_data.get('details', {})
        file_details = details.get(file_path, {})
        
        # Check for os.system detection
        analysis = str(file_details.get('analysis', ''))
        detailed = file_details.get('detailed_results', {})
        
        # Fickling should identify os.system as unsafe import
        assert file_details.get('safe') is False, "File with os.system should be unsafe"
        assert 'system' in str(file_details).lower() or 'os' in str(file_details).lower(), \
            f"Should detect os.system in analysis, got: {file_details}"
    
    def test_scan_different_pickle_protocols(self, scanner, temp_dir):
        """Test scanning of different pickle protocol versions."""
        exploit = PickleExploits.OSSystemExploit()
        
        # Track which protocols we successfully created
        protocols_created = []
        for protocol in [0, 1, 2, 3, 4, 5]:
            try:
                file_path = os.path.join(temp_dir, f"protocol_{protocol}.pkl")
                with open(file_path, 'wb') as f:
                    pickle.dump(exploit, f, protocol=protocol)
                protocols_created.append(protocol)
            except Exception:
                # Some protocols might not be supported
                continue
        
        result = scanner.scan(temp_dir)
        
        # Fickling should detect exploits in all protocol versions
        assert result.verdict == "MALICIOUS", f"Exploits in all protocols should be MALICIOUS, got {result.verdict}"
        # Should detect at least as many issues as protocols created
        assert result.issues_count >= len(protocols_created), \
            f"Should detect {len(protocols_created)} exploits, got {result.issues_count}"
        
        # Verify each protocol file is detected
        for protocol in protocols_created:
            expected_file = f"protocol_{protocol}.pkl"
            assert any(expected_file in f for f in result.affected_files), \
                f"Protocol {protocol} exploit should be detected"
    
    def test_scan_empty_pickle(self, scanner, temp_dir):
        """Test scanning of empty pickle file."""
        # Create minimal valid pickle
        empty_path = os.path.join(temp_dir, "empty.pkl")
        with open(empty_path, 'wb') as f:
            pickle.dump(None, f)
        
        result = scanner.scan(temp_dir)
        
        # Empty pickle should be safe
        assert result.verdict in ["SAFE", "SUSPICIOUS"]
        assert result.issues_count <= 1
    
    def test_scan_nested_pickle_structures(self, scanner, temp_dir):
        """Test scanning of complex nested pickle structures with embedded exploit."""
        # Create nested structure with hidden exploit
        nested = {
            'layer1': {
                'layer2': {
                    'layer3': [
                        'safe_string',
                        42,
                        {'exploit': PickleExploits.EvalCodeExecution()}
                    ]
                }
            }
        }
        
        file_path = os.path.join(temp_dir, "nested.pkl")
        with open(file_path, 'wb') as f:
            pickle.dump(nested, f)
        
        result = scanner.scan(temp_dir)
        
        # Fickling should detect the eval exploit even in nested structure
        assert result.verdict == "MALICIOUS", f"Nested exploit should be MALICIOUS, got {result.verdict}"
        assert result.issues_count > 0, "Should detect the embedded exploit"
        assert file_path in result.affected_files, f"Nested file should be affected: {result.affected_files}"
        
        # Verify detection details
        details = result.scanner_data.get('details', {})
        file_details = details.get(file_path, {})
        assert file_details.get('safe') is False, "File with nested exploit should be unsafe"
    
    def test_scan_pickle_with_custom_classes(self, scanner, temp_dir):
        """Test scanning of pickles with custom class definitions."""
        # Create pickles with custom classes (defined at module level)
        safe_path = os.path.join(temp_dir, "safe_class.pkl")
        with open(safe_path, 'wb') as f:
            pickle.dump(FicklingSafeClass(), f)
        
        unsafe_path = os.path.join(temp_dir, "unsafe_class.pkl")
        with open(unsafe_path, 'wb') as f:
            pickle.dump(FicklingUnsafeClass(), f)
        
        result = scanner.scan(temp_dir)
        
        # The unsafe class uses eval() which Fickling should detect
        assert result.verdict == "MALICIOUS", f"Class with eval() should be MALICIOUS, got {result.verdict}"
        assert result.issues_count > 0, "Should detect at least the unsafe class"
        
        # Verify the unsafe_class.pkl is in affected files
        assert any('unsafe_class' in f for f in result.affected_files), \
            f"unsafe_class.pkl should be in affected files: {result.affected_files}"
        
        # Check detection details
        details = result.scanner_data.get('details', {})
        unsafe_details = details.get(unsafe_path, {})
        
        # Fickling should detect eval as dangerous
        assert unsafe_details.get('safe') is False, "Unsafe class should be marked unsafe"
        # Fickling detects eval as 'OvertlyBadEvals' or mentions eval in analysis
        assert 'eval' in str(unsafe_details).lower() or 'OvertlyBadEvals' in str(unsafe_details), \
            f"Should detect eval in unsafe class, got: {unsafe_details}"
    
    def test_scan_corrupted_pickle(self, scanner, temp_dir):
        """Test handling of corrupted pickle files."""
        # Create various corrupted pickles
        corrupted_files = [
            ('truncated.pkl', b'\x80\x04\x95\x05\x00\x00'),  # Truncated
            ('invalid_opcode.pkl', b'\x80\x04\xFF\xFF'),  # Invalid opcodes
            ('bad_protocol.pkl', b'\x80\x99'),  # Invalid protocol
        ]
        
        for filename, data in corrupted_files:
            file_path = os.path.join(temp_dir, filename)
            with open(file_path, 'wb') as f:
                f.write(data)
        
        # Should handle corruption gracefully
        result = scanner.scan(temp_dir)
        assert result is not None
    
    def test_scan_result_metadata(self, scanner, temp_dir):
        """Test that scan results include proper metadata and structure."""
        # Create test pickle
        test_path = os.path.join(temp_dir, "test.pkl")
        with open(test_path, 'wb') as f:
            pickle.dump({'test': 'data'}, f)
        
        result = scanner.scan(temp_dir)
        
        # Verify required metadata fields
        assert result.scanner_name == 'fickling', f"Scanner name should be 'fickling', got {result.scanner_name}"
        assert result.scan_duration >= 0, f"Scan duration should be non-negative, got {result.scan_duration}"
        assert result.verdict in ["SAFE", "SUSPICIOUS", "MALICIOUS"], \
            f"Verdict should be SAFE/SUSPICIOUS/MALICIOUS, got {result.verdict}"
        
        # Verify scanner_data structure
        assert isinstance(result.scanner_data, dict), "scanner_data should be a dict"
        assert 'safe' in result.scanner_data, "scanner_data should have 'safe' field"
        assert 'unsafe_files' in result.scanner_data, "scanner_data should have 'unsafe_files' field"
        assert 'error_files' in result.scanner_data, "scanner_data should have 'error_files' field"
        assert 'details' in result.scanner_data, "scanner_data should have 'details' field"
        
        # Verify files_scanned contains our test file
        assert len(result.files_scanned) > 0, "Should have scanned at least one file"
        assert test_path in result.files_scanned, f"Test file should be in files_scanned: {result.files_scanned}"
        
        # For a simple benign pickle, should be safe
        assert result.verdict == "SAFE", f"Simple dict pickle should be SAFE, got {result.verdict}"
        assert result.issues_count == 0, f"Simple dict should have 0 issues, got {result.issues_count}"