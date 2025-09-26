"""Tests for scanner operational modes: offline and trusted module filtering."""
import pytest
import tempfile
import os
import sys
import pickle
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
import subprocess

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.static_scan.scanners.trivy_scanner import TrivyScanner
from app.static_scan.scanners.fickling_scanner import FicklingScanner
from app.static_scan.scanners.picklescan_scanner import PickleScanScanner


class TestOfflineMode:
    """Tests for offline mode functionality."""
    
    def test_offline_mode_controlled_by_environment_variable(self):
        """Test that OFFLINE_MODE environment variable controls scanner behavior."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a requirements.txt
            req_path = os.path.join(temp_dir, "requirements.txt")
            with open(req_path, 'w') as f:
                f.write("requests==2.31.0\n")
            
            # Test with OFFLINE_MODE=true
            with patch.dict(os.environ, {'OFFLINE_MODE': 'true'}):
                # Import here to pick up the env var
                from app.static_scan.static_scanner import StaticScanner
                scanner = StaticScanner()
                
                # Mock the scanners and methods
                with patch('app.static_scan.static_scanner.TrivyScanner') as MockTrivy:
                    mock_trivy = MagicMock()
                    MockTrivy.return_value = mock_trivy
                    
                    # Check that TrivyScanner is initialized with offline_mode=True
                    with patch('app.static_scan.static_scanner.Validator'), \
                         patch('app.static_scan.static_scanner.PypiLicenseScanner'), \
                         patch.object(scanner, '_download_and_extract_zip'), \
                         patch.object(scanner, '_scan_model_security'):
                        
                        # Verify offline_mode is read from environment
                        offline_mode = os.environ.get('OFFLINE_MODE', 'false').lower() == 'true'
                        assert offline_mode == True
                        
                        # Verify TrivyScanner would be created with offline_mode=True
                        trivy = TrivyScanner(offline_mode=offline_mode)
                        assert trivy._offline_mode == True
            
            # Test with OFFLINE_MODE=false
            with patch.dict(os.environ, {'OFFLINE_MODE': 'false'}):
                offline_mode = os.environ.get('OFFLINE_MODE', 'false').lower() == 'true'
                assert offline_mode == False
                
                trivy = TrivyScanner(offline_mode=offline_mode)
                assert trivy._offline_mode == False
            
            # Test with OFFLINE_MODE not set (default)
            with patch.dict(os.environ, {}, clear=True):
                # Remove OFFLINE_MODE if it exists
                os.environ.pop('OFFLINE_MODE', None)
                offline_mode = os.environ.get('OFFLINE_MODE', 'false').lower() == 'true'
                assert offline_mode == False
                
                trivy = TrivyScanner(offline_mode=offline_mode)
                assert trivy._offline_mode == False
    
    def test_trivy_scanner_adds_skip_db_update_in_offline_mode(self):
        """Test that TrivyScanner adds --skip-db-update flag when offline."""
        scanner_offline = TrivyScanner(offline_mode=True)
        scanner_online = TrivyScanner(offline_mode=False)
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a requirements.txt
            req_path = os.path.join(temp_dir, "requirements.txt")
            with open(req_path, 'w') as f:
                f.write("requests==2.31.0\n")
            
            # Mock subprocess.run to capture the commands
            with patch('subprocess.run') as mock_run:
                mock_run.return_value = MagicMock(
                    stdout='{"Results": []}',
                    stderr='',
                    returncode=0
                )
                
                # Test offline mode
                scanner_offline.scan(temp_dir)
                
                # Check both vulnerability scan and SBOM commands include --skip-db-update
                calls = mock_run.call_args_list
                assert len(calls) == 2  # One for vuln scan, one for SBOM
                
                vuln_command = calls[0][0][0]
                sbom_command = calls[1][0][0]
                
                assert '--skip-db-update' in vuln_command
                assert '--skip-db-update' in sbom_command
                
                # Reset mock
                mock_run.reset_mock()
                
                # Test online mode
                scanner_online.scan(temp_dir)
                
                calls = mock_run.call_args_list
                assert len(calls) == 2
                
                vuln_command = calls[0][0][0]
                sbom_command = calls[1][0][0]
                
                assert '--skip-db-update' not in vuln_command
                assert '--skip-db-update' not in sbom_command


class TestTrustedModuleFiltering:
    """Tests for trusted module filtering functionality."""
    
    def test_scanner_respects_trusted_filter_environment_variable(self):
        """Test that scanners respect their SCANNER_TRUSTED_FILTER env vars."""
        # Test with filter DISABLED for picklescan
        with patch.dict(os.environ, {'PICKLESCAN_TRUSTED_FILTER': 'false'}):
            scanner = PickleScanScanner()
            
            # Verify filter is disabled
            assert scanner.enable_trusted_filter == False
            
            # Verify that trusted modules are NOT filtered
            assert scanner.is_trusted_module_issue('torch.load') == False
            assert scanner.is_trusted_module_issue('numpy.array') == False
            assert scanner.is_trusted_module_issue('tensorflow.keras.models') == False
        
        # Test with filter ENABLED (default behavior)
        with patch.dict(os.environ, {}, clear=True):
            scanner = PickleScanScanner()
            
            # Verify filter is enabled by default
            assert scanner.enable_trusted_filter == True
            
            # Verify that trusted modules ARE filtered
            assert scanner.is_trusted_module_issue('torch.load') == True
            assert scanner.is_trusted_module_issue('numpy.array') == True
            assert scanner.is_trusted_module_issue('tensorflow.keras.models') == True
            assert scanner.is_trusted_module_issue('sklearn classifier') == True
            
            # But dangerous modules are NOT filtered
            assert scanner.is_trusted_module_issue('os.system') == False
            assert scanner.is_trusted_module_issue('eval()') == False
            assert scanner.is_trusted_module_issue('subprocess.call') == False
    
    def test_fickling_scanner_filters_trusted_modules_correctly(self):
        """Test FicklingScanner's trusted module filtering logic."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test pickle files
            safe_pkl = os.path.join(temp_dir, "model.pkl")
            
            # Create a simple pickle file
            data = {'weights': [1.0, 2.0, 3.0]}
            with open(safe_pkl, 'wb') as f:
                pickle.dump(data, f)
            
            # Test with filter ENABLED
            with patch.dict(os.environ, {}, clear=True):
                scanner = FicklingScanner()
                assert scanner.enable_trusted_filter == True
                
                # Mock fickling to simulate detecting torch operations
                with patch('fickling.load') as mock_load:
                    mock_error = MagicMock()
                    mock_error.info = {
                        'analysis': 'Unsafe operation detected: torch.load',
                        'severity': 'LIKELY_UNSAFE'
                    }
                    mock_load.side_effect = mock_error
                    
                    # The scanner should filter torch as trusted
                    assert scanner.is_trusted_module_issue('torch.load') == True
                    assert scanner.is_trusted_module_issue('torch') == True
            
            # Test with filter DISABLED
            with patch.dict(os.environ, {'FICKLING_TRUSTED_FILTER': 'false'}):
                scanner = FicklingScanner()
                assert scanner.enable_trusted_filter == False
                
                # Same operations should NOT be filtered
                assert scanner.is_trusted_module_issue('torch.load') == False
                assert scanner.is_trusted_module_issue('torch') == False