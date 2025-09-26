import pytest
import subprocess
import time
import requests
import tempfile
import os
import shutil
import threading
import http.server
import socketserver

from pathlib import Path


@pytest.fixture(scope="class")
def docker_compose_setup():
    """
    Fixture to set up and tear down Docker Compose environment for integration tests.
    """
    print("\n🐳 Starting Docker Compose services for integration tests...")
    
    # Start Docker Compose services
    result = subprocess.run(
        ["docker-compose", "up", "-d", "--build"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent
    )
    
    if result.returncode != 0:
        pytest.fail(f"Failed to start Docker Compose: {result.stderr}")
    
    # Wait for services to be ready
    print("⏳ Waiting for services to be ready...")
    max_retries = 30
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            # Check if the API is ready
            response = requests.get("http://localhost:8000/docs", timeout=5)
            if response.status_code == 200:
                print("✅ Services are ready!")
                break
        except requests.exceptions.RequestException:
            pass
        
        time.sleep(2)
        retry_count += 1
        
        if retry_count % 5 == 0:
            print(f"⏳ Still waiting... ({retry_count}/{max_retries})")
    
    if retry_count >= max_retries:
        # Clean up on failure
        subprocess.run(["docker-compose", "down", "-v"], 
                      cwd=Path(__file__).parent.parent)
        pytest.fail("Services failed to start within expected time")
    
    yield
    
    # Cleanup
    print("\n🧹 Cleaning up Docker Compose services...")
    subprocess.run(
        ["docker-compose", "down", "-v"],
        capture_output=True,
        cwd=Path(__file__).parent.parent
    )
    print("✅ Cleanup completed!")


@pytest.fixture
def model_total_client():
    """
    Create a ModelTotal client for testing.
    """
    # Import here to avoid import issues during fixture collection
    import sys
    sys.path.append(str(Path(__file__).parent.parent))
    from model_total import ModelTotal
    
    return ModelTotal("http://localhost:8000")

@pytest.fixture(scope="function")
def test_file_server():
    """
    Start a simple HTTP server to serve test files.
    Creates a fresh temporary directory for each test to avoid contamination.
    """
    
    # Create temporary directory first
    temp_dir = tempfile.mkdtemp()
    httpd = None
    
    try:
        # Find an available port
        with socketserver.TCPServer(("", 0), http.server.SimpleHTTPRequestHandler) as s:
            port = s.server_address[1]
        
        # Create server in the temp directory
        original_dir = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            handler = http.server.SimpleHTTPRequestHandler
            httpd = socketserver.TCPServer(("", port), handler)
            
            # Start server in a separate thread
            server_thread = threading.Thread(
                target=httpd.serve_forever,
                daemon=False  # Non-daemon thread to keep server alive
            )
            server_thread.start()
            
            # Give server time to start and test connectivity
            time.sleep(2)
            
            yield f"http://host.docker.internal:{port}", temp_dir
            
        finally:
            os.chdir(original_dir)
        
    finally:
        # Properly shutdown server
        if httpd:
            httpd.shutdown()
            httpd.server_close()
        
        # Clean up temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)