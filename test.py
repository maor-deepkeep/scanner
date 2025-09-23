import sys
import logging
import json
from aiohttp import web
import asyncio
from datetime import datetime
from pathlib import Path
from jinja2 import Template
import webbrowser
import platform
import zipfile
import tempfile
import shutil
import os

from model_total import ModelTotal

logger = logging.getLogger(__name__)

URL = "http://localhost:8000/"

def generate_html_report(scan_result: dict, output_file: str = "scan_report.html"):
    """Generate an HTML report with collapsible sections for scan results"""
    
    # Load template from file
    template_path = os.path.join(os.path.dirname(__file__), 'templates', 'scan_report.html')
    with open(template_path, 'r') as f:
        template_content = f.read()
    
    html_template = Template(template_content)
    
    # Process issues by type
    vulnerabilities = []
    malicious_code = []
    tamper_issues = []
    license_issues = []
    risk_issues = []
    
    for issue in scan_result.get('issues', []):
        issue_type = issue.get('type', 'unknown')
        
        if issue_type == 'vulnerability':
            vulnerabilities.append(issue)
        elif issue_type == 'malicious_code':
            malicious_code.append(issue)
        elif issue_type == 'tamper':
            tamper_issues.append(issue)
        elif issue_type == 'license':
            license_issues.append(issue)
        elif issue_type == 'risk':
            risk_issues.append(issue)
    
    # Count vulnerabilities by severity
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for issue in scan_result.get('issues', []):
        severity = issue.get('severity', 'low').lower()
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    # Prepare template context
    context = {
        'operation_id': scan_result.get('operation_id', 'N/A'),
        'model_id': scan_result.get('model_id', 'N/A'),
        'model_name': scan_result.get('model_name', 'N/A'),
        'model_version': scan_result.get('model_version', 'N/A'),
        'final_verdict': scan_result.get('final_verdict', 'N/A'),
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_issues': len(scan_result.get('issues', [])),
        'vulnerability_count': len(vulnerabilities),
        'malicious_count': len(malicious_code),
        'tamper_count': len(tamper_issues),
        'license_count': len(license_issues),
        'risk_count': len(risk_issues),
        'severity_counts': severity_counts,
        'vulnerabilities': vulnerabilities,
        'malicious_code': malicious_code,
        'tamper_issues': tamper_issues,
        'license_issues': license_issues,
        'risk_issues': risk_issues,
        'ml_bom': scan_result.get('ml_bom', {}),
        'ml_bom_json': json.dumps(scan_result.get('ml_bom', {}), indent=2) if scan_result.get('ml_bom') else '',
        'raw_json': json.dumps(scan_result, indent=2)
    }
    
    # Render and save HTML
    html = html_template.render(context)
    with open(output_file, 'w') as f:
        f.write(html)
    
    logger.info(f"HTML report generated: {output_file}")

async def serve_file(request, file_to_serve):
    try:
        logger.info("Serving file")
        content = open(file_to_serve, mode="rb").read()
        return web.Response(body=content, headers={
            "Content-Disposition": f'attachment; filename="{file_to_serve}"'
        })
    except FileNotFoundError:
        return web.Response(status=404, text="File not found")

async def start_server(file_to_serve: str):
    app = web.Application()
    app.router.add_get("/", lambda request: serve_file(request, file_to_serve))
    
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", 1234)
    await site.start()
    logger.info("Server running on http://0.0.0.0:1234")

def create_zip_from_folder(folder_path: Path, output_zip_path: Path):
    """Create a zip file from a folder."""
    with zipfile.ZipFile(output_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = Path(root) / file
                arcname = file_path.relative_to(folder_path)
                zipf.write(file_path, arcname)
    logger.info(f"Created zip file: {output_zip_path}")
    return output_zip_path

async def main(input_path: str):
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    # Determine if input is a file or folder
    input_path_obj = Path(input_path)
    if not input_path_obj.exists():
        logger.error(f"Input path does not exist: {input_path}")
        sys.exit(1)
    
    temp_zip_path = None
    file_to_serve = None
    
    if input_path_obj.is_file():
        # Input is already a file (hopefully a zip)
        file_to_serve = str(input_path_obj)
        base_name = input_path_obj.stem
        logger.info(f"Using existing file: {file_to_serve}")
    elif input_path_obj.is_dir():
        # Input is a folder, create a temporary zip
        base_name = input_path_obj.name if input_path_obj.name else "scan"
        temp_dir = tempfile.mkdtemp()
        temp_zip_path = Path(temp_dir) / f"{base_name}.zip"
        file_to_serve = str(create_zip_from_folder(input_path_obj, temp_zip_path))
        logger.info(f"Created temporary zip from folder: {file_to_serve}")
    else:
        logger.error(f"Input is neither a file nor a directory: {input_path}")
        sys.exit(1)
    
    # Create outputs directory if it doesn't exist
    output_dir = Path("outputs")
    output_dir.mkdir(exist_ok=True)
    
    # Generate timestamp for unique filenames
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_filename = output_dir / f"{base_name}_{timestamp}.json"
    html_filename = output_dir / f"{base_name}_{timestamp}.html"

    # start server in background
    server_task = asyncio.create_task(start_server(file_to_serve))
    
    # wait a moment for server to start
    await asyncio.sleep(1)

    async with ModelTotal(URL) as client:
        # Scan an artifact
        try:
            result = await client.scan_artifact(
                model_id="model-id-1",
                model_name="my-model",
                model_version="1.0.0",
                model_url="http://host.docker.internal:1234/",
                org_id="org-456",
                model_metadata={"description": "Test model"}
            )
            logger.info(f"Scan completed. Result: {result}")
            
            # Parse the result to dictionary
            scan_result_dict = json.loads(result.model_dump_json())
            
            # Save JSON output with timestamp
            json_result = json.dumps(scan_result_dict, indent=4)
            with open(json_filename, "w") as f:
                f.write(json_result)
            logger.info(f"JSON output saved to {json_filename}")
            
            # Generate HTML report with timestamp
            generate_html_report(scan_result_dict, html_filename)
            
            # Print summary to console
            issue_count = len(scan_result_dict.get('issues', []))
            vuln_count = len([i for i in scan_result_dict.get('issues', []) if i.get('type') == 'vulnerability'])
            mal_count = len([i for i in scan_result_dict.get('issues', []) if i.get('type') == 'malicious_code'])
            
            logger.info(f"Scan Summary:")
            logger.info(f"  Model: {scan_result_dict.get('model_name', 'N/A')} (v{scan_result_dict.get('model_version', 'N/A')})")
            logger.info(f"  Model ID: {scan_result_dict.get('model_id', 'N/A')}")
            logger.info(f"  Final Verdict: {scan_result_dict.get('final_verdict', 'N/A')}")
            logger.info(f"  Total Issues: {issue_count}")
            logger.info(f"    - {vuln_count} vulnerabilities")
            logger.info(f"    - {mal_count} malicious code detections")
            logger.info(f"Reports generated: {json_filename} and {html_filename}")
            
            # Open the HTML report in the browser
            html_path = html_filename.absolute()
            # webbrowser.open handles platform differences automatically
            webbrowser.open(f"file://{html_path}")
            
        except Exception as e:
            logger.info(f"Scan failed: {e}")
    
    # Clean up temporary files
    if temp_zip_path and temp_zip_path.exists():
        try:
            shutil.rmtree(temp_zip_path.parent)
            logger.info(f"Cleaned up temporary files: {temp_zip_path.parent}")
        except Exception as e:
            logger.warning(f"Failed to clean up temporary files: {e}")
    
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python test.py <path_to_model_zip_or_folder>")
        print("  path_to_model_zip_or_folder: Path to a zip file or folder containing the model")
        sys.exit(1)
    asyncio.run(main(sys.argv[1]))