# ModelTotal

A comprehensive security scanning platform for ML models that provides vulnerability analysis, license compliance checking, and tamper detection.

## File Structure

```
ModelTotal/
├── app/                          # FastAPI application
│   ├── main.py                   # Application entry point
│   ├── models.py                 # Pydantic data models
│   ├── routes/                   # API route handlers
│   │   ├── static_scan.py        # Static scan endpoints
│   │   └── trivy.py             # Trivy database management
│   ├── static_scan/             # Core scanning functionality
│   │   ├── static_scanner.py    # Main scanner orchestration
│   │   ├── static_scan_controller.py # Scan request handling
│   │   ├── validation/          # Model validation and tampering detection
│   │   │   └── validator.py     # File integrity and manifest validation
│   │   ├── scanners/            # Individual scanner implementations
│   │   │   ├── trivy_scanner.py # Trivy vulnerability scanning
│   │   │   ├── pypi_license_scanner.py # PyPI license detection
│   │   │   ├── modelscan_scanner.py # ModelScan ML-specific security scanner
│   │   │   ├── picklescan_scanner.py # PickleScan for pickle file analysis
│   │   │   ├── fickling_scanner.py # Fickling pickle security scanner
│   │   │   └── modelaudit_scanner.py # ModelAudit ML model scanner
│   │   └── classifiers/         # License and risk classification
│   │       └── license_classifier.py # License risk assessment
│   └── tasks/                   # Celery background tasks
│       └── tasks.py             # Async scan task definitions
├── test.py                      # Dev Client test script with example usage
├── model_total.py               # Standalone Python client library (Client API)
├── docker-compose.yml           # Multi-service deployment configuration
├── Dockerfile                   # Container build definition
└── requirements.txt             # Python dependencies
```

## Environment Variables

### Core Configuration
- **Ports:**
  - `8000` - Main API server (FastAPI)
  - `27017` - MongoDB database
  - `6379` - Redis cache/message broker
  - `9000` - MinIO S3 API
  - `9001` - MinIO Web Console (development only)

### Service URLs
- `MONGODB_URL` - MongoDB connection string (default: `mongodb://admin:password123@mongodb:27017`)
- `REDIS_URL` - Redis connection URL (default: `redis://redis:6379`)
- `MINIO_URL` - MinIO S3 endpoint (default: `http://minio:9000`)
- `MINIO_ACCESS_KEY` - MinIO access credentials (default: `minioadmin`)
- `MINIO_SECRET_KEY` - MinIO secret credentials (default: `minioadmin`)

### Operational Modes
- `OFFLINE_MODE` - Enable offline scanning mode (default: `true`), license scanning will be available only on ONLINE_MODE
- `TRIVY_CACHE_DIR` - Trivy vulnerability database cache location (default: `/data/trivy-cache`)
- `DOCKER_HOST` - Docker daemon socket (default: `unix:///var/run/docker.sock`)

## Database Tables

### MongoDB Collections
- **`scan_results.task_meta`** - Celery task metadata and results storage
  - Stores scan operation status, progress, and final results
  - Indexed by operation_id for fast retrieval

### MinIO Buckets
- **`model-total-{org_id}`** - Organization-specific model artifact storage
  - Stores downloaded model files and manifests
  - Enables organization-level data isolation

### Redis Keys
- Celery task queues and result caching
- Session data for scan progress tracking

## Tech Stack

### Backend Framework
- **FastAPI** - Modern Python web framework with automatic API documentation
- **Pydantic** - Data validation and serialization using Python type annotations
- **Uvicorn** - ASGI web server for high-performance async applications

### Task Processing
- **Celery** - Distributed task queue for async scan processing
- **Redis** - Message broker and result backend for Celery

### Data Storage
- **MongoDB** - Document database for scan results and metadata
- **MinIO** - S3-compatible object storage for model artifacts

### Security Scanning
- **Trivy** - Vulnerability scanner for containers and dependencies
- **Custom scanners** - License analysis (based on Pypi scaraping) and model-specific security checks

### HTTP Client
- **HTTPX/aiohttp** - Async HTTP clients for model downloads

## API Endpoints

### Static Scan Operations
- **POST `/static-scan`** - Initiate security scan
  ```json
  Request: {
    "model_id": "string",
    "model_name": "string", 
    "model_version": "string",
    "model_url": "string",
    "org_id": "string",
    "model_metadata": {}
  }
  Response: {
    "success": true,
    "operation_id": "uuid",
    "error": null
  }
  ```

- **GET `/static-scan/{operation_id}/status`** - Check scan progress
  ```json
  Response: {
    "operation_id": "uuid",
    "status": "PENDING|PROGRESS|SUCCESS|FAILURE",
    "progress": 0-100,
    "error": null
  }
  ```

- **GET `/static-scan/{operation_id}/results`** - Retrieve scan results
  ```json
  Response: {
    "operation_id": "uuid",
    "ml_bom": {},          // Machine Learning Bill of Materials
    "s_bom": {},           // Software Bill of Materials  
    "issues": [],          // Security vulnerabilities and license issues
    "generated_at": "datetime"
  }
  ```

### Trivy Database Management
- **POST `/trivy`** - Update vulnerability database
  ```json
  Request: multipart/form-data file (.tgz/.tar.gz)
  Response: {
    "success": true,
    "updated_at": "datetime"
  }
  ```

## Scanner Architecture

### Unified Scanner Result Structure

All security scanners inherit from `BaseScanResult` and implement a uniform interface:

```python
class BaseScanResult(BaseModel):
    # Core fields (always available)
    scanner_name: str
    scan_duration: float
    
    # Result fields (common across scanners)
    verdict: str  # SAFE, SUSPICIOUS, MALICIOUS
    issues_count: int
    
    # Optional fields
    files_scanned: List[str]
    affected_files: List[str]  # Files with issues
    
    # Scanner-specific data
    scanner_data: Dict[str, Any]  # Used by to_issues()
    raw_output: Dict[str, Any]    # Complete scanner output
    errors: List[str]
```

### Available Security Scanners

1. **ModelScan** - Detects unsafe operations in ML models
2. **PickleScan** - Analyzes pickle files for dangerous operations
3. **Fickling** - Alternative pickle security scanner with different detection methods
4. **ModelAudit** - Comprehensive ML model security audit
5. **Trivy** - Container and dependency vulnerability scanning
6. **PyPI License Scanner** - License compliance checking

### Scanner Base Classes

All scanner implementations inherit from:
- `BaseScanner` - Provides common file discovery and filtering utilities
- `BaseScanResult` - Ensures uniform result structure across all scanners

Both base classes are defined in `app/models.py` to avoid circular dependencies.

## Organization Separation

The system implements multi-tenant architecture with organization-level isolation:

- **MinIO Buckets**: Each organization gets isolated storage (`model-total-{org_id}`)
- **Data Segregation**: Model artifacts and scan results are separated by org_id
- **Access Control**: API requests include org_id for proper data routing
- **Resource Isolation**: Background scanning tasks maintain org context

## Recursive Scanning

The validation system performs recursive file analysis:

- **Deep Directory Traversal**: Recursively scans all files in model packages
- **File Integrity Checking**: Generates SHA-256 hashes for tamper detection  
- **Manifest Comparison**: Compares current vs. stored manifests to detect changes
- **Nested Archive Support**: Handles ZIP files and compressed model formats

## Trivy DB Download and Update

### Manual Database Update
1. **Download Latest DB**: Obtain Trivy vulnerability database (.tgz/.tar.gz format)
  - `wget https://github.com/aquasecurity/trivy-db/releases/latest/download/trivy-offline.db.tgz`
  - Source doc: `https://trivy.dev/v0.17.2/air-gap/`
2. **Upload via API**: Use `/trivy` endpoint to upload database file
3. **Automatic Extraction**: System extracts to `$TRIVY_CACHE_DIR/db/`
4. **Validation**: Ensures metadata.json and trivy.db files are present

### Programmatic Update
```python
# Using the ModelTotal client
async with ModelTotal("http://localhost:8000") as client:
    result = await client.update_trivy_db('/path/to/db.tar.gz')
    print(f"Database updated: {result.success}")
```

### Database Format Requirements
- **File Format**: `.tgz` or `.tar.gz` archive
- **Contents**: Must contain `metadata.json` and `trivy.db`
- **Version**: Supports Trivy DB v2 format only
- **Size**: No explicit limits, but consider container resources

## How to Run

### Development Mode
```bash
docker-compose up --build -d
```

### Client Testing
```bash
python3 test.py /path/to/model/file
```

### Integration tests
```bash
pytest -svx tests/test_integration.py 
```

The system will be available at `http://localhost:8000` with automatic API documentation at `http://localhost:8000/docs`.