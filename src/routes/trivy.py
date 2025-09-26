import os
import tarfile
import tempfile
import logging
from datetime import datetime
from fastapi import APIRouter, HTTPException, UploadFile, File
from src.models import TrivyDBUpdateResult

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/trivy")

@router.post("/")
async def update_trivy_database(file: UploadFile = File(...)) -> TrivyDBUpdateResult:
    """
    Extract uploaded Trivy database .tgz / .tar.gz file to the cache directory.
    """

    logger.info(f"Uploading Trivy database: {file.filename}")

    # Validate file type
    if not file.filename.endswith(('.tgz', '.tar.gz')):
        raise HTTPException(status_code=400, detail="File must be a .tgz or .tar.gz file")
    
    # Get the Trivy cache directory from environment
    cache_dir = os.getenv('TRIVY_CACHE_DIR')
    if not cache_dir:
        raise HTTPException(status_code=500, detail="TRIVY_CACHE_DIR environment variable not set")
    
    try:
        logger.info("Creating db folder inside cache dir")

        # Ensure the cache directory exists
        db_dir = os.path.join(cache_dir, 'db')
        os.makedirs(db_dir, exist_ok=True)

        with tempfile.NamedTemporaryFile(suffix='.tgz', delete=False) as temp_file:
            # Stream file in chunks to handle large files
            chunk_size = 8 * 1024 * 1024  # 8MB chunks for better performance
            bytes_written = 0

            while chunk := await file.read(chunk_size):
                temp_file.write(chunk)
                bytes_written += len(chunk)

                if bytes_written % (50 * 1024 * 1024) == 0:  # Log progress every 50MB
                    logger.info(f"Upload progress: {bytes_written / (1024 * 1024):.1f}MB")

            temp_file_path = temp_file.name
            logger.info(f"File saved: {bytes_written / (1024 * 1024):.1f}MB")
        
        logger.info(f"Extracting database to {db_dir}")

        # Extract the .tgz/.tar.gz file to the database directory
        with tarfile.open(temp_file_path, 'r:*') as tar:
            tar.extractall(path=db_dir)
        
        # Clean up the temporary file
        os.unlink(temp_file_path)
        
        logger.info(f"Trivy database updated successfully")
        return TrivyDBUpdateResult(
            success=True,
            updated_at=datetime.now()
        )
        
    except tarfile.TarError as e:
        logger.error(f"Failed to extract Trivy database: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to extract Trivy database: {e}")
    except Exception as e:
        logger.error(f"Unexpected error updating Trivy database: {e}")
        raise HTTPException(status_code=500, detail=f"Unexpected error updating Trivy database: {e}")
