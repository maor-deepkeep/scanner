import logging

from fastapi import FastAPI

from src.routes.static_scan import router as static_scan_router
from src.routes.trivy import router as trivy_router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

app = FastAPI(title="ModelTotal API", version="1.0.0")
app.include_router(static_scan_router)
app.include_router(trivy_router)