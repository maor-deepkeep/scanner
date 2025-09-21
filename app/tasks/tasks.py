import os

from celery import Celery
from celery.result import AsyncResult
from static_scan.static_scanner import StaticScanner
from models import StaticScanInitiationRequest

DATABASE = "scan_results"

celery_app = Celery(
    "worker",
    broker=f"{os.environ['REDIS_URL']}",
    backend=f"{os.environ['MONGODB_URL']}/scan_results",
)

celery_app.conf.update(
    mongodb_backend_settings={
        "database": DATABASE,
        "taskmeta_collection": "task_meta"
    },
    task_track_started=True
)

def get_task_status(operation_id: str) -> AsyncResult:
    return celery_app.AsyncResult(operation_id)

def get_task_result(operation_id: str) -> AsyncResult:
    result = celery_app.AsyncResult(operation_id)
    if not result.ready():
        raise Exception("Result is not ready")
    return result.result

def _create_progress_callback(task_instance):
    """
    Private function to create a progress callback for Celery tasks.
    
    Args:
        task_instance: The Celery task instance (self)
        
    Returns:
        Callable that updates the task progress
    """
    def progress_callback(current: int):
        """Callback function to update Celery task progress"""
        task_instance.update_state(
            state='PROGRESS',
            meta={'current': current, 'total': 100}
        )
    
    return progress_callback

@celery_app.task(bind=True)
def scan_task(self, request_data: dict) -> dict:
    static_scanner = StaticScanner()
    request = StaticScanInitiationRequest(**request_data)
    progress_callback = _create_progress_callback(self)
    
    response = static_scanner.scan(request, self.request.id, progress_callback=progress_callback)
    return response

