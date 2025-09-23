import logging

from app.tasks.tasks import scan_task, get_task_status, get_task_result
from app.models import StaticScanInitiationRequest, StaticScanInitiationResponse, StaticScanStatus, StaticScanResult

logger = logging.getLogger(__name__)

class StaticScanController:

    def post_scan_job(self, request: StaticScanInitiationRequest) -> StaticScanInitiationResponse:
        task = scan_task.delay(request.model_dump(mode='json'))
        logger.info(f"Task created with id: {task.id}")
        return StaticScanInitiationResponse(success=True, operation_id=task.id)

    def get_status(self, operation_id: str) -> StaticScanStatus:
        result = get_task_status(operation_id)
        
        # Extract progress information from task metadata
        progress = 0
        error = None
        
        logger.info(f'Asked for status, current status: {result.state}')
        if result.state == 'PROGRESS':
            # Extract progress from meta if available
            if result.info and isinstance(result.info, dict):
                progress = result.info.get('current', 0)
        elif result.state == 'SUCCESS':
            progress = 100
        elif result.state == 'FAILURE':
            progress = 0
            error = str(result.info) if result.info else "Task failed"
        elif result.state == 'PENDING':
            progress = 0
        
        return StaticScanStatus(
            operation_id=operation_id, 
            status=result.state, 
            progress=progress,
            error=error
        )

    def get_result(self, operation_id: str) -> StaticScanResult:
        result = get_task_result(operation_id)
        static_scan_result = StaticScanResult(**result)
        return static_scan_result