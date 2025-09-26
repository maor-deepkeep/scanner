from fastapi import APIRouter
from src.models import StaticScanInitiationRequest, StaticScanInitiationResponse, StaticScanStatus, StaticScanResult
from src.static_scan.static_scan_controller import StaticScanController


router = APIRouter(prefix="/static-scan")
controller = StaticScanController()

@router.post("/")
def static_scan_initiate(request: StaticScanInitiationRequest) -> StaticScanInitiationResponse:
    return controller.post_scan_job(request)

@router.get("/{operation_id}/status")
def static_scan_status(operation_id: str) -> StaticScanStatus:
    return controller.get_status(operation_id)

@router.get("/{operation_id}/results")
def static_scan_results(operation_id: str) -> StaticScanResult:
    return controller.get_result(operation_id)