from fastapi import APIRouter, HTTPException, Depends, status
from datetime import datetime

from app.models.email import (
    ServiceControlRequest, ServiceControlResponse,
    ServiceStatusResponse
)
from app.services.email_worker import email_worker
from app.api.auth import get_current_user

router = APIRouter()


@router.post("/service-control", response_model=ServiceControlResponse)
async def control_email_service(
    request: ServiceControlRequest,
    current_user: dict = Depends(get_current_user)
):
    """Start or stop the email processing service"""
    try:
        if request.action.lower() == "start":
            await email_worker.start()

            status_info = await email_worker.get_status()
            schedule_info = await email_worker.get_schedule_info()

            return ServiceControlResponse(
                success=True,
                message="Email service started successfully",
                status={
                    "service_status": status_info.status,
                    "started_at": status_info.started_at.isoformat() if status_info.started_at else None,
                    "started_by": request.user,
                    "schedule": {
                        "start_time": schedule_info.get("start_time"),
                        "end_time": schedule_info.get("end_time"),
                        "interval": schedule_info.get("interval"),
                        "interval_unit": schedule_info.get("interval_unit"),
                        "next_run": schedule_info.get("next_run")
                    }
                }
            )

        elif request.action.lower() == "stop":
            await email_worker.stop()

            return ServiceControlResponse(
                success=True,
                message="Email service stopped successfully",
                status={
                    "service_status": "stopped",
                    "stopped_at": datetime.now().isoformat(),
                    "stopped_by": request.user
                }
            )

        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid action. Use 'start' or 'stop'"
            )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error controlling service: {str(e)}"
        )


@router.get("/service-status", response_model=ServiceStatusResponse)
async def get_service_status(current_user: dict = Depends(get_current_user)):
    """Get current email service status"""
    try:
        status_info = await email_worker.get_status()

        return ServiceStatusResponse(
            success=True,
            status=status_info.status,
            started_at=status_info.started_at,
            last_activity=status_info.last_activity,
            next_run=status_info.next_run,
            is_processing=status_info.is_processing
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting service status: {str(e)}"
        )