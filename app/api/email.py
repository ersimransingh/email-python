from fastapi import APIRouter, HTTPException, Depends, status
from datetime import datetime

from app.core.config import EmailConfig
from app.models.email import (
    EmailTestRequest, EmailTestResponse,
    EmailProcessResponse, DashboardResponse
)
from app.services.email_service import email_service
from app.services.email_worker import email_worker
from app.services.database_manager import db_manager
from app.api.auth import get_current_user

router = APIRouter()


@router.post("/save-email-config")
async def save_email_config(
    config: EmailConfig,
    current_user: dict = Depends(get_current_user)
):
    """Save email service configuration"""
    try:
        # Save the configuration
        email_worker.save_config(config)

        return {
            "success": True,
            "message": "Email service configuration saved successfully"
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error saving email configuration: {str(e)}"
        )


@router.get("/check-email-config")
async def check_email_config(current_user: dict = Depends(get_current_user)):
    """Check if email configuration exists"""
    try:
        exists = email_worker.config_exists()
        return {"exists": exists}

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error checking email configuration: {str(e)}"
        )


@router.post("/email-test", response_model=EmailTestResponse)
async def test_email(
    request: EmailTestRequest,
    current_user: dict = Depends(get_current_user)
):
    """Send test email to verify SMTP configuration"""
    try:
        result = await email_service.send_test_email(str(request.email))

        if result.success:
            return EmailTestResponse(
                success=True,
                message_id=result.message_id,
                recipient=result.recipient,
                message="Test email sent successfully"
            )
        else:
            return EmailTestResponse(
                success=False,
                recipient=result.recipient,
                error=result.error,
                message="Test email failed to send"
            )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error sending test email: {str(e)}"
        )


@router.post("/email-force-process", response_model=EmailProcessResponse)
async def force_process_emails(current_user: dict = Depends(get_current_user)):
    """Force process emails immediately"""
    try:
        result = await email_worker.force_process_emails()

        return EmailProcessResponse(
            success=True,
            message=result.get("message", "Email processing completed"),
            timestamp=result.get("timestamp", datetime.now()),
            processed=result.get("processed"),
            sent=result.get("success"),
            failed=result.get("failed")
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error processing emails: {str(e)}"
        )


@router.get("/dashboard", response_model=DashboardResponse)
async def get_dashboard_data(current_user: dict = Depends(get_current_user)):
    """Get comprehensive dashboard data"""
    try:
        # Get database status
        db_status = await db_manager.check_database_status()

        # Get email statistics
        email_stats = await email_service.get_email_statistics()

        # Get worker status
        worker_status = await email_worker.get_status()

        # Get schedule information
        schedule_info = await email_worker.get_schedule_info()

        dashboard_data = {
            "database": {
                "connected": db_status.get("connected", False),
                "server": db_status.get("server"),
                "database": db_status.get("database"),
                "last_checked": db_status.get("last_checked"),
                "response_time": db_status.get("response_time"),
                "message": db_status.get("message")
            },
            "schedule": {
                "start_time": schedule_info.get("start_time"),
                "end_time": schedule_info.get("end_time"),
                "interval": schedule_info.get("interval"),
                "interval_unit": schedule_info.get("interval_unit"),
                "is_active": schedule_info.get("is_active", False),
                "within_schedule": schedule_info.get("within_schedule", False),
                "next_run": schedule_info.get("next_run")
            },
            "service": {
                "status": worker_status.status,
                "started_at": worker_status.started_at.isoformat() if worker_status.started_at else None,
                "last_activity": worker_status.last_activity.isoformat() if worker_status.last_activity else None,
                "next_run": worker_status.next_run.isoformat() if worker_status.next_run else None,
                "is_processing": worker_status.is_processing,
                "email_stats": {
                    "total_processed": email_stats.get("total_processed", 0),
                    "total_sent": email_stats.get("total_sent", 0),
                    "total_failed": email_stats.get("total_failed", 0),
                    "pending_count": email_stats.get("pending_count", 0)
                }
            }
        }

        return dashboard_data

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting dashboard data: {str(e)}"
        )