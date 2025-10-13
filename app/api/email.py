from fastapi import APIRouter, HTTPException, Depends, status
from typing import List
from datetime import datetime

from app.core.config import EmailConfig
from app.models.email import (
    EmailTestRequest, EmailTestResponse,
    EmailProcessResponse, DashboardResponse, CertificateStatusResponse,
    AllCertificatesResponse, CertificatePinSetRequest,
    CertificatePinSetResponse, CertificatePinStatusResponse,
    HardwareCertificatePinStatus
)
from app.services.email_service import email_service
from app.services.email_worker import email_worker
from app.services.database_manager import db_manager
from app.api.auth import get_current_user
from app.utils.certificate_utils import get_all_certificates

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


@router.get("/certificate-status", response_model=CertificateStatusResponse)
async def get_certificate_status(current_user: dict = Depends(get_current_user)):
    """Check status of USB hardware certificate token."""
    try:
        status_data = await email_service.get_hardware_certificate_status()
        available = bool(status_data.get("available"))

        return CertificateStatusResponse(
            success=available,
            available=available,
            token_present=bool(status_data.get("token_present")),
            certificate_found=bool(status_data.get("certificate_found")),
            token_label=status_data.get("token_label"),
            slot_id=status_data.get("slot_id"),
            certificate_id=status_data.get("certificate_id"),
            certificate_subject=status_data.get("certificate_subject"),
            certificate_not_valid_before=status_data.get("certificate_not_valid_before"),
            certificate_not_valid_after=status_data.get("certificate_not_valid_after"),
            library_path=status_data.get("library_path"),
            error=status_data.get("error"),
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error checking certificate status: {str(e)}"
        )


@router.get("/certificates", response_model=AllCertificatesResponse)
async def list_all_certificates(current_user: dict = Depends(get_current_user)):
    """
    List all certificates attached to the computer.

    This endpoint enumerates both:
    - System certificates from Windows certificate stores (Personal, Root, Intermediate)
    - Hardware token certificates from USB security tokens

    Returns detailed information about each certificate including:
    - Subject and issuer
    - Validity period
    - Serial number and thumbprint
    - Whether it has a private key
    - Source location (system store or hardware token)
    """
    try:
        result = get_all_certificates()

        return AllCertificatesResponse(
            success=result["success"],
            total_certificates=result["total_certificates"],
            system_certificates=result["system_certificates"],
            hardware_certificates=result["hardware_certificates"],
            error=result.get("error")
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error listing certificates: {str(e)}"
        )


@router.post("/certificates/pins", response_model=CertificatePinSetResponse)
async def set_certificate_pins(
    request: CertificatePinSetRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Store or update PINs for hardware token certificates.

    Validates the supplied PIN immediately when the PKCS#11 library is available.
    """
    if not request.entries:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one certificate entry is required"
        )

    pin_manager = getattr(email_service.pdf_signer, "pin_manager", None)
    if pin_manager is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Certificate PIN manager is not initialised"
        )

    results = []
    all_successful = True
    library_path = email_service.pdf_signer.pkcs11_library_path

    for entry in request.entries:
        metadata = {
            "subject": entry.certificate_subject,
            "serial_number": entry.certificate_serial,
        }
        try:
            stored_entry = pin_manager.set_pin(
                token_label=entry.token_label,
                certificate_id=entry.certificate_id,
                pin=entry.pin,
                slot_id=entry.slot_id,
                metadata=metadata,
                validate=True,
                pkcs11_library=library_path,
            )
            pin_valid = stored_entry.get("pin_valid")
            if pin_valid is True:
                message = "PIN stored and validated successfully"
            elif pin_valid is None:
                message = stored_entry.get("last_verification_error") or "PIN stored; validation not performed"
            else:
                message = "PIN stored"

            results.append({
                "token_label": entry.token_label,
                "certificate_id": entry.certificate_id,
                "slot_id": entry.slot_id,
                "success": True,
                "message": message,
                "pin_valid": pin_valid,
                "pin_last_verified_at": stored_entry.get("last_verified_at"),
                "error": None,
            })
        except ValueError as validation_error:
            all_successful = False
            results.append({
                "token_label": entry.token_label,
                "certificate_id": entry.certificate_id,
                "slot_id": entry.slot_id,
                "success": False,
                "message": "Failed to store PIN",
                "pin_valid": False,
                "pin_last_verified_at": None,
                "error": str(validation_error),
            })
        except Exception as unexpected_error:
            all_successful = False
            results.append({
                "token_label": entry.token_label,
                "certificate_id": entry.certificate_id,
                "slot_id": entry.slot_id,
                "success": False,
                "message": "Unexpected error while storing PIN",
                "pin_valid": None,
                "pin_last_verified_at": None,
                "error": str(unexpected_error),
            })

    return CertificatePinSetResponse(success=all_successful, results=results)


@router.get("/certificates/pins/status", response_model=CertificatePinStatusResponse)
async def get_certificate_pin_status(
    refresh: bool = False,
    current_user: dict = Depends(get_current_user)
):
    """
    Report the configured PIN status for hardware token certificates.

    When `refresh` is true, the API will attempt to re-validate stored PINs
    against the connected tokens (requires the token to be inserted).
    """
    pin_manager = getattr(email_service.pdf_signer, "pin_manager", None)
    if pin_manager is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Certificate PIN manager is not initialised"
        )

    library_path = email_service.pdf_signer.pkcs11_library_path

    try:
        certificates_info = get_all_certificates()
        hardware_certificates = certificates_info.get("hardware_certificates", [])
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error enumerating certificates: {str(e)}"
        )

    statuses: List[HardwareCertificatePinStatus] = []
    seen_entries = set()

    for cert in hardware_certificates:
        token_label = cert.get("token_label")
        certificate_id = cert.get("thumbprint")
        slot_id = cert.get("slot_id")

        entry = pin_manager.get_entry(token_label, certificate_id) if token_label else None
        if not entry and token_label:
            entry = pin_manager.get_entry(token_label)

        if entry and entry.get("pin") and (refresh or entry.get("pin_valid") is None):
            validation_status, validation_error = pin_manager.validate_pin(
                token_label=token_label,
                slot_id=slot_id,
                pin=entry.get("pin"),
                pkcs11_library=library_path,
            )
            pin_manager.record_validation(token_label, certificate_id, validation_status, validation_error)
            entry = pin_manager.get_entry(token_label, certificate_id) if token_label else None
            if not entry and token_label:
                entry = pin_manager.get_entry(token_label)

        pin_configured = bool(entry)
        statuses.append(
            HardwareCertificatePinStatus(
                token_present=True,
                token_label=token_label,
                slot_id=slot_id,
                certificate_id=certificate_id,
                subject=cert.get("subject"),
                issuer=cert.get("issuer"),
                serial_number=cert.get("serial_number"),
                not_valid_before=cert.get("not_valid_before"),
                not_valid_after=cert.get("not_valid_after"),
                pin_configured=pin_configured,
                pin_valid=entry.get("pin_valid") if entry else None,
                pin_last_verified_at=entry.get("last_verified_at") if entry else None,
                pin_last_error=entry.get("last_verification_error") if entry else None,
            )
        )

        if token_label:
            seen_key = f"{token_label}::{certificate_id or ''}".lower()
            seen_entries.add(seen_key)

    for stored_entry in pin_manager.list_entries():
        token_label = stored_entry.get("token_label")
        certificate_id = stored_entry.get("certificate_id")
        seen_key = f"{token_label}::{certificate_id or ''}".lower()
        if seen_key in seen_entries:
            continue

        metadata = stored_entry.get("metadata") or {}
        statuses.append(
            HardwareCertificatePinStatus(
                token_present=False,
                token_label=token_label,
                slot_id=stored_entry.get("slot_id"),
                certificate_id=certificate_id,
                subject=metadata.get("subject"),
                issuer=metadata.get("issuer"),
                serial_number=metadata.get("serial_number") or metadata.get("certificate_serial"),
                not_valid_before=metadata.get("not_valid_before"),
                not_valid_after=metadata.get("not_valid_after"),
                pin_configured=True,
                pin_valid=stored_entry.get("pin_valid"),
                pin_last_verified_at=stored_entry.get("last_verified_at"),
                pin_last_error=stored_entry.get("last_verification_error"),
            )
        )

    return CertificatePinStatusResponse(
        success=True,
        total_certificates=len(statuses),
        certificates=statuses,
        error=None
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
            failed=result.get("failed"),
            skipped=result.get("skipped")
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
