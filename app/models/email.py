from pydantic import BaseModel, EmailStr
from typing import Optional, Dict, Any, List
from datetime import datetime


class EmailTestRequest(BaseModel):
    email: EmailStr


class EmailTestResponse(BaseModel):
    success: bool
    message_id: Optional[str] = None
    recipient: str
    message: Optional[str] = None
    error: Optional[str] = None


class EmailProcessResponse(BaseModel):
    success: bool
    message: str
    timestamp: datetime
    processed: Optional[int] = None
    sent: Optional[int] = None
    failed: Optional[int] = None
    skipped: Optional[int] = None


class CertificateStatusResponse(BaseModel):
    success: bool
    available: bool
    token_present: bool
    certificate_found: bool
    token_label: Optional[str] = None
    slot_id: Optional[int] = None
    certificate_id: Optional[str] = None
    certificate_subject: Optional[str] = None
    certificate_not_valid_before: Optional[str] = None
    certificate_not_valid_after: Optional[str] = None
    library_path: Optional[str] = None
    error: Optional[str] = None


class ServiceControlRequest(BaseModel):
    action: str  # "start" or "stop"
    user: str


class ServiceControlResponse(BaseModel):
    success: bool
    message: str
    status: Dict[str, Any]


class ServiceStatusResponse(BaseModel):
    success: bool
    status: str
    started_at: Optional[datetime] = None
    last_activity: Optional[datetime] = None
    next_run: Optional[datetime] = None
    is_processing: bool = False


class DashboardStats(BaseModel):
    total_processed: int
    total_sent: int
    total_failed: int
    pending_count: int


class DashboardResponse(BaseModel):
    database: Dict[str, Any]
    schedule: Dict[str, Any]
    service: Dict[str, Any]


class CertificateInfo(BaseModel):
    subject: str
    issuer: str
    serial_number: str
    not_valid_before: str
    not_valid_after: str
    thumbprint: str
    has_private_key: bool
    store_name: Optional[str] = None
    store_location: Optional[str] = None
    source: str  # "System Store" or "Hardware Token"
    token_label: Optional[str] = None
    slot_id: Optional[int] = None


class AllCertificatesResponse(BaseModel):
    success: bool
    total_certificates: int
    system_certificates: List[CertificateInfo]
    hardware_certificates: List[CertificateInfo]
    error: Optional[str] = None


class CertificatePinPayload(BaseModel):
    token_label: str
    certificate_id: Optional[str] = None
    slot_id: Optional[int] = None
    pin: str
    certificate_subject: Optional[str] = None
    certificate_serial: Optional[str] = None


class CertificatePinOperationResult(BaseModel):
    token_label: str
    certificate_id: Optional[str] = None
    slot_id: Optional[int] = None
    success: bool
    message: str
    pin_valid: Optional[bool] = None
    pin_last_verified_at: Optional[str] = None
    error: Optional[str] = None


class CertificatePinSetRequest(BaseModel):
    entries: List[CertificatePinPayload]


class CertificatePinSetResponse(BaseModel):
    success: bool
    results: List[CertificatePinOperationResult]


class HardwareCertificatePinStatus(BaseModel):
    token_present: bool
    token_label: Optional[str] = None
    slot_id: Optional[int] = None
    certificate_id: Optional[str] = None
    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    not_valid_before: Optional[str] = None
    not_valid_after: Optional[str] = None
    pin_configured: bool
    pin_valid: Optional[bool] = None
    pin_last_verified_at: Optional[str] = None
    pin_last_error: Optional[str] = None


class CertificatePinStatusResponse(BaseModel):
    success: bool
    total_certificates: int
    certificates: List[HardwareCertificatePinStatus]
    error: Optional[str] = None
