from pydantic import BaseModel, EmailStr
from typing import Optional, Dict, Any
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