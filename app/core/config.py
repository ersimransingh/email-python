from pydantic import BaseModel
from typing import Optional, Literal
from datetime import datetime


class DatabaseConfig(BaseModel):
    server: str
    port: int
    user: str
    password: str
    database: str


class EmailConfig(BaseModel):
    start_time: str
    end_time: str
    interval: int
    interval_unit: Literal["minutes", "hours"]
    db_request_timeout: int
    db_connection_timeout: int
    username: str
    password: str


class SMTPConfig(BaseModel):
    smtp_server: str
    smtp_port: int
    smtp_account_name: str
    smtp_password: str
    smtp_mail_id: str
    application_name: str
    smtp_ssl_flag: Optional[str] = None
    param_code: Optional[str] = None
    is_active: Optional[str] = "Y"


class EmailRecord(BaseModel):
    dd_srno: Optional[int] = None
    dd_document: Optional[bytes] = None
    dd_filename: Optional[str] = None
    dd_to_emailid: str
    dd_cc_emailid: Optional[str] = None
    dd_subject: str
    dd_body_text: str
    dd_send_flag: str = "N"
    dd_email_param_code: Optional[str] = None
    dd_retry_count: int = 0
    dd_sent_date: Optional[datetime] = None
    dd_bounce_reason: Optional[str] = None
    dd_last_retry_date: Optional[datetime] = None
    dd_encpassword: Optional[str] = None  # Password for PDF encryption
    dd_finaldocument: Optional[bytes] = None  # Password-protected PDF
    dd_signed_flag: Optional[str] = None  # Database flag indicating whether signing is required
    dd_signedby: Optional[str] = None  # Name of person who signed the document
    dd_signedon: Optional[str] = None  # Date when document was signed (as string from DB)
    dd_signedtm: Optional[str] = None  # Time when document was signed (as string from DB)


class EmailResult(BaseModel):
    success: bool
    message_id: Optional[str] = None
    recipient: str
    cc: Optional[str] = None
    error: Optional[str] = None


class ProcessingStats(BaseModel):
    processed: int
    success: int
    failed: int


class WorkerStatus(BaseModel):
    status: str
    started_at: Optional[datetime] = None
    last_activity: Optional[datetime] = None
    next_run: Optional[datetime] = None
    is_processing: bool = False


class Settings:
    DATABASE_ENCRYPTION_KEY: str = "your-32-byte-encryption-key-here-1234567890123456"
    JWT_SECRET_KEY: str = "your-jwt-secret-key-should-be-long-and-secure-1234567890"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REDIS_URL: str = "redis://localhost:6379"
    LOG_LEVEL: str = "INFO"


settings = Settings()