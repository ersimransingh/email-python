import asyncio
import aiosmtplib
import smtplib
import os
from dataclasses import dataclass
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy import text
from sqlalchemy.orm import Session
import uuid

from app.core.config import SMTPConfig, EmailRecord, EmailResult, ProcessingStats
from app.models.database import EmailParameters, DigitalEmailDetails
from app.services.database_manager import db_manager
from app.utils.pdf_utils import PDFPasswordProtector
from app.utils.pdf_signing import PDFSigner


@dataclass
class _SMTPConnectionHandle:
    smtp: aiosmtplib.SMTP
    emails_sent: int
    last_activity: datetime


class _SMTPPool:
    def __init__(self, smtp_config: SMTPConfig, max_size: int):
        self.smtp_config = smtp_config
        self.max_size = max_size
        self.queue: asyncio.Queue[_SMTPConnectionHandle] = asyncio.Queue()
        self.created = 0
        self.lock = asyncio.Lock()


class EmailService:
    def __init__(self):
        self.smtp_connection: Optional[aiosmtplib.SMTP] = None
        self.current_smtp_config: Optional[SMTPConfig] = None
        self.connection_lock = asyncio.Lock()
        self.last_activity = None
        self.connection_timeout = int(os.environ.get("SMTP_CONNECTION_TIMEOUT", "300"))  # 5 minutes idle timeout
        self.max_emails_per_connection = int(os.environ.get("SMTP_MAX_EMAILS_PER_CONNECTION", "100"))
        self.emails_sent_count = 0
        self.pdf_signer = PDFSigner()  # Initialize PDF signer
        self.smtp_pools: Dict[str, _SMTPPool] = {}
        self.max_send_concurrency = max(1, int(os.environ.get("EMAIL_SEND_CONCURRENCY", "10")))
        self.smtp_pool_size = max(1, int(os.environ.get("SMTP_POOL_SIZE", str(self.max_send_concurrency))))
        self.queue_batch_size = max(1, int(os.environ.get("EMAIL_QUEUE_BATCH_SIZE", "500")))
        self.queue_batch_cap = max(self.queue_batch_size, int(os.environ.get("EMAIL_QUEUE_MAX_BATCH", "5000")))
        self.send_delay_seconds = max(0.0, float(os.environ.get("EMAIL_SEND_DELAY_SECONDS", "0")))
        self.sign_all_pdfs = os.environ.get("EMAIL_SIGN_ALL_PDFS", "true").lower() in ("1", "true", "yes")
        self.default_signer_name = os.environ.get("PDF_SIGNER_DEFAULT_NAME")

    async def get_hardware_certificate_status(self) -> Dict[str, Any]:
        """Return current status of the USB hardware certificate token."""
        try:
            return self.pdf_signer.get_hardware_token_status()
        except Exception as error:
            print(f"Error retrieving hardware token status: {error}")
            return {
                "library_path": getattr(self.pdf_signer, "pkcs11_library_path", None),
                "token_present": False,
                "certificate_found": False,
                "token_label": None,
                "slot_id": None,
                "available": False,
                "error": str(error),
            }

    async def get_smtp_details(self) -> Optional[SMTPConfig]:
        """Get default SMTP configuration from database"""
        try:
            async with db_manager.get_session() as session:
                query = text("""
                    SELECT TOP 1 SMTPServer, SMTPPort, SMTPAccountName, SMTPPassword,
                           SMTPMailId, ApplicationName, SMTPSSLFlag, ParamCode, IsActive
                    FROM tbl_EMailParameters
                    WHERE IsActive = 'Y'
                    ORDER BY ParamCode
                """)
                result = session.execute(query)
                row = result.fetchone()

                if row:
                    return SMTPConfig(
                        smtp_server=row.SMTPServer,
                        smtp_port=row.SMTPPort,
                        smtp_account_name=row.SMTPAccountName,
                        smtp_password=row.SMTPPassword,
                        smtp_mail_id=row.SMTPMailId,
                        application_name=row.ApplicationName,
                        smtp_ssl_flag=row.SMTPSSLFlag,
                        param_code=row.ParamCode,
                        is_active=row.IsActive
                    )
                return None
        except Exception as e:
            print(f"Error getting SMTP details: {e}")
            return None

    async def get_smtp_details_by_param_code(self, param_code: str) -> Optional[SMTPConfig]:
        """Get SMTP configuration by parameter code"""
        try:
            print(f"Looking for SMTP config with ParamCode: {param_code}")

            async with db_manager.get_session() as session:
                query = text("""
                    SELECT SMTPServer, SMTPPort, SMTPAccountName, SMTPPassword,
                           SMTPMailId, ApplicationName, SMTPSSLFlag, ParamCode, IsActive
                    FROM tbl_EMailParameters
                    WHERE ParamCode = :param_code AND IsActive = 'Y'
                """)
                result = session.execute(query, {"param_code": param_code})
                row = result.fetchone()

                if row:
                    print(f"SUCCESS: Found SMTP config for ParamCode: {param_code}")
                    print(f"Server: {row.SMTPServer}")
                    print(f"Port: {row.SMTPPort}")
                    print(f"Account: {row.SMTPAccountName}")
                    print(f"SSL Flag: {row.SMTPSSLFlag}")
                    print(f"Mail ID: {row.SMTPMailId}")
                    print(f"App Name: {row.ApplicationName}")

                    return SMTPConfig(
                        smtp_server=row.SMTPServer,
                        smtp_port=row.SMTPPort,
                        smtp_account_name=row.SMTPAccountName,
                        smtp_password=row.SMTPPassword,
                        smtp_mail_id=row.SMTPMailId,
                        application_name=row.ApplicationName,
                        smtp_ssl_flag=row.SMTPSSLFlag,
                        param_code=row.ParamCode,
                        is_active=row.IsActive
                    )
                else:
                    print(f"ERROR: No SMTP config found for ParamCode: {param_code}")
                return None
        except Exception as e:
            print(f"Error getting SMTP details by param code: {e}")
            return None

    async def _is_connection_healthy(self, smtp: Optional[aiosmtplib.SMTP] = None) -> bool:
        """Check if an SMTP connection is still healthy"""
        smtp = smtp or self.smtp_connection
        if not smtp:
            return False

        try:
            # Send NOOP command to check connection
            await smtp.noop()
            return True
        except Exception:
            return False

    async def _should_reconnect(self) -> bool:
        """Determine if we should create a new connection"""
        # Reconnect if no connection exists
        if not self.smtp_connection:
            return True

        # Reconnect if connection is unhealthy
        if not await self._is_connection_healthy():
            return True

        # Reconnect if we've sent too many emails on this connection
        if self.emails_sent_count >= self.max_emails_per_connection:
            return True

        # Reconnect if connection has been idle too long
        if (self.last_activity and
            (datetime.now() - self.last_activity).total_seconds() > self.connection_timeout):
            return True

        return False

    async def _close_smtp_connection(self, close_pools: bool = True):
        """Safely close SMTP connections"""
        if self.smtp_connection:
            try:
                await self.smtp_connection.quit()
            except:
                pass  # Ignore errors during cleanup
            finally:
                self.smtp_connection = None
                self.emails_sent_count = 0
        if close_pools:
            await self._close_all_smtp_pools()

    async def _create_smtp_connection(self, smtp_config: SMTPConfig) -> aiosmtplib.SMTP:
        """Create a new SMTP connection with improved timeout and error handling"""
        print("=" * 60)
        print("CREATING NEW SMTP CONNECTION")
        print("=" * 60)
        print(f"SMTP Server: {smtp_config.smtp_server}")
        print(f"Port: {smtp_config.smtp_port}")
        print(f"Account: {smtp_config.smtp_account_name}")
        print(f"Password: {'*' * len(smtp_config.smtp_password) if smtp_config.smtp_password else 'Not provided'}")
        print(f"SSL Flag: {smtp_config.smtp_ssl_flag}")
        print(f"Mail ID: {smtp_config.smtp_mail_id}")
        print(f"App Name: {smtp_config.application_name}")
        print("=" * 60)

        # Determine TLS/SSL settings
        use_ssl = smtp_config.smtp_port == 465  # SSL port (immediate TLS)
        use_starttls = smtp_config.smtp_port == 587  # STARTTLS port (upgrade to TLS after connection)

        print(f"Connection Type:")
        print(f"   - Use SSL (port 465): {use_ssl}")
        print(f"   - Use STARTTLS (port 587): {use_starttls}")
        print(f"   - SSL Flag from DB: {smtp_config.smtp_ssl_flag}")
        print("=" * 60)

        # Increased timeout for better reliability
        connection_timeout = 180  # 180 seconds (3 minutes) timeout for port 587 STARTTLS

        # Try multiple connection strategies
        connection_strategies = []

        if use_ssl:
            # Strategy for port 465 (SSL/TLS)
            connection_strategies.append(("SSL/TLS", {
                "hostname": smtp_config.smtp_server,
                "port": smtp_config.smtp_port,
                "use_tls": True,
                "start_tls": False,
                "timeout": connection_timeout,
                "validate_certs": False  # Match Node.js rejectUnauthorized: false
            }))
        else:
            # Strategies for port 587 (STARTTLS)
            # IMPORTANT: For port 587, use_tls should be False, then manually call starttls()
            connection_strategies.append(("STARTTLS", {
                "hostname": smtp_config.smtp_server,
                "port": smtp_config.smtp_port,
                "use_tls": False,
                "start_tls": False,  # Don't auto-starttls, we'll do it manually
                "timeout": connection_timeout,
                "validate_certs": False  # Match Node.js rejectUnauthorized: false
            }))

        last_error = None

        for strategy_name, smtp_params in connection_strategies:
            try:
                print(f"Trying strategy: {strategy_name}")
                smtp = aiosmtplib.SMTP(**smtp_params)

                print("Connecting to SMTP server...")
                await smtp.connect()
                print("SUCCESS: Connected successfully!")

                # Check if we need to do STARTTLS (for port 587)
                if strategy_name == "STARTTLS":
                    try:
                        print("Starting TLS encryption via STARTTLS...")
                        # Check if STARTTLS is supported
                        if smtp.supports_extension("STARTTLS"):
                            await smtp.starttls(validate_certs=False)
                            print("SUCCESS: TLS encryption started!")
                        else:
                            print("WARNING: Server doesn't advertise STARTTLS support, attempting anyway...")
                            await smtp.starttls(validate_certs=False)
                            print("SUCCESS: TLS encryption started!")
                    except Exception as tls_error:
                        print(f"TLS Error: {tls_error}")
                        # If STARTTLS fails, the connection might already be encrypted
                        if "already using TLS" in str(tls_error).lower():
                            print("INFO: Connection appears to already be using TLS")
                        else:
                            raise tls_error

                # Login if credentials provided
                if smtp_config.smtp_account_name and smtp_config.smtp_password:
                    print("Authenticating...")
                    await smtp.login(smtp_config.smtp_account_name, smtp_config.smtp_password)
                    print("SUCCESS: Authentication successful!")

                print(f"SUCCESS: SMTP connection established using {strategy_name}!")
                print("=" * 60)
                return smtp

            except Exception as e:
                print(f"ERROR: {strategy_name} failed: {str(e)}")
                last_error = e
                try:
                    await smtp.quit()
                except:
                    pass

        # If all strategies failed, raise the last error
        print("ERROR: All connection strategies failed!")
        print("=" * 60)
        raise last_error if last_error else Exception("Unknown SMTP connection error")

    async def _get_smtp_connection(self, smtp_config: SMTPConfig) -> aiosmtplib.SMTP:
        """Get a healthy SMTP connection, creating/reconnecting if necessary"""
        async with self.connection_lock:
            # Check if we need to reconnect
            if await self._should_reconnect():
                print("Connection needs refresh - creating new connection...")

                # Close existing connection without affecting pooled connections
                await self._close_smtp_connection(close_pools=False)

                # Create new connection
                self.smtp_connection = await self._create_smtp_connection(smtp_config)
                self.current_smtp_config = smtp_config
                self.emails_sent_count = 0
                self.last_activity = datetime.now()

                print("New persistent SMTP connection established!")
            else:
                print("Reusing existing SMTP connection")

            # Update activity timestamp
            self.last_activity = datetime.now()
            return self.smtp_connection

    def _make_smtp_pool_key(self, smtp_config: SMTPConfig) -> str:
        return "|".join(
            [
                smtp_config.smtp_server or "",
                str(smtp_config.smtp_port or ""),
                smtp_config.smtp_account_name or "",
                smtp_config.param_code or "",
            ]
        )

    def _get_smtp_pool(self, smtp_config: SMTPConfig) -> _SMTPPool:
        pool_key = self._make_smtp_pool_key(smtp_config)
        pool = self.smtp_pools.get(pool_key)
        if pool is None:
            pool = _SMTPPool(smtp_config, self.smtp_pool_size)
            self.smtp_pools[pool_key] = pool
        return pool

    async def _should_reconnect_handle(self, handle: _SMTPConnectionHandle) -> bool:
        if handle.emails_sent >= self.max_emails_per_connection:
            return True
        if handle.last_activity and (datetime.now() - handle.last_activity).total_seconds() > self.connection_timeout:
            return True
        if not await self._is_connection_healthy(handle.smtp):
            return True
        return False

    async def _acquire_smtp_handle(self, smtp_config: SMTPConfig) -> tuple[_SMTPPool, _SMTPConnectionHandle]:
        pool = self._get_smtp_pool(smtp_config)
        try:
            handle = pool.queue.get_nowait()
        except asyncio.QueueEmpty:
            handle = None

        if handle is None:
            async with pool.lock:
                if pool.created < pool.max_size:
                    smtp = await self._create_smtp_connection(smtp_config)
                    handle = _SMTPConnectionHandle(smtp=smtp, emails_sent=0, last_activity=datetime.now())
                    pool.created += 1
            if handle is None:
                handle = await pool.queue.get()

        if await self._should_reconnect_handle(handle):
            await self._discard_smtp_handle(pool, handle)
            smtp = await self._create_smtp_connection(smtp_config)
            handle = _SMTPConnectionHandle(smtp=smtp, emails_sent=0, last_activity=datetime.now())
            async with pool.lock:
                pool.created += 1

        return pool, handle

    async def _release_smtp_handle(self, pool: _SMTPPool, handle: _SMTPConnectionHandle) -> None:
        handle.last_activity = datetime.now()
        await pool.queue.put(handle)

    async def _discard_smtp_handle(self, pool: _SMTPPool, handle: _SMTPConnectionHandle) -> None:
        try:
            await handle.smtp.quit()
        except Exception:
            pass
        async with pool.lock:
            pool.created = max(0, pool.created - 1)

    async def _close_all_smtp_pools(self):
        for pool in self.smtp_pools.values():
            while True:
                try:
                    handle = pool.queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                try:
                    await handle.smtp.quit()
                except Exception:
                    pass
            pool.created = 0
        self.smtp_pools = {}

    @staticmethod
    def _coerce_bytes(value: Optional[bytes]) -> Optional[bytes]:
        if value is None:
            return None
        if isinstance(value, bytes):
            return value
        if isinstance(value, bytearray):
            return bytes(value)
        if isinstance(value, memoryview):
            return value.tobytes()
        try:
            return bytes(value)
        except Exception:
            return None

    async def send_email_with_attachment(
        self,
        email_record: EmailRecord,
        signing_status: Optional[Dict[str, Any]] = None,
    ) -> EmailResult:
        """Send email with PDF attachment"""
        try:
            # Get SMTP configuration
            smtp_config = None
            if email_record.dd_email_param_code:
                smtp_config = await self.get_smtp_details_by_param_code(email_record.dd_email_param_code)

            if not smtp_config:
                smtp_config = await self.get_smtp_details()

            if not smtp_config:
                return EmailResult(
                    success=False,
                    recipient=email_record.dd_to_emailid,
                    cc=email_record.dd_cc_emailid,
                    error="No SMTP configuration found"
                )

            # Create email message
            message = MIMEMultipart()
            message["From"] = smtp_config.smtp_mail_id
            message["To"] = email_record.dd_to_emailid
            if email_record.dd_cc_emailid:
                message["Cc"] = email_record.dd_cc_emailid
            message["Subject"] = email_record.dd_subject

            # Add body
            message.attach(MIMEText(email_record.dd_body_text, "html"))

            # Track if a new protected PDF was created
            new_protected_pdf = None
            signing_info_saved = False
            signing_required = False

            # Add attachment if exists
            if email_record.dd_document and email_record.dd_filename:
                # Determine which document to use as attachment
                attachment_data = self._coerce_bytes(email_record.dd_document)
                filename = email_record.dd_filename

                if not attachment_data:
                    return EmailResult(
                        success=False,
                        recipient=email_record.dd_to_emailid,
                        cc=email_record.dd_cc_emailid,
                        error="Attachment data is missing or invalid"
                    )

                # Check if password protection is needed and document is a PDF
                if (email_record.dd_encpassword and
                    email_record.dd_encpassword.strip() and
                    PDFPasswordProtector.is_pdf_data(attachment_data)):

                    print(f"PDF password protection required for email ID {email_record.dd_srno}")

                    # Check if we already have a protected version
                    if email_record.dd_finaldocument:
                        print("Using existing password-protected PDF from dd_finaldocument")
                        existing_protected = self._coerce_bytes(email_record.dd_finaldocument)
                        if existing_protected:
                            attachment_data = existing_protected
                        else:
                            print("Stored password-protected PDF is invalid; recreating...")
                            email_record.dd_finaldocument = None
                    else:
                        print("Creating new password-protected PDF...")
                        try:
                            # Protect the PDF with password
                            protected_pdf = PDFPasswordProtector.protect_pdf_with_password(
                                attachment_data,
                                email_record.dd_encpassword
                            )

                            # Verify the protection worked
                            if PDFPasswordProtector.verify_pdf_protection(protected_pdf, email_record.dd_encpassword):
                                attachment_data = protected_pdf
                                print("PDF password protection successful - using protected version")

                                # Mark for saving to database after successful email sending
                                new_protected_pdf = protected_pdf
                            else:
                                print("PDF password protection verification failed - using original")

                        except Exception as pdf_error:
                            print(f"Error protecting PDF: {pdf_error}")
                            print("Using original PDF without protection")
                else:
                    print(f"No password protection needed for email ID {email_record.dd_srno}")

                # Check if PDF digital signing is needed
                signing_flag_enabled = (email_record.dd_signed_flag or "").strip().upper() == "Y"
                is_pdf_attachment = PDFPasswordProtector.is_pdf_data(attachment_data)
                signing_required = is_pdf_attachment and (self.sign_all_pdfs or signing_flag_enabled)
                signer_name = (email_record.dd_signedby or "").strip()

                if signing_required:
                    if not signer_name:
                        signer_name = self.default_signer_name or smtp_config.application_name or "Digital Signature"

                    print(f"PDF digital signing required for email ID {email_record.dd_srno} by {signer_name}")
                    signing_status = signing_status or self.pdf_signer.get_signing_status()
                    if not signing_status.get("available"):
                        pkcs12_status = signing_status.get("pkcs12") or {}
                        hardware_status = signing_status.get("hardware") or {}
                        reason = pkcs12_status.get("error") or hardware_status.get("error") or "Signing certificate unavailable"
                        token_label = hardware_status.get("token_label") or "unknown"
                        print(
                            f"Digital signing required but certificate unavailable for email ID {email_record.dd_srno}: {reason} "
                            f"(token label: {token_label}). Skipping this email - it will remain pending."
                        )
                        return EmailResult(
                            success=False,
                            recipient=email_record.dd_to_emailid,
                            cc=email_record.dd_cc_emailid,
                            error=f"Digital signing required but certificate unavailable: {reason}. Email skipped - will retry when certificate is available.",
                            retry_later=True
                        )

                    try:
                        signing_result = await asyncio.to_thread(
                            self.pdf_signer.sign_pdf_with_certificate,
                            attachment_data,
                            signer_name,
                            pdf_password=(
                                email_record.dd_encpassword.strip()
                                if email_record.dd_encpassword and email_record.dd_encpassword.strip()
                                else None
                            ),
                        )
                    except Exception as signing_error:
                        print(f"Error during PDF signing: {signing_error}")
                        return EmailResult(
                            success=False,
                            recipient=email_record.dd_to_emailid,
                            cc=email_record.dd_cc_emailid,
                            error=f"PDF signing failed: {signing_error}"
                        )

                    if not signing_result.get("success") or not signing_result.get("signed_pdf"):
                        error_message = signing_result.get("error", "Unknown error")
                        print(f"PDF signing failed: {error_message}")
                        return EmailResult(
                            success=False,
                            recipient=email_record.dd_to_emailid,
                            cc=email_record.dd_cc_emailid,
                            error=f"PDF signing failed: {error_message}"
                        )

                    attachment_data = signing_result["signed_pdf"]
                    print("PDF successfully digitally signed")

                    email_record.dd_signedby = signer_name
                    email_record.dd_signedon = signing_result["signed_on"]
                    email_record.dd_signedtm = signing_result["signed_time"]

                    try:
                        await self.save_signing_info(
                            email_record.dd_srno,
                            signer_name,
                            email_record.dd_signedon,
                            email_record.dd_signedtm,
                        )
                        signing_info_saved = True
                    except Exception as signing_save_error:
                        print(f"Warning: Signed PDF but failed to save signing information: {signing_save_error}")
                else:
                    print(
                        f"Digital signing not required for email ID {email_record.dd_srno} "
                        f"(dd_signed_flag: {email_record.dd_signed_flag or 'N'}, sign_all: {self.sign_all_pdfs}) - proceeding with email sending"
                    )

                attachment = MIMEApplication(attachment_data, Name=filename)
                attachment['Content-Disposition'] = f'attachment; filename="{filename}"'
                message.attach(attachment)

            pool = None
            smtp_handle = None
            release_handle = False
            try:
                pool, smtp_handle = await self._acquire_smtp_handle(smtp_config)
                smtp = smtp_handle.smtp
                release_handle = True

                recipients = [email_record.dd_to_emailid]
                if email_record.dd_cc_emailid:
                    cc_addresses = [addr.strip() for addr in email_record.dd_cc_emailid.split(",")]
                    recipients.extend(cc_addresses)
                    print(f"CC Recipients: {cc_addresses}")

                message_id = str(uuid.uuid4())
                message["Message-ID"] = f"<{message_id}@{smtp_config.smtp_server}>"

                print(f"Sending email via pooled connection...")
                print(f"TO: {email_record.dd_to_emailid}")
                print(f"CC: {email_record.dd_cc_emailid or 'None'}")
                print(f"Total Recipients: {recipients}")
                send_errors, server_response = await smtp.send_message(message, recipients=recipients)

                if send_errors:
                    error_messages = "; ".join(
                        f"{recipient}: {resp.code} {resp.message}"
                        for recipient, resp in send_errors.items()
                    )
                    print(f"SMTP rejected recipient(s): {error_messages}")
                    raise Exception(f"SMTP rejected recipient(s): {error_messages}")

                if server_response:
                    print(f"SMTP response: {server_response}")

                smtp_handle.emails_sent += 1
                self.emails_sent_count += 1
                print(f"Email sent successfully using pooled connection!")
            except Exception:
                if pool is not None and smtp_handle is not None:
                    release_handle = False
                    await self._discard_smtp_handle(pool, smtp_handle)
                raise
            finally:
                if release_handle and pool is not None and smtp_handle is not None:
                    await self._release_smtp_handle(pool, smtp_handle)

            # If a new protected PDF was created, save it to the database
            if new_protected_pdf:
                try:
                    await self.save_protected_pdf(email_record.dd_srno, new_protected_pdf)
                except Exception as pdf_save_error:
                    print(f"Warning: Email sent successfully but failed to save protected PDF: {pdf_save_error}")

            # If PDF signing information was updated, save it to the database
            if (signing_required and
                email_record.dd_signedby and
                email_record.dd_signedon and
                email_record.dd_signedtm and
                not signing_info_saved):
                try:
                    await self.save_signing_info(
                        email_record.dd_srno,
                        email_record.dd_signedby,
                        email_record.dd_signedon,
                        email_record.dd_signedtm
                    )
                except Exception as signing_save_error:
                    print(f"Warning: Email sent successfully but failed to save signing information: {signing_save_error}")

            return EmailResult(
                success=True,
                message_id=message_id,
                recipient=email_record.dd_to_emailid,
                cc=email_record.dd_cc_emailid
            )

        except Exception as e:
            print(f"Error sending email: {str(e)}")
            # Avoid tearing down pooled connections for a single message failure
            await self._close_smtp_connection(close_pools=False)

            return EmailResult(
                success=False,
                recipient=email_record.dd_to_emailid,
                cc=email_record.dd_cc_emailid,
                error=str(e)
            )

    async def send_test_email(self, to_email: str) -> EmailResult:
        """Send test email to verify SMTP configuration using persistent connection"""
        try:
            smtp_config = await self.get_smtp_details()
            if not smtp_config:
                return EmailResult(
                    success=False,
                    recipient=to_email,
                    error="No SMTP configuration found"
                )

            # Get persistent connection
            smtp = await self._get_smtp_connection(smtp_config)

            # Create test email
            message = MIMEMultipart()
            message["From"] = smtp_config.smtp_mail_id
            message["To"] = to_email
            message["Subject"] = "Test Email from Email Service"

            body = f"""
            <html>
            <body>
                <h2>Email Service Test</h2>
                <p>This is a test email from the Python Email Service.</p>
                <p><strong>SMTP Server:</strong> {smtp_config.smtp_server}:{smtp_config.smtp_port}</p>
                <p><strong>Application:</strong> {smtp_config.application_name}</p>
                <p><strong>Connection Type:</strong> Persistent Connection (#{self.emails_sent_count + 1})</p>
                <p><strong>Sent at:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>If you received this email, the SMTP configuration is working correctly.</p>
            </body>
            </html>
            """
            message.attach(MIMEText(body, "html"))

            # Send test email using persistent connection
            message_id = str(uuid.uuid4())
            message["Message-ID"] = f"<{message_id}@{smtp_config.smtp_server}>"

            print("Sending test email via persistent connection...")
            send_errors, server_response = await smtp.send_message(
                message,
                recipients=[to_email],
            )

            if send_errors:
                error_messages = "; ".join(
                    f"{recipient}: {resp.code} {resp.message}"
                    for recipient, resp in send_errors.items()
                )
                print(f"SMTP rejected recipient(s): {error_messages}")
                raise Exception(f"SMTP rejected recipient(s): {error_messages}")

            if server_response:
                print(f"SMTP response: {server_response}")

            # Increment counter
            self.emails_sent_count += 1
            print("Test email sent successfully via persistent connection!")

            return EmailResult(
                success=True,
                message_id=message_id,
                recipient=to_email
            )

        except Exception as e:
            print(f"Error sending test email: {str(e)}")
            # Close connection on error
            await self._close_smtp_connection(close_pools=False)

            return EmailResult(
                success=False,
                recipient=to_email,
                error=str(e)
            )

    async def close_connections(self):
        """Manually close SMTP connections - useful for cleanup"""
        await self._close_smtp_connection()
        print("All SMTP connections closed.")

    async def get_pending_emails(self, limit: int = 50, include_high_retry: bool = False) -> List[EmailRecord]:
        """Get pending emails from database queue

        Args:
            limit: Maximum number of emails to fetch
            include_high_retry: If True, includes emails with retry_count >= 3
        """
        try:
            async with db_manager.get_session() as session:
                # SQL Server doesn't support parameterized TOP, so we'll use string formatting
                # with a safe integer limit
                safe_limit = int(limit) if isinstance(limit, (int, str)) and str(limit).isdigit() else 50
                safe_limit = min(safe_limit, self.queue_batch_cap)

                # Build WHERE clause based on parameters
                if include_high_retry:
                    where_clause = "WHERE dd_SendFlag = 'N'"
                    print(f"Fetching ALL pending emails (including high retry count)...")
                else:
                    where_clause = "WHERE dd_SendFlag = 'N' AND dd_RetryCount < 3"
                    print(f"Fetching pending emails with retry count < 3...")

                query = text(f"""
                    SELECT TOP {safe_limit} dd_srno, dd_document, dd_filename, dd_toEmailid, dd_ccEmailid,
                           dd_subject, dd_bodyText, dd_SendFlag, dd_EmailParamCode, dd_RetryCount,
                           dd_Encpassword, dd_Finaldocument, dd_signedFlag, dd_signedby, dd_signedon, dd_signedtm
                    FROM Digital_Emaildetails
                    {where_clause}
                    ORDER BY dd_srno
                """)

                print(f"Executing query: {query}")
                result = session.execute(query)
                rows = result.fetchall()

                print(f"Found {len(rows)} pending email(s)")

                emails = []
                emails_requiring_signing = 0
                emails_not_requiring_signing = 0
                
                for row in rows:
                    document_data = self._coerce_bytes(row.dd_document)
                    final_document_data = self._coerce_bytes(row.dd_Finaldocument)
                    email_record = EmailRecord(
                        dd_srno=row.dd_srno,
                        dd_document=document_data,
                        dd_filename=row.dd_filename,
                        dd_to_emailid=row.dd_toEmailid,
                        dd_cc_emailid=row.dd_ccEmailid,
                        dd_subject=row.dd_subject,
                        dd_body_text=row.dd_bodyText,
                        dd_send_flag=row.dd_SendFlag,
                        dd_email_param_code=row.dd_EmailParamCode,
                        dd_retry_count=row.dd_RetryCount,
                        dd_encpassword=row.dd_Encpassword,
                        dd_finaldocument=final_document_data,
                        dd_signed_flag=row.dd_signedFlag,
                        dd_signedby=row.dd_signedby,
                        dd_signedon=row.dd_signedon,
                        dd_signedtm=row.dd_signedtm
                    )
                    emails.append(email_record)
                    
                    # Count signing requirements
                    if (row.dd_signedFlag or "").strip().upper() == "Y":
                        emails_requiring_signing += 1
                    else:
                        emails_not_requiring_signing += 1
                        
                    print(f"  - Email ID {row.dd_srno}: {row.dd_toEmailid} (Retry: {row.dd_RetryCount}, Signing: {(row.dd_signedFlag or 'N').upper()})")

                # Print summary of signing requirements
                if emails_requiring_signing > 0 or emails_not_requiring_signing > 0:
                    print(f"Email signing summary: {emails_requiring_signing} emails require digital signing, {emails_not_requiring_signing} emails can be sent without signing")

                return emails
        except Exception as e:
            print(f"Error getting pending emails: {e}")
            return []

    async def reset_email_retry_count(self, email_id: int):
        """Reset retry count for a specific email to allow reprocessing"""
        try:
            async with db_manager.get_session() as session:
                query = text("""
                    UPDATE Digital_Emaildetails
                    SET dd_RetryCount = 0, dd_BounceReason = ''
                    WHERE dd_srno = :email_id
                """)
                session.execute(query, {"email_id": email_id})
                session.commit()
                print(f"Reset retry count for email ID {email_id}")
        except Exception as e:
            print(f"Error resetting retry count: {e}")

    async def reset_all_failed_emails(self):
        """Reset all failed emails to pending status for reprocessing"""
        try:
            async with db_manager.get_session() as session:
                # Use empty string instead of NULL to avoid constraint issues
                query = text("""
                    UPDATE Digital_Emaildetails
                    SET dd_SendFlag = 'N', dd_RetryCount = 0, dd_BounceReason = ''
                    WHERE dd_SendFlag = 'F' OR (dd_SendFlag = 'N' AND dd_RetryCount >= 3)
                """)
                result = session.execute(query)
                session.commit()
                print(f"Reset {result.rowcount} failed emails to pending status")
                return result.rowcount
        except Exception as e:
            print(f"Error resetting failed emails: {e}")
            return 0

    async def update_email_status(self, email_id: int, status: str, message_id: str = None, error: str = None):
        """Update email status in database"""
        try:
            async with db_manager.get_session() as session:
                if status == "Y":  # Success
                    query = text("""
                        UPDATE Digital_Emaildetails
                        SET dd_SendFlag = :status, dd_SentDate = :sent_date
                        WHERE dd_srno = :email_id
                    """)
                    session.execute(query, {
                        "status": status,
                        "sent_date": datetime.now(),
                        "email_id": email_id
                    })
                else:  # Failed
                    query = text("""
                        UPDATE Digital_Emaildetails
                        SET dd_SendFlag = :status, dd_BounceReason = :error,
                            dd_RetryCount = dd_RetryCount + 1, dd_LastRetryDate = :retry_date
                        WHERE dd_srno = :email_id
                    """)
                    session.execute(query, {
                        "status": status,
                        "error": error,
                        "retry_date": datetime.now(),
                        "email_id": email_id
                    })

                session.commit()
        except Exception as e:
            print(f"Error updating email status: {e}")

    async def save_protected_pdf(self, email_id: int, protected_pdf_data: bytes):
        """Save password-protected PDF to dd_Finaldocument column"""
        try:
            async with db_manager.get_session() as session:
                query = text("""
                    UPDATE Digital_Emaildetails
                    SET dd_Finaldocument = :pdf_data
                    WHERE dd_srno = :email_id
                """)
                session.execute(query, {
                    "pdf_data": protected_pdf_data,
                    "email_id": email_id
                })
                session.commit()
                print(f"Protected PDF saved to database for email ID {email_id}")
        except Exception as e:
            print(f"Error saving protected PDF: {e}")

    async def save_signing_info(self, email_id: int, signed_by: str, signed_on: any, signed_time: any):
        """Save PDF signing information to database"""
        try:
            async with db_manager.get_session() as session:
                # Convert datetime objects to strings for database storage
                signed_on_str = signed_on.strftime('%Y%m%d') if hasattr(signed_on, 'strftime') else str(signed_on)
                signed_time_str = signed_time.strftime('%H:%M:%S') if hasattr(signed_time, 'strftime') else str(signed_time)

                query = text("""
                    UPDATE Digital_Emaildetails
                    SET dd_signedby = :signed_by, dd_signedon = :signed_on, dd_signedtm = :signed_time
                    WHERE dd_srno = :email_id
                """)
                session.execute(query, {
                    "signed_by": signed_by,
                    "signed_on": signed_on_str,
                    "signed_time": signed_time_str,
                    "email_id": email_id
                })
                session.commit()
                print(f"PDF signing information saved to database for email ID {email_id}")
        except Exception as e:
            print(f"Error saving signing information: {e}")

    async def process_email_queue(self, include_high_retry: bool = False) -> ProcessingStats:
        """Process all pending emails in queue using pooled SMTP connections.

        Args:
            include_high_retry: If True, processes emails even with retry_count >= 3
        """
        stats = ProcessingStats(processed=0, success=0, failed=0, skipped=0)
        batch_index = 0

        try:
            while True:
                pending_emails = await self.get_pending_emails(
                    limit=self.queue_batch_size,
                    include_high_retry=include_high_retry,
                )
                if not pending_emails:
                    break

                batch_index += 1
                total_emails = len(pending_emails)
                print(
                    f"\nProcessing batch {batch_index} with {total_emails} pending emails using pooled SMTP connections..."
                )

                signing_status = None
                signing_needed = self.sign_all_pdfs or any(
                    (record.dd_signed_flag or '').strip().upper() == 'Y' for record in pending_emails
                )

                if signing_needed:
                    signing_status = self.pdf_signer.get_signing_status()
                    if signing_status.get('available'):
                        if signing_status.get('pkcs12', {}).get('available') and not self.pdf_signer.force_hardware_token:
                            print('Digital signing available via PKCS#12 certificate')
                        else:
                            print('Digital signing available via hardware token')
                    else:
                        pkcs12_status = signing_status.get('pkcs12') or {}
                        hardware_status = signing_status.get('hardware') or {}
                        reason = pkcs12_status.get('error') or hardware_status.get('error') or 'Signing certificate unavailable'
                        print(f"Digital signing is not available ({reason})")
                        print('  - Emails requiring signing will be skipped and remain pending')

                semaphore = asyncio.Semaphore(self.max_send_concurrency)

                async def _process_one(email_record: EmailRecord):
                    async with semaphore:
                        try:
                            result = await self.send_email_with_attachment(
                                email_record,
                                signing_status=signing_status,
                            )
                        except Exception as error:
                            result = EmailResult(
                                success=False,
                                recipient=email_record.dd_to_emailid,
                                cc=email_record.dd_cc_emailid,
                                error=str(error),
                            )

                        if self.send_delay_seconds > 0:
                            await asyncio.sleep(self.send_delay_seconds)

                        if getattr(result, 'retry_later', False):
                            return 'skipped', email_record, result

                        if result.success:
                            await self.update_email_status(email_record.dd_srno, 'Y', result.message_id)
                            return 'success', email_record, result

                        await self.update_email_status(email_record.dd_srno, 'F', error=result.error)
                        return 'failed', email_record, result

                tasks = [asyncio.create_task(_process_one(email_record)) for email_record in pending_emails]

                for task in asyncio.as_completed(tasks):
                    status, email_record, result = await task

                    if status == 'skipped':
                        stats.skipped += 1
                        reason = result.error or 'Deferred for retry'
                        print(f"SKIPPED: Email {email_record.dd_srno} deferred: {reason}")
                        continue

                    stats.processed += 1
                    if status == 'success':
                        stats.success += 1
                        print(f"SUCCESS: Email {email_record.dd_srno} sent and marked as successful")
                    else:
                        stats.failed += 1
                        print(f"FAILED: Email {email_record.dd_srno} failed: {result.error}")

            await self._close_smtp_connection()
            print(
                f"\nEmail queue processing completed. Connection closed. Processed: {stats.processed}, "
                f"Sent: {stats.success}, Failed: {stats.failed}, Skipped: {stats.skipped}"
            )

        except Exception as e:
            print(f"Error processing email queue: {e}")
            await self._close_smtp_connection()

        return stats

    async def get_email_statistics(self) -> Dict[str, int]:
        """Get email processing statistics"""
        try:
            async with db_manager.get_session() as session:
                # Get total processed emails
                query = text("SELECT COUNT(*) as total FROM Digital_Emaildetails")
                result = session.execute(query)
                total_processed = result.scalar()

                # Get sent emails
                query = text("SELECT COUNT(*) as sent FROM Digital_Emaildetails WHERE dd_SendFlag = 'Y'")
                result = session.execute(query)
                total_sent = result.scalar()

                # Get failed emails
                query = text("SELECT COUNT(*) as failed FROM Digital_Emaildetails WHERE dd_SendFlag = 'F'")
                result = session.execute(query)
                total_failed = result.scalar()

                # Get pending emails
                query = text("SELECT COUNT(*) as pending FROM Digital_Emaildetails WHERE dd_SendFlag = 'N'")
                result = session.execute(query)
                pending_count = result.scalar()

                return {
                    "total_processed": total_processed or 0,
                    "total_sent": total_sent or 0,
                    "total_failed": total_failed or 0,
                    "pending_count": pending_count or 0
                }
        except Exception as e:
            print(f"Error getting email statistics: {e}")
            return {
                "total_processed": 0,
                "total_sent": 0,
                "total_failed": 0,
                "pending_count": 0
            }


# Global email service instance
email_service = EmailService()

