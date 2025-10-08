import asyncio
import aiosmtplib
import smtplib
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


class EmailService:
    def __init__(self):
        self.smtp_connection: Optional[aiosmtplib.SMTP] = None
        self.current_smtp_config: Optional[SMTPConfig] = None
        self.connection_lock = asyncio.Lock()
        self.last_activity = None
        self.connection_timeout = 300  # 5 minutes idle timeout
        self.max_emails_per_connection = 100  # Reconnect after N emails
        self.emails_sent_count = 0
        self.pdf_signer = PDFSigner()  # Initialize PDF signer

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

    async def _is_connection_healthy(self) -> bool:
        """Check if current SMTP connection is still healthy"""
        if not self.smtp_connection:
            return False

        try:
            # Send NOOP command to check connection
            await self.smtp_connection.noop()
            return True
        except:
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

    async def _close_smtp_connection(self):
        """Safely close the current SMTP connection"""
        if self.smtp_connection:
            try:
                await self.smtp_connection.quit()
            except:
                pass  # Ignore errors during cleanup
            finally:
                self.smtp_connection = None
                self.emails_sent_count = 0

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
        connection_timeout = 60  # 1 minute timeout

        # Try multiple connection strategies
        connection_strategies = []

        if use_ssl:
            # Strategy for port 465 (SSL/TLS)
            connection_strategies.append(("SSL/TLS", {
                "hostname": smtp_config.smtp_server,
                "port": smtp_config.smtp_port,
                "use_tls": True,
                "timeout": connection_timeout,
                "validate_certs": False  # Match Node.js rejectUnauthorized: false
            }))
        else:
            # Strategies for port 587 (STARTTLS)
            connection_strategies.extend([
                ("STARTTLS", {
                    "hostname": smtp_config.smtp_server,
                    "port": smtp_config.smtp_port,
                    "use_tls": False,
                    "timeout": connection_timeout,
                    "validate_certs": False  # Match Node.js rejectUnauthorized: false
                }),
                ("Direct TLS (fallback)", {
                    "hostname": smtp_config.smtp_server,
                    "port": smtp_config.smtp_port,
                    "use_tls": True,
                    "timeout": connection_timeout,
                    "validate_certs": False  # Match Node.js rejectUnauthorized: false
                })
            ])

        last_error = None

        for strategy_name, smtp_params in connection_strategies:
            try:
                print(f"Trying strategy: {strategy_name}")
                smtp = aiosmtplib.SMTP(**smtp_params)

                print("Connecting to SMTP server...")
                await smtp.connect()
                print("SUCCESS: Connected successfully!")

                # Check if we need to do STARTTLS
                if strategy_name == "STARTTLS" and smtp_config.smtp_ssl_flag == "Y":
                    try:
                        print("Starting TLS encryption via STARTTLS...")
                        await smtp.starttls()
                        print("SUCCESS: TLS encryption started!")
                    except Exception as tls_error:
                        print(f"TLS Error: {tls_error}")
                        # If STARTTLS fails, the connection might already be encrypted
                        if "already using TLS" in str(tls_error):
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

                # Close existing connection
                await self._close_smtp_connection()

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

    async def send_email_with_attachment(self, email_record: EmailRecord) -> EmailResult:
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

            # Add attachment if exists
            if email_record.dd_document and email_record.dd_filename:
                # Determine which document to use as attachment
                attachment_data = email_record.dd_document
                filename = email_record.dd_filename

                # Check if password protection is needed and document is a PDF
                if (email_record.dd_encpassword and
                    email_record.dd_encpassword.strip() and
                    PDFPasswordProtector.is_pdf_data(email_record.dd_document)):

                    print(f"PDF password protection required for email ID {email_record.dd_srno}")

                    # Check if we already have a protected version
                    if email_record.dd_finaldocument:
                        print("Using existing password-protected PDF from dd_finaldocument")
                        attachment_data = email_record.dd_finaldocument
                    else:
                        print("Creating new password-protected PDF...")
                        try:
                            # Protect the PDF with password
                            protected_pdf = PDFPasswordProtector.protect_pdf_with_password(
                                email_record.dd_document,
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
                signer_name = (email_record.dd_signedby or "").strip()

                if signing_flag_enabled:
                    if not PDFPasswordProtector.is_pdf_data(attachment_data):
                        print(f"Signing flag enabled for email ID {email_record.dd_srno} but attachment is not a PDF; skipping digital signature.")
                    elif not signer_name:
                        print(f"Signing flag enabled for email ID {email_record.dd_srno} but signer name is missing; skipping digital signature.")
                    else:
                        print(f"PDF digital signing required for email ID {email_record.dd_srno} by {signer_name}")
                        token_status = await self.get_hardware_certificate_status()
                        if not token_status.get("available"):
                            default_reason = ("Hardware token not detected"
                                               if not token_status.get("token_present")
                                               else "Certificate not found on hardware token")
                            reason = token_status.get("error") or default_reason
                            token_label = token_status.get("token_label") or "unknown"
                            print(
                                f"Digital signing postponed for email ID {email_record.dd_srno}: {reason} "
                                f"(token label: {token_label})"
                            )
                            return EmailResult(
                                success=False,
                                recipient=email_record.dd_to_emailid,
                                cc=email_record.dd_cc_emailid,
                                error=f"Digital signing postponed: {reason}",
                                retry_later=True
                            )
                        try:
                            signing_result = self.pdf_signer.sign_pdf_with_certificate(
                                attachment_data,
                                signer_name,
                                pdf_password=(
                                    email_record.dd_encpassword.strip()
                                    if email_record.dd_encpassword and email_record.dd_encpassword.strip()
                                    else None
                                ),
                            )

                            if signing_result["success"]:
                                if signing_result.get("signed_pdf"):
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
                                    print("PDF signing completed but no signed data returned")
                            else:
                                print(f"PDF signing failed: {signing_result.get('error', 'Unknown error')}")
                                print("Proceeding with unsigned PDF")
                        except Exception as signing_error:
                            print(f"Error during PDF signing: {signing_error}")
                            print("Proceeding with unsigned PDF")
                else:
                    print(f"Digital signing not required for email ID {email_record.dd_srno} (flag: {email_record.dd_signed_flag or 'N'})")

                attachment = MIMEApplication(attachment_data, Name=filename)
                attachment['Content-Disposition'] = f'attachment; filename="{filename}"'
                message.attach(attachment)

            # Get persistent SMTP connection instead of creating new one
            smtp = await self._get_smtp_connection(smtp_config)

            recipients = [email_record.dd_to_emailid]
            if email_record.dd_cc_emailid:
                cc_addresses = [addr.strip() for addr in email_record.dd_cc_emailid.split(",")]
                recipients.extend(cc_addresses)
                print(f"CC Recipients: {cc_addresses}")

            message_id = str(uuid.uuid4())
            message["Message-ID"] = f"<{message_id}@{smtp_config.smtp_server}>"

            print(f"Sending email via persistent connection (email #{self.emails_sent_count + 1})...")
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

            # Increment counter but don't close connection (persistent)
            self.emails_sent_count += 1
            print(f"Email sent successfully using persistent connection!")

            # If a new protected PDF was created, save it to the database
            if new_protected_pdf:
                try:
                    await self.save_protected_pdf(email_record.dd_srno, new_protected_pdf)
                except Exception as pdf_save_error:
                    print(f"Warning: Email sent successfully but failed to save protected PDF: {pdf_save_error}")

            # If PDF signing information was updated, save it to the database
            if ((email_record.dd_signed_flag or "").strip().upper() == "Y" and
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
            # On error, close connection to ensure clean state for next attempt
            await self._close_smtp_connection()

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
            await self._close_smtp_connection()

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
                safe_limit = min(safe_limit, 1000)  # Cap at 1000 for safety

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
                for row in rows:
                    email_record = EmailRecord(
                        dd_srno=row.dd_srno,
                        dd_document=row.dd_document,
                        dd_filename=row.dd_filename,
                        dd_to_emailid=row.dd_toEmailid,
                        dd_cc_emailid=row.dd_ccEmailid,
                        dd_subject=row.dd_subject,
                        dd_body_text=row.dd_bodyText,
                        dd_send_flag=row.dd_SendFlag,
                        dd_email_param_code=row.dd_EmailParamCode,
                        dd_retry_count=row.dd_RetryCount,
                        dd_encpassword=row.dd_Encpassword,
                        dd_finaldocument=row.dd_Finaldocument,
                        dd_signed_flag=row.dd_signedFlag,
                        dd_signedby=row.dd_signedby,
                        dd_signedon=row.dd_signedon,
                        dd_signedtm=row.dd_signedtm
                    )
                    emails.append(email_record)
                    print(f"  - Email ID {row.dd_srno}: {row.dd_toEmailid} (Retry: {row.dd_RetryCount})")

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
        """Process all pending emails in queue using persistent connection

        Args:
            include_high_retry: If True, processes emails even with retry_count >= 3
        """
        stats = ProcessingStats(processed=0, success=0, failed=0)

        try:
            pending_emails = await self.get_pending_emails(include_high_retry=include_high_retry)
            total_emails = len(pending_emails)

            print(f"\nProcessing {total_emails} pending emails using persistent SMTP connection...")

            for index, email_record in enumerate(pending_emails):
                print(f"\n[{index + 1}/{total_emails}] Processing email ID {email_record.dd_srno}")
                result = await self.send_email_with_attachment(email_record)

                if getattr(result, "retry_later", False):
                    stats.skipped += 1
                    reason = result.error or "Deferred for retry"
                    print(f"SKIPPED: Email {email_record.dd_srno} deferred: {reason}")
                    continue

                stats.processed += 1

                if result.success:
                    await self.update_email_status(email_record.dd_srno, "Y", result.message_id)
                    stats.success += 1
                    print(f"SUCCESS: Email {email_record.dd_srno} sent and marked as successful")
                else:
                    await self.update_email_status(email_record.dd_srno, "F", error=result.error)
                    stats.failed += 1
                    print(f"FAILED: Email {email_record.dd_srno} failed: {result.error}")

                if index < total_emails - 1:
                    await asyncio.sleep(0.5)

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

