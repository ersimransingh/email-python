"""
PDF Digital Signing utilities using endesive and PyKCS11
"""

import io
import os
import datetime
from typing import Optional, Dict, Any, List, Tuple
from pathlib import Path

# Configuration for PDF signing
DEFAULT_TOKEN_PIN = "Secmark123"
DEFAULT_CERTIFICATE_PATH = "signing_certificate.p12"  # Add your certificate path
DEFAULT_CERTIFICATE_PASSWORD = "certificate_password"  # Add your certificate password

# Hardware token defaults
DEFAULT_PKCS11_LIBRARY = os.environ.get("PDF_SIGNER_PKCS11_LIB", r"C:\\\Windows\\System32\\eTPKCS11.dll")
DEFAULT_TOKEN_LABEL_HINTS = ["Secmark", "Card", "A33F79EEA4260E4B"]

class SafeNetTokenSigner:
    """Minimal helper to interact with SafeNet (or compatible) USB tokens via PKCS#11."""

    def __init__(self, pin: str, library_path: str, label_hints: List[str]):
        self.pin = pin
        self.library_path = library_path
        self.pkcs11_lib = library_path  # Backwards-compatible attribute name
        self.label_hints = label_hints
        self.pkcs11 = None
        self.session = None
        self._cached_certificate = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

    def cleanup(self):
        try:
            if self.session:
                self.session.logout()
                self.session.closeSession()
        except Exception:
            pass
        finally:
            self.session = None
        try:
            if self.pkcs11:
                self.pkcs11.unload()
        except Exception:
            pass
        finally:
            self.pkcs11 = None
            self._cached_certificate = None

    def login(self):
        try:
            import PyKCS11 as PK11
        except ImportError as exc:
            raise RuntimeError('PyKCS11 is required for hardware token signing') from exc

        try:
            print(f"[INFO] Loading PKCS#11 library: {self.pkcs11_lib}")
            self.pkcs11 = PK11.PyKCS11Lib()
            self.pkcs11.load(self.pkcs11_lib)

            slots = self.pkcs11.getSlotList(tokenPresent=True)
            if not slots:
                raise RuntimeError('No PKCS#11 tokens detected')

            label_hints_lower = [hint.lower() for hint in self.label_hints if hint]
            target_slot = None
            target_label = None
            for slot in slots:
                token_info = self.pkcs11.getTokenInfo(slot)
                token_name = token_info.label.strip()
                print(f"[INFO] Found token: '{token_name}' in slot {slot}")
                token_name_normalised = token_name.lower()
                if any(hint in token_name_normalised for hint in label_hints_lower):
                    target_slot = slot
                    target_label = token_name
                    print(f"[OK] Using token: {token_name}")
                    break

            if target_slot is None:
                target_slot = slots[0]
                token_info = self.pkcs11.getTokenInfo(target_slot)
                target_label = token_info.label.strip()
                print(f"[WARN] Using first available token: {target_label}")

            self.session = self.pkcs11.openSession(
                target_slot, PK11.CKF_SERIAL_SESSION | PK11.CKF_RW_SESSION
            )
            self.session.login(self.pin)
            print(f"[OK] Successfully logged into SafeNet token '{target_label}'")

        except Exception as error:
            print(f"[ERROR] Login failed: {error}")
            raise

    def certificate(self):
        if self.session is None:
            raise RuntimeError('Token session not initialised; call login() first')
        if self._cached_certificate:
            return self._cached_certificate

        try:
            import PyKCS11 as PK11
        except ImportError as exc:
            raise RuntimeError('PyKCS11 is required for hardware token signing') from exc

        try:
            pkcs11_objects = self.session.findObjects([(PK11.CKA_CLASS, PK11.CKO_CERTIFICATE)])
        except Exception as error:
            raise RuntimeError(f'Failed to enumerate certificates: {error}') from error

        if not pkcs11_objects:
            raise RuntimeError('No certificates found on token')

        print(f"[OK] Found {len(pkcs11_objects)} certificate(s) on token")

        for index, pk11_object in enumerate(pkcs11_objects, start=1):
            print(f"[CHECK] Examining certificate {index}...")
            try:
                cert_attrs = self.session.getAttributeValue(pk11_object, [PK11.CKA_VALUE])
            except Exception as attr_error:
                print(f"[WARN] Certificate {index}: Error getting attributes: {attr_error}")
                continue

            if not cert_attrs or not cert_attrs[0]:
                print(f"[WARN] Certificate {index}: No certificate value found")
                continue

            cert_der = bytes(cert_attrs[0])
            if not cert_der:
                print(f"[WARN] Certificate {index}: Empty certificate data")
                continue

            print(f"[OK] Certificate {index}: Found certificate data ({len(cert_der)} bytes)")

            try:
                id_attrs = self.session.getAttributeValue(pk11_object, [PK11.CKA_ID])
                if id_attrs and id_attrs[0]:
                    cert_id = bytes(id_attrs[0])
                else:
                    cert_id = bytes([index - 1])
                    print(f"[WARN] Certificate {index}: No ID found, using generated ID")
            except Exception as id_error:
                cert_id = bytes([index - 1])
                print(f"[WARN] Certificate {index}: Error getting ID, using generated ID ({id_error})")

            try:
                from cryptography import x509
                cert_obj = x509.load_der_x509_certificate(cert_der)
                subject_parts = [f"{attribute.oid._name}={attribute.value}" for attribute in cert_obj.subject]
                subject_str = ", ".join(subject_parts)
                print(f"[OK] Certificate {index} subject: {subject_str}")
                subject_upper = subject_str.upper()
            except Exception as parse_error:
                subject_upper = ""
                print(f"[WARN] Certificate {index}: Could not parse certificate details: {parse_error}")
            if any(keyword in subject_upper for keyword in ("SECMARK", "CONSULTANCY", "LIMITED")):
                print(f"[TARGET] Certificate {index}: This appears to be the Secmark certificate!")
                self._cached_certificate = (cert_id, cert_der)
                return self._cached_certificate

            print(f"[OK] Certificate {index}: Using this certificate (ID: {cert_id.hex()})")
            self._cached_certificate = (cert_id, cert_der)
            return self._cached_certificate
        raise RuntimeError('No usable certificates found - all certificates failed to load')

    def sign(self, keyid, data, mech):
        if self.session is None:
            raise RuntimeError('Token session not initialised; call login() first')

        try:
            import PyKCS11 as PK11
        except ImportError as exc:
            raise RuntimeError('PyKCS11 is required for hardware token signing') from exc

        try:
            private_keys = self.session.findObjects([
                (PK11.CKA_CLASS, PK11.CKO_PRIVATE_KEY),
                (PK11.CKA_ID, keyid),
            ])
        except Exception as error:
            raise RuntimeError(f'Failed to query private keys: {error}') from error

        if not private_keys:
            raise RuntimeError('Private key not found for the certificate')

        if isinstance(mech, str):
            mechanism_map = {
                'sha1': PK11.Mechanism(PK11.CKM_SHA1_RSA_PKCS, None),
                'sha224': PK11.Mechanism(PK11.CKM_SHA224_RSA_PKCS, None),
                'sha256': PK11.Mechanism(PK11.CKM_SHA256_RSA_PKCS, None),
                'sha384': PK11.Mechanism(PK11.CKM_SHA384_RSA_PKCS, None),
                'sha512': PK11.Mechanism(PK11.CKM_SHA512_RSA_PKCS, None),
            }
            mech_obj = mechanism_map.get(mech.lower())
            if mech_obj is None:
                raise ValueError(f"Unsupported mechanism '{mech}'")
        else:
            mech_obj = mech

        mechanism_repr = getattr(mech_obj, 'mechanism', mech_obj)
        print(f"[INFO] Signing with mechanism: {mechanism_repr}")
        try:
            signature = self.session.sign(private_keys[0], data, mech_obj)
        except Exception as sign_error:
            print(f"[ERROR] Signing failed: {sign_error}")
            raise

        print(f"[OK] Data signed successfully, signature size: {len(signature)} bytes")
        return bytes(signature)



class PDFSigner:
    """Utility class for PDF digital signing"""

    def __init__(self, certificate_path: str = None, certificate_password: str = None, token_pin: str = None):
        self.certificate_path = certificate_path or DEFAULT_CERTIFICATE_PATH
        self.certificate_password = certificate_password or DEFAULT_CERTIFICATE_PASSWORD
        self.token_pin = token_pin or os.environ.get('PDF_SIGNER_TOKEN_PIN', DEFAULT_TOKEN_PIN)
        self.pkcs11_library_path = os.environ.get('PDF_SIGNER_PKCS11_LIB', DEFAULT_PKCS11_LIBRARY)
        hints_env = os.environ.get('PDF_SIGNER_TOKEN_HINTS')
        if hints_env:
            self.token_label_hints = [hint.strip() for hint in hints_env.split(',') if hint.strip()]
        else:
            self.token_label_hints = DEFAULT_TOKEN_LABEL_HINTS
        self.force_hardware_token = os.environ.get('PDF_SIGNER_FORCE_HARDWARE', 'false').lower() in ('1', 'true', 'yes')
        self._packages_installed = False

    def _ensure_packages_installed(self) -> bool:
        """Ensure required packages are available for PDF signing."""
        if self._packages_installed:
            return True

        missing_packages = []

        try:
            import endesive  # noqa: F401
        except ImportError:
            missing_packages.append('endesive')

        try:
            import PyKCS11  # noqa: F401
        except ImportError:
            missing_packages.append('PyKCS11')

        try:
            import cryptography  # noqa: F401
        except ImportError:
            missing_packages.append('cryptography')

        try:
            import asn1crypto  # noqa: F401
        except ImportError:
            missing_packages.append('asn1crypto')

        try:
            from pypdf import PdfReader  # noqa: F401
        except ImportError:
            missing_packages.append('pypdf')

        try:
            from Cryptodome.Cipher import AES  # noqa: F401
        except ImportError:
            missing_packages.append('pycryptodomex')

        if missing_packages:
            print('[ERROR] Missing required packages for PDF signing: ' + ', '.join(missing_packages))
            print('Install them before attempting to send signed PDFs, e.g.: pip install ' + ' '.join(missing_packages))
            return False

        self._packages_installed = True
        return True


    def _prepare_pdf_for_signing(
        self,
        pdf_data: bytes,
        pdf_password: Optional[str],
    ) -> Tuple[bytes, bool]:
        'Prepare PDF bytes for signing, validating passwords and normalising encryption.'
        try:
            from pypdf import PdfReader, PdfWriter
        except ImportError as exc:
            raise RuntimeError('pypdf is required to process PDFs before signing') from exc

        buffer = io.BytesIO(pdf_data)
        try:
            reader = PdfReader(buffer, strict=False)
        except Exception as exc:
            raise ValueError(f'Unable to read PDF bytes: {exc}') from exc

        converted_to_rc4 = False

        if reader.is_encrypted:
            if not pdf_password:
                raise ValueError('PDF is password protected but no password was provided.')
            try:
                decrypt_result = reader.decrypt(pdf_password)
            except NotImplementedError as decrypt_error:
                raise RuntimeError(
                    'pypdf requires PyCryptodome or pycryptodomex to decrypt AES-protected PDFs.'
                ) from decrypt_error

            if decrypt_result == 0:
                raise ValueError('Failed to decrypt PDF with the supplied password.')

            encrypt_ref = reader.trailer.get('/Encrypt') if reader.trailer else None
            if hasattr(encrypt_ref, 'get_object'):
                encrypt_dict = encrypt_ref.get_object()
            else:
                encrypt_dict = encrypt_ref

            version = 0
            if isinstance(encrypt_dict, dict):
                try:
                    version = int(encrypt_dict.get('/V', 0))
                except Exception:
                    version = 0

            if version not in (0, 1, 2):
                print(f"[WARN] Encryption algorithm V={version} unsupported for direct signing; re-encrypting with 128-bit RC4...")
                writer = PdfWriter()
                for page in reader.pages:
                    writer.add_page(page)
                if reader.metadata:
                    writer.add_metadata(reader.metadata)
                writer.encrypt(
                    user_password=pdf_password,
                    owner_password=pdf_password,
                    use_128bit=True,
                )
                buffer_out = io.BytesIO()
                writer.write(buffer_out)
                pdf_data = buffer_out.getvalue()
                converted_to_rc4 = True
                print('[OK] PDF re-encrypted with RC4 for signing compatibility.')
        elif pdf_password:
            print('[WARN] Password provided but PDF is not encrypted; continuing without decryption.')

        return pdf_data, converted_to_rc4

    def sign_pdf_with_certificate(
        self,
        pdf_data: bytes,
        signer_name: str,
        pdf_password: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Sign PDF with digital certificate or hardware token

        Args:
            pdf_data: PDF file as bytes
            signer_name: Name of the person signing the document
            pdf_password: Password to unlock the PDF if it is protected

        Returns:
            Dictionary with signing result and signed PDF data
        """
        try:
            print(f"Attempting to digitally sign PDF for: {signer_name}")

            if not self._ensure_packages_installed():
                return {
                    "success": False,
                    "error": "Required packages not available",
                    "signed_pdf": None,
                    "signed_by": signer_name,
                    "signed_on": None,
                    "signed_time": None,
                    "encryption_reencrypted": False,
                }

            try:
                from endesive import pdf, hsm
            except ImportError as import_error:
                return {
                    "success": False,
                    "error": f"Import error: {import_error}",
                    "signed_pdf": None,
                    "signed_by": signer_name,
                    "signed_on": None,
                    "signed_time": None,
                    "encryption_reencrypted": False,
                }

            try:
                from cryptography.hazmat.primitives.serialization import pkcs12
            except ImportError:
                pkcs12 = None

            try:
                prepared_pdf_data, converted_to_rc4 = self._prepare_pdf_for_signing(pdf_data, pdf_password)
            except Exception as prep_error:
                print(f"PDF preparation failed: {prep_error}")
                return {
                    "success": False,
                    "error": f"PDF preparation failed: {prep_error}",
                    "signed_pdf": pdf_data,
                    "signed_by": signer_name,
                    "signed_on": None,
                    "signed_time": None,
                    "encryption_reencrypted": False,
                }

            sign_datetime = datetime.datetime.utcnow()
            sign_date = sign_datetime.date()
            sign_time = sign_datetime.time()
            signature_dict = self._build_signature_dict(signer_name, sign_datetime, pdf_password)

            signed_pdf_data = None
            signer_source = None

            if not self.force_hardware_token and pkcs12 is not None:
                try:
                    signed_pdf_data = self._sign_with_pkcs12(
                        pdf,
                        pkcs12,
                        prepared_pdf_data,
                        signature_dict,
                    )
                    signer_source = "PKCS#12 certificate"
                except FileNotFoundError:
                    print(f"Certificate file not found: {self.certificate_path}")
                except Exception as certificate_error:
                    print(f"PKCS#12 signing failed: {certificate_error}")

            if signed_pdf_data is None:
                try:
                    signed_pdf_data = self._sign_with_hardware_token(
                        pdf,
                        hsm,
                        prepared_pdf_data,
                        signature_dict,
                    )
                    signer_source = "hardware token"
                except Exception as token_error:
                    print(f"Hardware token signing failed: {token_error}")
                    return {
                        "success": False,
                        "error": str(token_error),
                        "signed_pdf": pdf_data,
                        "signed_by": signer_name,
                        "signed_on": None,
                        "signed_time": None,
                        "encryption_reencrypted": converted_to_rc4,
                    }

            if not signed_pdf_data:
                return {
                    "success": False,
                    "error": "Signing failed: no signed data produced",
                    "signed_pdf": pdf_data,
                    "signed_by": signer_name,
                    "signed_on": None,
                    "signed_time": None,
                    "encryption_reencrypted": converted_to_rc4,
                }

            print(f"PDF successfully signed using {signer_source}")
            print(
                f"Prepared size: {len(prepared_pdf_data)} bytes, Signed size: {len(signed_pdf_data)} bytes"
            )

            return {
                "success": True,
                "error": None,
                "signed_pdf": signed_pdf_data,
                "signed_by": signer_name,
                "signed_on": sign_date,
                "signed_time": sign_time,
                "encryption_reencrypted": converted_to_rc4,
            }

        except Exception as e:
            print(f"Error signing PDF: {e}")
            import traceback
            traceback.print_exc()

            return {
                "success": False,
                "error": str(e),
                "signed_pdf": pdf_data,  # Fallback to original
                "signed_by": signer_name,
                "signed_on": datetime.datetime.now().date(),
                "signed_time": datetime.datetime.now().time(),
                "encryption_reencrypted": False,
            }

    def _build_signature_dict(
        self, signer_name: str, sign_datetime: datetime.datetime, pdf_password: Optional[str]
    ) -> Dict[str, Any]:
        signing_date_bytes = sign_datetime.strftime("%Y%m%d%H%M%S+00'00'").encode("utf-8")

        signature_dict = {
            "sigflags": 3,
            "sigpage": 0,
            "sigandcertify": False,
            "aligned": 4096,
            "contact": signer_name,
            "location": "Digital Signature",
            "signingdate": signing_date_bytes,
            "reason": "Document Verification",
            "signature": f"Digitally signed by {signer_name}",
        }

        if pdf_password:
            signature_dict["password"] = pdf_password

        return signature_dict

    def _sign_with_pkcs12(
        self,
        pdf_module,
        pkcs12_module,
        pdf_data: bytes,
        signature_dict: Dict[str, Any],
    ) -> bytes:
        if self.certificate_path and not os.path.exists(self.certificate_path):
            raise FileNotFoundError(self.certificate_path)
        if pkcs12_module is None:
            raise RuntimeError('cryptography pkcs12 module is unavailable')

        with open(self.certificate_path, 'rb') as cert_file:
            cert_data = cert_file.read()

        private_key, certificate, additional_certificates = pkcs12_module.load_key_and_certificates(
            cert_data,
            self.certificate_password.encode(),
        )

        if private_key is None or certificate is None:
            raise ValueError('PKCS#12 archive does not contain both certificate and private key')

        other_certs = list(additional_certificates or [])

        signature_increment = pdf_module.cms.sign(
            pdf_data,
            signature_dict,
            private_key,
            certificate,
            other_certs,
            'sha256',
        )

        if not signature_increment:
            raise ValueError('PDF signing library returned empty signature data')

        return pdf_data + signature_increment

    def _sign_with_hardware_token(
        self,
        pdf_module,
        hsm_module,
        pdf_data: bytes,
        signature_dict: Dict[str, Any],
    ) -> bytes:
        with SafeNetTokenSigner(
            self.token_pin,
            self.pkcs11_library_path,
            self.token_label_hints,
        ) as token_signer:
            token_signer.login()
            certificate_tuple = token_signer.certificate()

            class _TokenHSMBridge(hsm_module.BaseHSM):
                def __init__(self, signer, cert_tuple):
                    self.signer = signer
                    self.cert_tuple = cert_tuple

                def certificate(self):
                    return self.cert_tuple

                def sign(self, keyid, data, mech):
                    return self.signer.sign(keyid, data, mech)

            hsm_bridge = _TokenHSMBridge(token_signer, certificate_tuple)

            signature_increment = pdf_module.cms.sign(
                pdf_data,
                signature_dict,
                None,
                None,
                [],
                'sha256',
                hsm_bridge,
            )

            if not signature_increment:
                raise ValueError('PDF signing library returned empty signature data')

            return pdf_data + signature_increment


    def sign_pdf_with_token(
        self, pdf_data: bytes, signer_name: str, pdf_password: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Sign PDF with hardware token (PyKCS11)

        Args:
            pdf_data: PDF file as bytes
            signer_name: Name of the person signing the document
            pdf_password: Password to unlock the PDF if it is protected

        Returns:
            Dictionary with signing result and signed PDF data
        """
        try:
            print(f"Attempting to sign PDF with hardware token for: {signer_name}")

            if not self._ensure_packages_installed():
                return {
                    "success": False,
                    "error": "Required packages not available",
                    "signed_pdf": None,
                    "signed_by": signer_name,
                    "signed_on": None,
                    "signed_time": None,
                    "encryption_reencrypted": False,
                }

            try:
                from endesive import pdf, hsm
            except ImportError as import_error:
                return {
                    "success": False,
                    "error": f"Import error: {import_error}",
                    "signed_pdf": None,
                    "signed_by": signer_name,
                    "signed_on": None,
                    "signed_time": None,
                    "encryption_reencrypted": False,
                }

            try:
                prepared_pdf_data, converted_to_rc4 = self._prepare_pdf_for_signing(pdf_data, pdf_password)
            except Exception as prep_error:
                print(f"PDF preparation failed: {prep_error}")
                return {
                    "success": False,
                    "error": f"PDF preparation failed: {prep_error}",
                    "signed_pdf": pdf_data,
                    "signed_by": signer_name,
                    "signed_on": None,
                    "signed_time": None,
                    "encryption_reencrypted": False,
                }

            sign_datetime = datetime.datetime.utcnow()
            sign_date = sign_datetime.date()
            sign_time = sign_datetime.time()
            signature_dict = self._build_signature_dict(signer_name, sign_datetime, pdf_password)

            signed_pdf_data = self._sign_with_hardware_token(
                pdf,
                hsm,
                prepared_pdf_data,
                signature_dict,
            )

            print('PDF successfully signed using hardware token')

            return {
                "success": True,
                "error": None,
                "signed_pdf": signed_pdf_data,
                "signed_by": signer_name,
                "signed_on": sign_date,
                "signed_time": sign_time,
                "encryption_reencrypted": converted_to_rc4,
            }

        except Exception as e:
            print(f"Error with token signing: {e}")
            return {
                "success": False,
                "error": str(e),
                "signed_pdf": pdf_data,  # Fallback to original
                "signed_by": signer_name,
                "signed_on": datetime.datetime.now().date(),
                "signed_time": datetime.datetime.now().time(),
                "encryption_reencrypted": False,
            }

    def verify_pdf_signature(self, pdf_data: bytes) -> Dict[str, Any]:
        """
        Verify PDF digital signature

        Args:
            pdf_data: Signed PDF file as bytes

        Returns:
            Dictionary with verification results
        """
        try:
            # Import required libraries
            from endesive import pdf

            # Verify signature
            trusted_cert_pems = []  # Add trusted certificates if needed
            verification_result = pdf.verify(pdf_data, trusted_cert_pems)

            return {
                "is_signed": True,
                "is_valid": verification_result.get('verified', False),
                "signer_info": verification_result.get('signer', 'Unknown'),
                "sign_date": verification_result.get('signing_date', None),
                "details": verification_result
            }

        except Exception as e:
            print(f"Error verifying PDF signature: {e}")
            return {
                "is_signed": False,
                "is_valid": False,
                "signer_info": None,
                "sign_date": None,
                "error": str(e)
            }

    def get_pdf_signature_info(self, pdf_data: bytes) -> Dict[str, Any]:
        """
        Get basic signature information from PDF

        Args:
            pdf_data: PDF file as bytes

        Returns:
            Dictionary with signature information
        """
        try:
            # Check if PDF has signatures
            # This is a basic implementation - can be enhanced
            pdf_content = pdf_data.decode('latin-1', errors='ignore')
            has_signature = '/Sig' in pdf_content or '/ByteRange' in pdf_content

            return {
                "has_signature": has_signature,
                "signature_count": pdf_content.count('/Sig') if has_signature else 0,
                "size_bytes": len(pdf_data)
            }

        except Exception as e:
            return {
                "has_signature": False,
                "signature_count": 0,
                "size_bytes": len(pdf_data),
                "error": str(e)
            }
