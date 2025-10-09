"""
Certificate utilities for enumerating all certificates on the computer
"""

import os
import sys
from typing import List, Dict, Any


def get_all_system_certificates() -> List[Dict[str, Any]]:
    """
    Enumerate all certificates from Windows certificate stores.
    Returns a list of certificate information dictionaries.
    """
    certificates = []

    # Only works on Windows
    if sys.platform != 'win32':
        print("[INFO] System certificate enumeration is only supported on Windows")
        return certificates

    try:
        import win32crypt
        import pywintypes
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
    except ImportError as e:
        print(f"[WARN] Required packages not available for certificate enumeration: {e}")
        print("[INFO] Install with: pip install pywin32 cryptography")
        return certificates

    # Certificate store locations and names to check
    stores_to_check = [
        ("CurrentUser", "MY"),      # Personal certificates
        ("CurrentUser", "ROOT"),    # Trusted root certificates
        ("CurrentUser", "CA"),      # Intermediate certificates
        ("LocalMachine", "MY"),     # Computer personal certificates
        ("LocalMachine", "ROOT"),   # Computer trusted root
        ("LocalMachine", "CA"),     # Computer intermediate
    ]

    for store_location, store_name in stores_to_check:
        try:
            # Determine store location flag
            if store_location == "CurrentUser":
                location_flag = win32crypt.CERT_SYSTEM_STORE_CURRENT_USER
            else:
                location_flag = win32crypt.CERT_SYSTEM_STORE_LOCAL_MACHINE

            # Open the certificate store
            store = win32crypt.CertOpenStore(
                win32crypt.CERT_STORE_PROV_SYSTEM,
                0,
                None,
                location_flag,
                store_name
            )

            # Enumerate certificates
            cert_context = None
            while True:
                cert_context = win32crypt.CertEnumCertificatesInStore(store, cert_context)
                if cert_context is None:
                    break

                try:
                    # Get certificate data
                    cert_data = win32crypt.CertSerializeCertificateStoreElement(cert_context, 0)

                    # Parse certificate using cryptography library
                    cert_der = cert_context.CertContext
                    cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())

                    # Extract certificate information
                    subject = cert_obj.subject.rfc4514_string()
                    issuer = cert_obj.issuer.rfc4514_string()
                    serial_number = format(cert_obj.serial_number, 'x').upper()
                    not_valid_before = cert_obj.not_valid_before.isoformat()
                    not_valid_after = cert_obj.not_valid_after.isoformat()

                    # Get thumbprint (SHA-1 hash of certificate)
                    thumbprint = cert_context.CertGetCertificateContextProperty(
                        win32crypt.CERT_SHA1_HASH_PROP_ID
                    ).hex().upper()

                    # Check if certificate has private key
                    has_private_key = False
                    try:
                        key_prov_info = cert_context.CertGetCertificateContextProperty(
                            win32crypt.CERT_KEY_PROV_INFO_PROP_ID
                        )
                        has_private_key = key_prov_info is not None
                    except:
                        pass

                    cert_info = {
                        "subject": subject,
                        "issuer": issuer,
                        "serial_number": serial_number,
                        "not_valid_before": not_valid_before,
                        "not_valid_after": not_valid_after,
                        "thumbprint": thumbprint,
                        "has_private_key": has_private_key,
                        "store_name": store_name,
                        "store_location": store_location,
                        "source": "System Store"
                    }

                    certificates.append(cert_info)

                except Exception as cert_error:
                    print(f"[WARN] Error processing certificate: {cert_error}")
                    continue

            # Close the store
            win32crypt.CertCloseStore(store, 0)

        except Exception as store_error:
            print(f"[WARN] Error accessing certificate store {store_location}\\{store_name}: {store_error}")
            continue

    print(f"[INFO] Found {len(certificates)} system certificates")
    return certificates


def get_all_hardware_certificates() -> List[Dict[str, Any]]:
    """
    Enumerate all certificates from hardware tokens (USB tokens).
    Returns a list of certificate information dictionaries.
    """
    certificates = []

    try:
        import PyKCS11 as PK11
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
    except ImportError as e:
        print(f"[INFO] PyKCS11 not available for hardware token enumeration: {e}")
        return certificates

    # Get PKCS11 library path
    pkcs11_library = os.environ.get('PDF_SIGNER_PKCS11_LIB')
    if not pkcs11_library:
        # Try default Windows path
        if sys.platform == 'win32':
            possible_paths = [
                os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32', 'eTPKCS11.dll'),
                r"C:\Windows\System32\eTPKCS11.dll",
            ]
            for path in possible_paths:
                if os.path.exists(path):
                    pkcs11_library = path
                    break

    if not pkcs11_library or not os.path.exists(pkcs11_library):
        print("[INFO] PKCS11 library not found, skipping hardware token enumeration")
        return certificates

    try:
        print(f"[INFO] Loading PKCS#11 library: {pkcs11_library}")
        pkcs11 = PK11.PyKCS11Lib()
        pkcs11.load(pkcs11_library)

        slots = pkcs11.getSlotList(tokenPresent=True)
        if not slots:
            print("[INFO] No PKCS#11 tokens detected")
            return certificates

        print(f"[INFO] Found {len(slots)} hardware token(s)")

        for slot in slots:
            try:
                token_info = pkcs11.getTokenInfo(slot)
                token_label = token_info.label.strip()
                print(f"[INFO] Checking token: '{token_label}' in slot {slot}")

                # Try to open session (read-only, no login required for certificate enumeration)
                try:
                    session = pkcs11.openSession(slot, PK11.CKF_SERIAL_SESSION)
                except Exception as session_error:
                    print(f"[WARN] Could not open session for slot {slot}: {session_error}")
                    continue

                try:
                    # Find all certificates on this token
                    cert_objects = session.findObjects([(PK11.CKA_CLASS, PK11.CKO_CERTIFICATE)])

                    print(f"[INFO] Found {len(cert_objects)} certificate(s) on token '{token_label}'")

                    for cert_obj in cert_objects:
                        try:
                            # Get certificate value (DER encoded)
                            cert_attrs = session.getAttributeValue(cert_obj, [PK11.CKA_VALUE])
                            if not cert_attrs or not cert_attrs[0]:
                                continue

                            cert_der = bytes(cert_attrs[0])

                            # Parse certificate
                            cert = x509.load_der_x509_certificate(cert_der, default_backend())

                            # Get certificate ID
                            try:
                                id_attrs = session.getAttributeValue(cert_obj, [PK11.CKA_ID])
                                cert_id = bytes(id_attrs[0]).hex().upper() if id_attrs and id_attrs[0] else "N/A"
                            except:
                                cert_id = "N/A"

                            # Check if there's a corresponding private key
                            has_private_key = False
                            try:
                                private_keys = session.findObjects([
                                    (PK11.CKA_CLASS, PK11.CKO_PRIVATE_KEY),
                                ])
                                has_private_key = len(private_keys) > 0
                            except:
                                pass

                            cert_info = {
                                "subject": cert.subject.rfc4514_string(),
                                "issuer": cert.issuer.rfc4514_string(),
                                "serial_number": format(cert.serial_number, 'x').upper(),
                                "not_valid_before": cert.not_valid_before.isoformat(),
                                "not_valid_after": cert.not_valid_after.isoformat(),
                                "thumbprint": cert_id,  # Using CKA_ID as thumbprint for hardware certs
                                "has_private_key": has_private_key,
                                "source": "Hardware Token",
                                "token_label": token_label,
                                "slot_id": slot
                            }

                            certificates.append(cert_info)

                        except Exception as cert_error:
                            print(f"[WARN] Error processing certificate on token: {cert_error}")
                            continue

                finally:
                    session.closeSession()

            except Exception as slot_error:
                print(f"[WARN] Error processing slot {slot}: {slot_error}")
                continue

        pkcs11.unload()

    except Exception as e:
        print(f"[ERROR] Error enumerating hardware certificates: {e}")

    print(f"[INFO] Found {len(certificates)} hardware token certificates")
    return certificates


def get_all_certificates() -> Dict[str, Any]:
    """
    Get all certificates from both system stores and hardware tokens.

    Returns:
        Dictionary containing system and hardware certificates with metadata
    """
    try:
        system_certs = get_all_system_certificates()
        hardware_certs = get_all_hardware_certificates()

        return {
            "success": True,
            "total_certificates": len(system_certs) + len(hardware_certs),
            "system_certificates": system_certs,
            "hardware_certificates": hardware_certs,
            "error": None
        }
    except Exception as e:
        print(f"[ERROR] Error getting all certificates: {e}")
        return {
            "success": False,
            "total_certificates": 0,
            "system_certificates": [],
            "hardware_certificates": [],
            "error": str(e)
        }
