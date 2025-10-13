import datetime
from typing import Dict, Any, Optional, List, Tuple

from app.core.security import SecurityManager


class CertificatePinManager:
    """
    Manage storage and validation of hardware token certificate PINs.
    PIN data is stored using the existing encrypted configuration mechanism.
    """

    CONFIG_TYPE = "certificate_pin"

    def __init__(self, pkcs11_library: Optional[str] = None):
        self.security_manager = SecurityManager()
        self.pkcs11_library = pkcs11_library
        self._store_cache: Optional[Dict[str, Dict[str, Any]]] = None

    @staticmethod
    def _normalise(value: Optional[str]) -> str:
        return (value or "").strip().lower()

    def _make_key(self, token_label: Optional[str], certificate_id: Optional[str]) -> Optional[str]:
        if not token_label:
            return None
        cert_component = self._normalise(certificate_id) if certificate_id else "__any__"
        return f"{self._normalise(token_label)}::{cert_component}"

    def _load_store(self) -> Dict[str, Dict[str, Any]]:
        if self._store_cache is not None:
            return self._store_cache

        raw_data = self.security_manager.load_encrypted_config(self.CONFIG_TYPE) or {}
        entries = raw_data.get("entries", [])

        store: Dict[str, Dict[str, Any]] = {}
        for entry in entries:
            key = self._make_key(entry.get("token_label"), entry.get("certificate_id"))
            if key:
                store[key] = entry
        self._store_cache = store
        return store

    def _persist_store(self):
        if self._store_cache is None:
            return

        serializable_entries = list(self._store_cache.values())
        payload = {"entries": serializable_entries}
        self.security_manager.save_encrypted_config(payload, self.CONFIG_TYPE)

    def list_entries(self) -> List[Dict[str, Any]]:
        """Return all stored PIN entries."""
        store = self._load_store()
        return [entry.copy() for entry in store.values()]

    def get_entry(self, token_label: str, certificate_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Fetch stored entry for a given token/certificate combination."""
        key = self._make_key(token_label, certificate_id)
        store = self._load_store()
        if key and key in store:
            return store[key].copy()

        # Fallback: match on token label only
        normalised_label = self._normalise(token_label)
        for entry_key, entry in store.items():
            entry_label = self._normalise(entry.get("token_label"))
            if entry_label == normalised_label:
                return entry.copy()
        return None

    def get_pin(self, token_label: str, certificate_id: Optional[str] = None) -> Optional[str]:
        """Return stored PIN for the given token/certificate, if available."""
        entry = self.get_entry(token_label, certificate_id)
        if not entry:
            return None
        return entry.get("pin")

    def remove_entry(self, token_label: str, certificate_id: Optional[str] = None) -> bool:
        """Remove stored PIN entry."""
        key = self._make_key(token_label, certificate_id)
        store = self._load_store()
        removed = False

        if key and key in store:
            store.pop(key)
            removed = True
        else:
            # Remove first match by token label
            normalised_label = self._normalise(token_label)
            for entry_key in list(store.keys()):
                if self._normalise(store[entry_key].get("token_label")) == normalised_label:
                    store.pop(entry_key)
                    removed = True
                    break

        if removed:
            self._persist_store()
        return removed

    def set_pin(
        self,
        token_label: str,
        certificate_id: Optional[str],
        pin: str,
        slot_id: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
        validate: bool = True,
        pkcs11_library: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Store/update the PIN for a certificate.

        Args:
            token_label: Hardware token label reported by PKCS#11.
            certificate_id: Identifier for certificate (CKA_ID hex string).
            pin: PIN to store.
            slot_id: Optional slot identifier.
            metadata: Optional metadata (e.g. subject, serial number).
            validate: When True, attempt to verify the PIN immediately.
            pkcs11_library: Explicit PKCS#11 library path to use for validation.

        Returns:
            Stored entry data.
        """
        if not token_label:
            raise ValueError("token_label is required")
        if not pin:
            raise ValueError("pin is required")

        key = self._make_key(token_label, certificate_id)
        if not key:
            raise ValueError("Unable to build certificate key")

        store = self._load_store()
        existing_entry = store.get(key)
        now_iso = datetime.datetime.utcnow().isoformat()

        verification_status: Optional[bool] = None
        verification_error: Optional[str] = None
        library_path = pkcs11_library or self.pkcs11_library

        if validate and library_path:
            verification_status, verification_error = self.validate_pin(
                token_label=token_label,
                slot_id=slot_id,
                pin=pin,
                pkcs11_library=library_path,
            )
            if verification_status is False:
                raise ValueError(verification_error or "PIN validation failed")
        elif validate and not library_path:
            verification_status = None
            verification_error = "PKCS#11 library path not available for validation"

        entry = existing_entry.copy() if existing_entry else {}
        if "created_at" not in entry:
            entry["created_at"] = now_iso

        entry.update(
            {
                "token_label": token_label.strip(),
                "certificate_id": (certificate_id or "").strip() or None,
                "slot_id": slot_id,
                "pin": pin,
                "updated_at": now_iso,
                "pin_valid": verification_status,
                "last_verification_error": verification_error,
                "last_verified_at": now_iso if verification_status is not None else entry.get("last_verified_at"),
            }
        )

        if metadata:
            entry["metadata"] = metadata

        store[key] = entry
        self._persist_store()
        return entry.copy()

    def record_validation(
        self,
        token_label: str,
        certificate_id: Optional[str],
        is_valid: Optional[bool],
        error: Optional[str],
    ) -> None:
        """Persist validation outcome for a stored PIN."""
        key = self._make_key(token_label, certificate_id)
        store = self._load_store()

        entry = None
        if key and key in store:
            entry = store[key]
        else:
            normalised_label = self._normalise(token_label)
            for existing_key, existing_entry in store.items():
                if self._normalise(existing_entry.get("token_label")) == normalised_label:
                    entry = existing_entry
                    break

        if entry is None:
            return

        entry["pin_valid"] = is_valid
        entry["last_verification_error"] = error
        entry["last_verified_at"] = datetime.datetime.utcnow().isoformat()
        self._persist_store()

    def validate_pin(
        self,
        token_label: str,
        slot_id: Optional[int],
        pin: str,
        pkcs11_library: str,
    ) -> Tuple[Optional[bool], Optional[str]]:
        """
        Attempt to authenticate against the hardware token using the supplied PIN.

        Returns:
            Tuple[Optional[bool], Optional[str]] where the boolean indicates:
                True  -> PIN valid
                False -> PIN invalid/locked
                None  -> Validation could not be performed
            Second element contains error details when applicable.
        """
        try:
            import PyKCS11 as PK11  # type: ignore
        except ImportError as exc:
            return None, f"PyKCS11 import error: {exc}"

        pkcs11 = PK11.PyKCS11Lib()
        try:
            pkcs11.load(pkcs11_library)
        except Exception as load_error:
            return None, f"Failed to load PKCS#11 library: {load_error}"

        normalised_label = self._normalise(token_label)
        candidate_slots: List[Tuple[int, str]] = []
        last_error: Optional[str] = None

        try:
            slots = pkcs11.getSlotList(tokenPresent=True)
            if not slots:
                return None, "No PKCS#11 tokens detected"

            for slot in slots:
                try:
                    token_info = pkcs11.getTokenInfo(slot)
                except Exception as slot_info_error:
                    last_error = str(slot_info_error)
                    continue

                slot_label = (token_info.label or "").strip()
                slot_matches_label = (
                    not normalised_label or self._normalise(slot_label) == normalised_label
                )
                slot_matches_id = slot_id is None or slot == slot_id

                if slot_matches_label and slot_matches_id:
                    candidate_slots.append((slot, slot_label))

            if not candidate_slots and slot_id is not None:
                # Try to fall back to explicit slot even if label didn't match
                for slot in slots:
                    if slot == slot_id:
                        try:
                            token_info = pkcs11.getTokenInfo(slot)
                            candidate_slots.append((slot, (token_info.label or "").strip()))
                        except Exception as slot_info_error:
                            last_error = str(slot_info_error)
                        break

            if not candidate_slots:
                return None, last_error or "Matching token not found"

            for slot, slot_label in candidate_slots:
                session = None
                try:
                    session = pkcs11.openSession(slot, PK11.CKF_SERIAL_SESSION | PK11.CKF_RW_SESSION)
                    session.login(pin)
                    session.logout()
                    return True, None
                except Exception as login_error:
                    error_message = str(login_error)
                    last_error = error_message or "Authentication failed"
                    # Common PKCS#11 error codes for invalid PINs
                    if any(code in error_message for code in ("CKR_PIN_INCORRECT", "CKR_PIN_LOCKED", "CKR_PIN_LEN_RANGE")):
                        return False, error_message
                finally:
                    if session is not None:
                        try:
                            session.closeSession()
                        except Exception:
                            pass

            return None, last_error or "Unable to validate PIN"
        finally:
            try:
                pkcs11.unload()
            except Exception:
                pass
