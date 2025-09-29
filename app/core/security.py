import os
import json
import base64
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from pathlib import Path

try:
    from cryptography.fernet import Fernet
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

from passlib.context import CryptContext
from jose import JWTError, jwt

from app.core.config import settings


class SecurityManager:
    def __init__(self):
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        if HAS_CRYPTOGRAPHY:
            self.cipher_suite = Fernet(self._get_encryption_key())
        else:
            self.cipher_suite = None

    def _get_encryption_key(self) -> bytes:
        """Get or generate encryption key for configuration files"""
        if not HAS_CRYPTOGRAPHY:
            return b""

        key = settings.DATABASE_ENCRYPTION_KEY.encode()
        if len(key) != 32:
            # If key is not 32 bytes, generate a proper key from it
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'salt_',  # In production, use a random salt
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(key))
        else:
            key = base64.urlsafe_b64encode(key)
        return key

    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        return self.pwd_context.hash(password)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        return self.pwd_context.verify(plain_password, hashed_password)

    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token"""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
        return encoded_jwt

    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
            return payload
        except JWTError:
            raise JWTError("Invalid token")

    def encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        if HAS_CRYPTOGRAPHY and self.cipher_suite:
            return self.cipher_suite.encrypt(data.encode()).decode()
        else:
            # Fallback to base64 encoding (NOT secure for production)
            return base64.b64encode(data.encode()).decode()

    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        if HAS_CRYPTOGRAPHY and self.cipher_suite:
            return self.cipher_suite.decrypt(encrypted_data.encode()).decode()
        else:
            # Fallback to base64 decoding (NOT secure for production)
            return base64.b64decode(encrypted_data.encode()).decode()

    def save_encrypted_config(self, config_data: Dict[str, Any], config_type: str):
        """Save encrypted configuration to file"""
        config_dir = Path("config")
        config_dir.mkdir(exist_ok=True)

        config_file = config_dir / f"{config_type}_config.json"

        # Encrypt the configuration data
        config_json = json.dumps(config_data)
        encrypted_config = self.encrypt_data(config_json)

        with open(config_file, "w") as f:
            f.write(encrypted_config)

    def load_encrypted_config(self, config_type: str) -> Optional[Dict[str, Any]]:
        """Load and decrypt configuration from file"""
        config_file = Path("config") / f"{config_type}_config.json"

        if not config_file.exists():
            return None

        try:
            with open(config_file, "r") as f:
                encrypted_config = f.read()

            # Decrypt the configuration data
            config_json = self.decrypt_data(encrypted_config)
            return json.loads(config_json)
        except Exception as e:
            print(f"Error loading config: {e}")
            return None

    def config_exists(self, config_type: str) -> bool:
        """Check if configuration file exists"""
        config_file = Path("config") / f"{config_type}_config.json"
        return config_file.exists()