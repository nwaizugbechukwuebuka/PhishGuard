"""
Enhanced Security Utilities for PhishGuard
Comprehensive security features including JWT/OAuth2, encryption, and access control
"""

import base64
import hashlib
import os
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union

import bcrypt
import jwt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import HTTPException, status
from passlib.context import CryptContext

from src.api.utils.logger import get_logger

logger = get_logger(__name__)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT configuration
JWT_SECRET_KEY = os.getenv(
    "JWT_SECRET_KEY", "phishguard-secret-key-change-in-production"
)
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

# Encryption key for sensitive data
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "encryption-key-change-in-production")


class SecurityError(Exception):
    """Custom security-related exception"""

    pass


class PasswordValidator:
    """Password validation and strength checking"""

    def __init__(self):
        self.min_length = int(os.getenv("PASSWORD_MIN_LENGTH", "8"))
        self.require_uppercase = True
        self.require_lowercase = True
        self.require_digits = True
        self.require_special = True
        self.special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    def validate_password(self, password: str) -> Dict[str, Any]:
        """
        Validate password strength

        Args:
            password: Password to validate

        Returns:
            Dictionary with validation results
        """
        errors = []
        score = 0

        # Length check
        if len(password) < self.min_length:
            errors.append(
                f"Password must be at least {self.min_length} characters long"
            )
        else:
            score += 1

        # Character type checks
        if self.require_uppercase and not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")
        else:
            score += 1

        if self.require_lowercase and not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")
        else:
            score += 1

        if self.require_digits and not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit")
        else:
            score += 1

        if self.require_special and not any(c in self.special_chars for c in password):
            errors.append("Password must contain at least one special character")
        else:
            score += 1

        # Additional strength checks
        if len(password) >= 12:
            score += 1

        if len(set(password)) >= len(password) * 0.7:  # Character diversity
            score += 1

        # Common password patterns
        common_patterns = ["123", "abc", "password", "qwerty", "admin"]
        if not any(pattern in password.lower() for pattern in common_patterns):
            score += 1

        # Strength rating
        if score <= 3:
            strength = "weak"
        elif score <= 5:
            strength = "medium"
        elif score <= 6:
            strength = "strong"
        else:
            strength = "very_strong"

        return {
            "is_valid": len(errors) == 0,
            "errors": errors,
            "strength": strength,
            "score": score,
        }


class TokenManager:
    """JWT token management with enhanced security"""

    @staticmethod
    def create_access_token(
        data: Dict[str, Any], expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create JWT access token

        Args:
            data: Token payload data
            expires_delta: Token expiration time

        Returns:
            JWT token string
        """
        to_encode = data.copy()

        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

        to_encode.update(
            {"exp": expire, "iat": datetime.utcnow(), "token_type": "access"}
        )

        return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    @staticmethod
    def create_refresh_token(data: Dict[str, Any]) -> str:
        """
        Create JWT refresh token

        Args:
            data: Token payload data

        Returns:
            JWT refresh token string
        """
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

        to_encode.update(
            {"exp": expire, "iat": datetime.utcnow(), "token_type": "refresh"}
        )

        return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    @staticmethod
    def verify_token(token: str, token_type: str = "access") -> Dict[str, Any]:
        """
        Verify and decode JWT token

        Args:
            token: JWT token to verify
            token_type: Expected token type (access/refresh)

        Returns:
            Decoded token payload

        Raises:
            HTTPException: If token is invalid
        """
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])

            # Verify token type
            if payload.get("token_type") != token_type:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            return payload

        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except jwt.InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    @staticmethod
    def create_password_reset_token(user_id: str) -> str:
        """
        Create password reset token

        Args:
            user_id: User ID

        Returns:
            Password reset token
        """
        data = {"user_id": user_id, "purpose": "password_reset"}
        expire = datetime.utcnow() + timedelta(hours=1)  # 1 hour expiry
        data["exp"] = expire

        return jwt.encode(data, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    @staticmethod
    def verify_password_reset_token(token: str) -> Optional[str]:
        """
        Verify password reset token

        Args:
            token: Password reset token

        Returns:
            User ID if token is valid, None otherwise
        """
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])

            if payload.get("purpose") != "password_reset":
                return None

            return payload.get("user_id")

        except jwt.InvalidTokenError:
            return None


class DataEncryption:
    """Data encryption and decryption utilities"""

    def __init__(self, key: str = None):
        """
        Initialize encryption with key

        Args:
            key: Encryption key (base64 encoded)
        """
        if key:
            self.key = key.encode()
        else:
            self.key = ENCRYPTION_KEY.encode()

        # Derive Fernet key from provided key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"phishguard_salt",  # In production, use random salt per encryption
            iterations=100000,
        )
        key_derived = base64.urlsafe_b64encode(kdf.derive(self.key))
        self.fernet = Fernet(key_derived)

    def encrypt(self, data: str) -> str:
        """
        Encrypt string data

        Args:
            data: Data to encrypt

        Returns:
            Encrypted data (base64 encoded)
        """
        try:
            encrypted_data = self.fernet.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted_data).decode()
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            raise SecurityError("Encryption failed")

    def decrypt(self, encrypted_data: str) -> str:
        """
        Decrypt string data

        Args:
            encrypted_data: Encrypted data (base64 encoded)

        Returns:
            Decrypted data
        """
        try:
            decoded_data = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted_data = self.fernet.decrypt(decoded_data)
            return decrypted_data.decode()
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            raise SecurityError("Decryption failed")

    def encrypt_dict(self, data: Dict[str, Any]) -> str:
        """
        Encrypt dictionary data

        Args:
            data: Dictionary to encrypt

        Returns:
            Encrypted JSON string
        """
        import json

        json_data = json.dumps(data)
        return self.encrypt(json_data)

    def decrypt_dict(self, encrypted_data: str) -> Dict[str, Any]:
        """
        Decrypt dictionary data

        Args:
            encrypted_data: Encrypted JSON string

        Returns:
            Decrypted dictionary
        """
        import json

        json_data = self.decrypt(encrypted_data)
        return json.loads(json_data)


class AccessControl:
    """Role-based access control (RBAC) system"""

    ROLES = {
        "admin": {
            "permissions": ["*"],  # All permissions
            "description": "System administrator",
        },
        "security_analyst": {
            "permissions": [
                "emails:read",
                "emails:write",
                "emails:delete",
                "quarantine:read",
                "quarantine:write",
                "reports:read",
                "reports:write",
                "users:read",
                "simulations:read",
                "simulations:write",
            ],
            "description": "Security analyst",
        },
        "user": {
            "permissions": [
                "emails:read",
                "reports:read",
                "simulations:participate",
                "profile:read",
                "profile:write",
            ],
            "description": "Regular user",
        },
        "viewer": {
            "permissions": ["reports:read", "emails:read"],
            "description": "Read-only viewer",
        },
    }

    @classmethod
    def has_permission(cls, user_role: str, required_permission: str) -> bool:
        """
        Check if user role has required permission

        Args:
            user_role: User's role
            required_permission: Required permission

        Returns:
            True if user has permission
        """
        if user_role not in cls.ROLES:
            return False

        permissions = cls.ROLES[user_role]["permissions"]

        # Admin has all permissions
        if "*" in permissions:
            return True

        # Check exact permission match
        if required_permission in permissions:
            return True

        # Check wildcard permissions
        for permission in permissions:
            if permission.endswith("*"):
                prefix = permission[:-1]
                if required_permission.startswith(prefix):
                    return True

        return False

    @classmethod
    def get_user_permissions(cls, user_role: str) -> List[str]:
        """
        Get all permissions for a user role

        Args:
            user_role: User's role

        Returns:
            List of permissions
        """
        if user_role not in cls.ROLES:
            return []

        return cls.ROLES[user_role]["permissions"]

    @classmethod
    def validate_role(cls, role: str) -> bool:
        """
        Validate if role exists

        Args:
            role: Role to validate

        Returns:
            True if role is valid
        """
        return role in cls.ROLES


class SecurityAudit:
    """Security audit and logging utilities"""

    @staticmethod
    def log_security_event(
        event_type: str,
        user_id: str = None,
        ip_address: str = None,
        user_agent: str = None,
        details: Dict[str, Any] = None,
        severity: str = "info",
    ):
        """
        Log security-related events

        Args:
            event_type: Type of security event
            user_id: User ID involved
            ip_address: Source IP address
            user_agent: User agent string
            details: Additional event details
            severity: Event severity (info, warning, error, critical)
        """
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "details": details or {},
            "severity": severity,
        }

        if severity == "critical":
            logger.critical(f"Security Event: {log_data}")
        elif severity == "error":
            logger.error(f"Security Event: {log_data}")
        elif severity == "warning":
            logger.warning(f"Security Event: {log_data}")
        else:
            logger.info(f"Security Event: {log_data}")

    @staticmethod
    def check_suspicious_activity(
        user_id: str, ip_address: str, activity_type: str
    ) -> Dict[str, Any]:
        """
        Check for suspicious user activity patterns

        Args:
            user_id: User ID
            ip_address: Source IP address
            activity_type: Type of activity

        Returns:
            Suspicious activity analysis
        """
        # This would integrate with a real threat intelligence system
        # For now, return basic analysis

        suspicious_indicators = []
        risk_score = 0.0

        # Example checks (would be more sophisticated in production)
        if ip_address:
            # Check for known malicious IPs (placeholder)
            if ip_address.startswith("192.168."):  # Private IP - less suspicious
                risk_score += 0.1
            else:
                risk_score += 0.3

        # Check activity frequency (would need database integration)
        # This is a placeholder for real implementation

        return {
            "is_suspicious": risk_score > 0.5,
            "risk_score": risk_score,
            "indicators": suspicious_indicators,
            "recommended_action": "monitor" if risk_score < 0.7 else "alert",
        }


# Utility functions
def hash_password(password: str) -> tuple[str, str]:
    """
    Hash password with salt

    Args:
        password: Plain text password

    Returns:
        Tuple of (hashed_password, salt)
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8"), salt.decode("utf-8")


def verify_password(password: str, hashed_password: str) -> bool:
    """
    Verify password against hash

    Args:
        password: Plain text password
        hashed_password: Hashed password

    Returns:
        True if password matches
    """
    return pwd_context.verify(password, hashed_password)


def generate_secure_token() -> str:
    """
    Generate cryptographically secure random token

    Returns:
        Secure random token
    """
    return secrets.token_urlsafe(32)


def hash_data(data: str) -> str:
    """
    Create SHA-256 hash of data

    Args:
        data: Data to hash

    Returns:
        Hexadecimal hash string
    """
    return hashlib.sha256(data.encode()).hexdigest()


def constant_time_compare(a: str, b: str) -> bool:
    """
    Constant-time string comparison to prevent timing attacks

    Args:
        a: First string
        b: Second string

    Returns:
        True if strings are equal
    """
    return secrets.compare_digest(a, b)


# Initialize global instances
password_validator = PasswordValidator()
data_encryption = DataEncryption()
security_audit = SecurityAudit()

# Export common functions
__all__ = [
    "TokenManager",
    "PasswordValidator",
    "DataEncryption",
    "AccessControl",
    "SecurityAudit",
    "SecurityError",
    "hash_password",
    "verify_password",
    "generate_secure_token",
    "hash_data",
    "constant_time_compare",
    "password_validator",
    "data_encryption",
    "security_audit",
]
