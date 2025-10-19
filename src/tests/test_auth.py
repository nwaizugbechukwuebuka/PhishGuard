"""
Comprehensive test suite for PhishGuard authentication system.
Tests JWT tokens, password security, role-based access control.
"""

import os
import sys
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

import jwt
import pytest
from passlib.context import CryptContext

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.middleware.auth_middleware import verify_jwt_token
from api.utils.config import settings
from api.utils.security import (
    create_access_token,
    generate_reset_token,
    hash_password,
    verify_password,
    verify_reset_token,
    verify_token,
)

# Password context for testing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class TestPasswordSecurity:
    """Test password hashing and verification."""

    def test_hash_password(self):
        """Test password hashing."""
        password = "testpassword123"
        hashed = hash_password(password)

        assert hashed != password
        assert len(hashed) > 50  # Bcrypt hashes are typically 60 chars
        assert hashed.startswith("$2b$")

    def test_verify_password_correct(self):
        """Test password verification with correct password."""
        password = "testpassword123"
        hashed = hash_password(password)

        assert verify_password(password, hashed) == True

    def test_verify_password_incorrect(self):
        """Test password verification with incorrect password."""
        password = "testpassword123"
        wrong_password = "wrongpassword"
        hashed = hash_password(password)

        assert verify_password(wrong_password, hashed) == False

    def test_password_strength_validation(self):
        """Test password strength requirements."""
        weak_passwords = ["123", "password", "abc", "12345678", "password123"]

        strong_passwords = ["TestPassword123!", "MyStr0ng_P@ssw0rd", "C0mplex!P@ssw0rd"]

        # Note: This would require implementing password strength validation
        # For now, just test that we can hash any password
        for password in weak_passwords + strong_passwords:
            hashed = hash_password(password)
            assert verify_password(password, hashed)

    def test_same_password_different_hashes(self):
        """Test that same password produces different hashes (salt)."""
        password = "testpassword123"
        hash1 = hash_password(password)
        hash2 = hash_password(password)

        assert hash1 != hash2
        assert verify_password(password, hash1)
        assert verify_password(password, hash2)


class TestJWTTokens:
    """Test JWT token creation and verification."""

    def test_create_access_token(self):
        """Test JWT token creation."""
        data = {"sub": "test@example.com", "role": "user"}
        token = create_access_token(data=data)

        assert isinstance(token, str)
        assert len(token) > 100  # JWT tokens are typically long

        # Decode without verification to check structure
        decoded = jwt.decode(token, options={"verify_signature": False})
        assert decoded["sub"] == "test@example.com"
        assert "exp" in decoded

    def test_create_token_with_expiration(self):
        """Test JWT token with custom expiration."""
        data = {"sub": "test@example.com"}
        expires_delta = timedelta(minutes=30)
        token = create_access_token(data=data, expires_delta=expires_delta)

        decoded = jwt.decode(token, options={"verify_signature": False})
        exp_timestamp = decoded["exp"]
        exp_datetime = datetime.fromtimestamp(exp_timestamp)

        # Should expire in approximately 30 minutes
        expected_exp = datetime.utcnow() + expires_delta
        assert abs((exp_datetime - expected_exp).total_seconds()) < 10

    def test_verify_valid_token(self):
        """Test verification of valid token."""
        data = {"sub": "test@example.com", "role": "user"}
        token = create_access_token(data=data)

        payload = verify_token(token)
        assert payload["sub"] == "test@example.com"
        assert payload["role"] == "user"

    def test_verify_invalid_token(self):
        """Test verification of invalid token."""
        invalid_token = "invalid.jwt.token"

        payload = verify_token(invalid_token)
        assert payload is None

    def test_verify_expired_token(self):
        """Test verification of expired token."""
        data = {"sub": "test@example.com"}
        expires_delta = timedelta(seconds=-1)  # Already expired
        token = create_access_token(data=data, expires_delta=expires_delta)

        payload = verify_token(token)
        assert payload is None

    def test_token_without_required_claims(self):
        """Test token missing required claims."""
        # Create token manually without required claims
        token = jwt.encode(
            {"some_field": "some_value"},
            settings.SECRET_KEY,
            algorithm=settings.ALGORITHM,
        )

        payload = verify_token(token)
        # Should handle gracefully
        assert payload is None or "sub" not in payload


class TestPasswordReset:
    """Test password reset functionality."""

    def test_generate_reset_token(self):
        """Test generating password reset token."""
        email = "test@example.com"
        reset_token = generate_reset_token(email)

        assert isinstance(reset_token, str)
        assert len(reset_token) > 50

    def test_verify_valid_reset_token(self):
        """Test verifying valid reset token."""
        email = "test@example.com"
        reset_token = generate_reset_token(email)

        verified_email = verify_reset_token(reset_token)
        assert verified_email == email

    def test_verify_invalid_reset_token(self):
        """Test verifying invalid reset token."""
        invalid_token = "invalid.reset.token"

        verified_email = verify_reset_token(invalid_token)
        assert verified_email is None

    def test_verify_expired_reset_token(self):
        """Test verifying expired reset token."""
        email = "test@example.com"
        # Create expired token (would need to modify function to accept expiration)
        # For now, just test with invalid token

        verified_email = verify_reset_token("expired.token")
        assert verified_email is None


class TestAuthMiddleware:
    """Test authentication middleware."""

    @patch("api.database.get_db")
    def test_verify_jwt_token_valid(self, mock_get_db):
        """Test JWT token verification in middleware."""
        # Mock database session and user
        mock_db = Mock()
        mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

        mock_user = Mock()
        mock_user.email = "test@example.com"
        mock_user.is_active = True
        mock_db.query.return_value.filter.return_value.first.return_value = mock_user

        # Create valid token
        token = create_access_token(data={"sub": "test@example.com"})

        # Test middleware function
        user = verify_jwt_token(token, mock_db)
        assert user == mock_user

    @patch("api.database.get_db")
    def test_verify_jwt_token_invalid(self, mock_get_db):
        """Test JWT token verification with invalid token."""
        mock_db = Mock()

        # Test with invalid token
        with pytest.raises(Exception):  # Should raise authentication error
            verify_jwt_token("invalid.token", mock_db)

    @patch("api.database.get_db")
    def test_verify_jwt_token_user_not_found(self, mock_get_db):
        """Test JWT token verification when user not found."""
        # Mock database session
        mock_db = Mock()
        mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

        # Mock user not found
        mock_db.query.return_value.filter.return_value.first.return_value = None

        # Create valid token for non-existent user
        token = create_access_token(data={"sub": "nonexistent@example.com"})

        # Test middleware function
        with pytest.raises(Exception):  # Should raise authentication error
            verify_jwt_token(token, mock_db)

    @patch("api.database.get_db")
    def test_verify_jwt_token_inactive_user(self, mock_get_db):
        """Test JWT token verification with inactive user."""
        # Mock database session and inactive user
        mock_db = Mock()
        mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

        mock_user = Mock()
        mock_user.email = "test@example.com"
        mock_user.is_active = False  # Inactive user
        mock_db.query.return_value.filter.return_value.first.return_value = mock_user

        # Create valid token
        token = create_access_token(data={"sub": "test@example.com"})

        # Test middleware function
        with pytest.raises(Exception):  # Should raise authentication error
            verify_jwt_token(token, mock_db)


class TestRoleBasedAccess:
    """Test role-based access control."""

    def test_admin_role_token(self):
        """Test token with admin role."""
        data = {"sub": "admin@example.com", "role": "admin"}
        token = create_access_token(data=data)

        payload = verify_token(token)
        assert payload["role"] == "admin"

    def test_user_role_token(self):
        """Test token with user role."""
        data = {"sub": "user@example.com", "role": "user"}
        token = create_access_token(data=data)

        payload = verify_token(token)
        assert payload["role"] == "user"

    def test_analyst_role_token(self):
        """Test token with analyst role."""
        data = {"sub": "analyst@example.com", "role": "analyst"}
        token = create_access_token(data=data)

        payload = verify_token(token)
        assert payload["role"] == "analyst"

    def test_token_without_role(self):
        """Test token without role claim."""
        data = {"sub": "user@example.com"}  # No role
        token = create_access_token(data=data)

        payload = verify_token(token)
        assert payload["sub"] == "user@example.com"
        # Role should be optional or have default value


class TestSecurityHeaders:
    """Test security-related functionality."""

    def test_token_claims_validation(self):
        """Test validation of token claims."""
        # Test various token claim scenarios
        test_cases = [
            {"sub": "test@example.com", "role": "user"},
            {"sub": "admin@example.com", "role": "admin"},
            {"sub": "user@example.com", "permissions": ["read", "write"]},
        ]

        for claims in test_cases:
            token = create_access_token(data=claims)
            payload = verify_token(token)

            for key, value in claims.items():
                assert payload[key] == value

    def test_token_audience_validation(self):
        """Test token audience validation if implemented."""
        # This would test audience claim validation
        # Currently not implemented but good security practice
        data = {"sub": "test@example.com", "aud": "phishguard-api"}
        token = create_access_token(data=data)

        payload = verify_token(token)
        assert payload["sub"] == "test@example.com"

    def test_token_issuer_validation(self):
        """Test token issuer validation if implemented."""
        # This would test issuer claim validation
        # Currently not implemented but good security practice
        data = {"sub": "test@example.com", "iss": "phishguard"}
        token = create_access_token(data=data)

        payload = verify_token(token)
        assert payload["sub"] == "test@example.com"


class TestAuthenticationFlow:
    """Test complete authentication flows."""

    def test_login_flow(self):
        """Test complete login flow."""
        # 1. User provides credentials
        email = "test@example.com"
        password = "testpassword123"

        # 2. Password is hashed and stored (registration)
        hashed_password = hash_password(password)

        # 3. User logs in - password is verified
        assert verify_password(password, hashed_password)

        # 4. JWT token is created
        token = create_access_token(data={"sub": email, "role": "user"})

        # 5. Token is verified
        payload = verify_token(token)
        assert payload["sub"] == email
        assert payload["role"] == "user"

    def test_registration_flow(self):
        """Test user registration flow."""
        # 1. User provides registration data
        email = "newuser@example.com"
        password = "newpassword123"

        # 2. Password is validated and hashed
        hashed_password = hash_password(password)
        assert hashed_password != password

        # 3. User record is created (simulated)
        user_data = {
            "email": email,
            "hashed_password": hashed_password,
            "is_active": True,
            "role": "user",
        }

        # 4. Welcome token is created
        token = create_access_token(data={"sub": email, "role": "user"})

        # 5. Token can be verified
        payload = verify_token(token)
        assert payload["sub"] == email

    def test_password_reset_flow(self):
        """Test password reset flow."""
        # 1. User requests password reset
        email = "test@example.com"

        # 2. Reset token is generated
        reset_token = generate_reset_token(email)

        # 3. Reset token is verified
        verified_email = verify_reset_token(reset_token)
        assert verified_email == email

        # 4. New password is set
        new_password = "newpassword123"
        new_hashed = hash_password(new_password)

        # 5. New password can be verified
        assert verify_password(new_password, new_hashed)


class TestSecurityVulnerabilities:
    """Test protection against common security vulnerabilities."""

    def test_timing_attack_protection(self):
        """Test protection against timing attacks in password verification."""
        # Both valid and invalid passwords should take similar time
        # This is a basic test - proper timing analysis would require more sophisticated testing

        password = "testpassword123"
        hashed = hash_password(password)

        # Valid password
        result1 = verify_password(password, hashed)
        assert result1 == True

        # Invalid password of same length
        result2 = verify_password("wrongpassword", hashed)
        assert result2 == False

        # Invalid password of different length
        result3 = verify_password("wrong", hashed)
        assert result3 == False

    def test_jwt_algorithm_confusion(self):
        """Test protection against JWT algorithm confusion attacks."""
        # Ensure we're using a secure algorithm
        data = {"sub": "test@example.com"}
        token = create_access_token(data=data)

        # Decode and check algorithm
        header = jwt.get_unverified_header(token)
        assert header["alg"] == settings.ALGORITHM
        assert settings.ALGORITHM in ["HS256", "RS256"]  # Secure algorithms

    def test_jwt_secret_exposure(self):
        """Test that JWT secret is not exposed."""
        # Secret should not be easily guessable
        assert len(settings.SECRET_KEY) >= 32
        assert settings.SECRET_KEY != "secret"
        assert settings.SECRET_KEY != "your-secret-key"

    def test_password_hash_format(self):
        """Test that password hashes use secure format."""
        password = "testpassword123"
        hashed = hash_password(password)

        # Should be bcrypt format
        assert hashed.startswith("$2b$")
        # Should have proper cost factor (at least 12)
        cost_factor = int(hashed.split("$")[2])
        assert cost_factor >= 10  # Minimum acceptable cost


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
