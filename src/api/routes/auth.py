"""
Authentication Routes for PhishGuard API

Comprehensive authentication endpoints including login, registration,
password management, and multi-factor authentication.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request, Response, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import secrets
import hashlib
import pyotp
import qrcode
import io
import base64
from pydantic import BaseModel, EmailStr, validator

from ..database import get_db
from ..models.user import User, UserRole, LoginAttempt
from ..models.audit_log import AuditLog, ActionType, StatusType, SeverityLevel
from ..middleware.auth_middleware import AuthMiddleware, get_current_user
from ..services.user_service import UserService
from ..services.notification_service import NotificationService
from ..utils.security import verify_password, get_password_hash, generate_reset_token
from ..utils.validators import validate_password_strength, validate_email_format
from ..utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/auth", tags=["authentication"])
security = HTTPBearer()
auth_middleware = AuthMiddleware()

# Pydantic models for request/response
class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    remember_me: bool = False
    device_name: Optional[str] = None

class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: Dict[str, Any]

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    confirm_password: str
    first_name: str
    last_name: str
    department: Optional[str] = None
    job_title: Optional[str] = None
    
    @validator('confirm_password')
    def passwords_match(cls, v, values, **kwargs):
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v

class RegisterResponse(BaseModel):
    message: str
    user_id: str
    email: str

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str
    confirm_password: str
    
    @validator('confirm_password')
    def passwords_match(cls, v, values, **kwargs):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str
    confirm_password: str
    
    @validator('confirm_password')
    def passwords_match(cls, v, values, **kwargs):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class MFASetupResponse(BaseModel):
    secret: str
    qr_code: str
    backup_codes: list

class MFAVerifyRequest(BaseModel):
    token: str

class DeviceInfo(BaseModel):
    device_name: str
    device_type: str
    user_agent: str
    ip_address: str


@router.post("/login", response_model=LoginResponse)
async def login(
    request: LoginRequest,
    http_request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Authenticate user and return access tokens.
    
    Args:
        request: Login request data
        http_request: FastAPI request object
        background_tasks: Background task handler
        db: Database session
        
    Returns:
        Access token and user information
        
    Raises:
        HTTPException: If authentication fails
    """
    try:
        # Get client information
        client_ip = http_request.client.host
        user_agent = http_request.headers.get("user-agent", "")
        
        # Validate email format
        if not validate_email_format(request.email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email format"
            )
        
        # Check for user
        user = db.query(User).filter(User.email == request.email).first()
        
        # Record login attempt
        login_attempt = LoginAttempt(
            email=request.email,
            ip_address=client_ip,
            user_agent=user_agent,
            success=False,
            user_id=user.id if user else None
        )
        
        if not user:
            # User not found
            login_attempt.failure_reason = "user_not_found"
            db.add(login_attempt)
            db.commit()
            
            # Log security event
            background_tasks.add_task(
                log_security_event,
                db,
                ActionType.LOGIN_FAILED,
                request.email,
                client_ip,
                user_agent,
                "User not found"
            )
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        # Check if account is locked
        if user.is_locked:
            login_attempt.failure_reason = "account_locked"
            db.add(login_attempt)
            db.commit()
            
            background_tasks.add_task(
                log_security_event,
                db,
                ActionType.LOGIN_FAILED,
                user.email,
                client_ip,
                user_agent,
                "Account locked"
            )
            
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Account is locked. Please contact administrator."
            )
        
        # Check if account is active
        if not user.is_active:
            login_attempt.failure_reason = "account_inactive"
            db.add(login_attempt)
            db.commit()
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is not active"
            )
        
        # Verify password
        if not verify_password(request.password, user.password_hash):
            # Increment failed login attempts
            user.failed_login_attempts += 1
            user.last_failed_login = datetime.utcnow()
            
            # Lock account if too many failed attempts
            if user.failed_login_attempts >= 5:
                user.is_locked = True
                user.locked_at = datetime.utcnow()
                
                # Send account lockout notification
                background_tasks.add_task(
                    send_account_lockout_notification,
                    user.email,
                    client_ip
                )
            
            login_attempt.failure_reason = "invalid_password"
            db.add(login_attempt)
            db.commit()
            
            background_tasks.add_task(
                log_security_event,
                db,
                ActionType.LOGIN_FAILED,
                user.email,
                client_ip,
                user_agent,
                f"Invalid password. Attempts: {user.failed_login_attempts}"
            )
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        # Check if MFA is enabled and required
        if user.mfa_enabled and not request.dict().get("mfa_token"):
            # Return special response indicating MFA is required
            login_attempt.requires_mfa = True
            login_attempt.success = False
            login_attempt.failure_reason = "mfa_required"
            db.add(login_attempt)
            db.commit()
            
            return {
                "requires_mfa": True,
                "message": "Multi-factor authentication required",
                "user_id": str(user.id)
            }
        
        # Verify MFA token if provided
        if user.mfa_enabled and request.dict().get("mfa_token"):
            mfa_token = request.dict().get("mfa_token")
            if not verify_mfa_token(user.mfa_secret, mfa_token):
                login_attempt.failure_reason = "invalid_mfa"
                db.add(login_attempt)
                db.commit()
                
                background_tasks.add_task(
                    log_security_event,
                    db,
                    ActionType.LOGIN_FAILED,
                    user.email,
                    client_ip,
                    user_agent,
                    "Invalid MFA token"
                )
                
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid MFA token"
                )
        
        # Successful login
        user.failed_login_attempts = 0
        user.last_login = datetime.utcnow()
        user.last_login_ip = client_ip
        
        # Update login attempt
        login_attempt.success = True
        login_attempt.user_id = user.id
        db.add(login_attempt)
        
        # Generate tokens
        token_data = {
            "sub": str(user.id),
            "email": user.email,
            "roles": [role.name for role in user.roles]
        }
        
        access_token = auth_middleware.create_access_token(token_data)
        refresh_token = auth_middleware.create_refresh_token(token_data)
        
        # Store device information if provided
        if request.device_name:
            device_info = DeviceInfo(
                device_name=request.device_name,
                device_type="web",  # Could be enhanced to detect actual device type
                user_agent=user_agent,
                ip_address=client_ip
            )
            # Store device info in user session or separate table
        
        db.commit()
        
        # Log successful login
        background_tasks.add_task(
            log_security_event,
            db,
            ActionType.LOGIN,
            user.email,
            client_ip,
            user_agent,
            "Successful login"
        )
        
        # Return successful response
        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=auth_middleware.access_token_expire_minutes * 60,
            user={
                "id": str(user.id),
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "department": user.department,
                "job_title": user.job_title,
                "roles": [role.name for role in user.roles],
                "mfa_enabled": user.mfa_enabled,
                "last_login": user.last_login.isoformat() if user.last_login else None
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service error"
        )


@router.post("/register", response_model=RegisterResponse)
async def register(
    request: RegisterRequest,
    http_request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Register a new user account.
    
    Args:
        request: Registration request data
        http_request: FastAPI request object
        background_tasks: Background task handler
        db: Database session
        
    Returns:
        Registration confirmation
        
    Raises:
        HTTPException: If registration fails
    """
    try:
        # Validate email format
        if not validate_email_format(request.email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email format"
            )
        
        # Validate password strength
        password_validation = validate_password_strength(request.password)
        if not password_validation["valid"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Password validation failed: {', '.join(password_validation['errors'])}"
            )
        
        # Check if user already exists
        existing_user = db.query(User).filter(User.email == request.email).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User with this email already exists"
            )
        
        # Create new user
        user_service = UserService(db)
        user = user_service.create_user(
            email=request.email,
            password=request.password,
            first_name=request.first_name,
            last_name=request.last_name,
            department=request.department,
            job_title=request.job_title
        )
        
        # Send welcome email
        background_tasks.add_task(
            send_welcome_email,
            user.email,
            user.first_name
        )
        
        # Log user creation
        background_tasks.add_task(
            log_security_event,
            db,
            ActionType.USER_CREATE,
            user.email,
            http_request.client.host,
            http_request.headers.get("user-agent", ""),
            "User registered successfully"
        )
        
        return RegisterResponse(
            message="User registered successfully",
            user_id=str(user.id),
            email=user.email
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration service error"
        )


@router.post("/logout")
async def logout(
    http_request: Request,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Logout user and invalidate tokens.
    
    Args:
        http_request: FastAPI request object
        background_tasks: Background task handler
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        Logout confirmation
    """
    try:
        # In a production system, you would:
        # 1. Add the token to a blacklist/revocation list
        # 2. Clear any server-side session data
        # 3. Potentially notify other services of the logout
        
        # Log logout event
        background_tasks.add_task(
            log_security_event,
            db,
            ActionType.LOGOUT,
            current_user.email,
            http_request.client.host,
            http_request.headers.get("user-agent", ""),
            "User logged out"
        )
        
        return {"message": "Logged out successfully"}
        
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout service error"
        )


@router.post("/refresh")
async def refresh_token(
    request: RefreshTokenRequest,
    db: Session = Depends(get_db)
):
    """
    Refresh access token using refresh token.
    
    Args:
        request: Refresh token request
        db: Database session
        
    Returns:
        New access token
        
    Raises:
        HTTPException: If refresh token is invalid
    """
    try:
        # Validate refresh token
        payload = await auth_middleware.validate_token(request.refresh_token)
        if not payload or payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        # Get user
        user_id = payload.get("sub")
        user = db.query(User).filter(User.id == user_id).first()
        
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        # Generate new access token
        token_data = {
            "sub": str(user.id),
            "email": user.email,
            "roles": [role.name for role in user.roles]
        }
        
        new_access_token = auth_middleware.create_access_token(token_data)
        
        return {
            "access_token": new_access_token,
            "token_type": "bearer",
            "expires_in": auth_middleware.access_token_expire_minutes * 60
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh service error"
        )


@router.post("/change-password")
async def change_password(
    request: PasswordChangeRequest,
    http_request: Request,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Change user password.
    
    Args:
        request: Password change request
        http_request: FastAPI request object
        background_tasks: Background task handler
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        Password change confirmation
        
    Raises:
        HTTPException: If password change fails
    """
    try:
        # Verify current password
        if not verify_password(request.current_password, current_user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )
        
        # Validate new password strength
        password_validation = validate_password_strength(request.new_password)
        if not password_validation["valid"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Password validation failed: {', '.join(password_validation['errors'])}"
            )
        
        # Update password
        current_user.password_hash = get_password_hash(request.new_password)
        current_user.password_changed_at = datetime.utcnow()
        current_user.force_password_change = False
        
        db.commit()
        
        # Send password change notification
        background_tasks.add_task(
            send_password_change_notification,
            current_user.email,
            http_request.client.host
        )
        
        # Log password change
        background_tasks.add_task(
            log_security_event,
            db,
            ActionType.PASSWORD_CHANGE,
            current_user.email,
            http_request.client.host,
            http_request.headers.get("user-agent", ""),
            "Password changed successfully"
        )
        
        return {"message": "Password changed successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password change error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password change service error"
        )


@router.post("/forgot-password")
async def forgot_password(
    request: ForgotPasswordRequest,
    http_request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Initiate password reset process.
    
    Args:
        request: Forgot password request
        http_request: FastAPI request object
        background_tasks: Background task handler
        db: Database session
        
    Returns:
        Password reset confirmation
    """
    try:
        # Check if user exists
        user = db.query(User).filter(User.email == request.email).first()
        
        # Always return success to prevent email enumeration
        if user and user.is_active:
            # Generate reset token
            reset_token = generate_reset_token()
            
            # Store reset token (in production, use a secure storage with expiration)
            user.reset_token = reset_token
            user.reset_token_expires = datetime.utcnow() + timedelta(hours=1)
            
            db.commit()
            
            # Send password reset email
            background_tasks.add_task(
                send_password_reset_email,
                user.email,
                reset_token
            )
            
            # Log password reset request
            background_tasks.add_task(
                log_security_event,
                db,
                ActionType.PASSWORD_RESET,
                user.email,
                http_request.client.host,
                http_request.headers.get("user-agent", ""),
                "Password reset requested"
            )
        
        return {"message": "If the email exists, a password reset link has been sent"}
        
    except Exception as e:
        logger.error(f"Password reset error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password reset service error"
        )


@router.post("/reset-password")
async def reset_password(
    request: ResetPasswordRequest,
    http_request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Reset password using reset token.
    
    Args:
        request: Password reset request
        http_request: FastAPI request object
        background_tasks: Background task handler
        db: Database session
        
    Returns:
        Password reset confirmation
        
    Raises:
        HTTPException: If reset fails
    """
    try:
        # Find user by reset token
        user = db.query(User).filter(
            User.reset_token == request.token,
            User.reset_token_expires > datetime.utcnow()
        ).first()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token"
            )
        
        # Validate new password strength
        password_validation = validate_password_strength(request.new_password)
        if not password_validation["valid"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Password validation failed: {', '.join(password_validation['errors'])}"
            )
        
        # Update password
        user.password_hash = get_password_hash(request.new_password)
        user.password_changed_at = datetime.utcnow()
        user.reset_token = None
        user.reset_token_expires = None
        user.failed_login_attempts = 0
        user.is_locked = False
        user.locked_at = None
        
        db.commit()
        
        # Send password reset confirmation
        background_tasks.add_task(
            send_password_reset_confirmation,
            user.email
        )
        
        # Log successful password reset
        background_tasks.add_task(
            log_security_event,
            db,
            ActionType.PASSWORD_RESET,
            user.email,
            http_request.client.host,
            http_request.headers.get("user-agent", ""),
            "Password reset completed"
        )
        
        return {"message": "Password reset successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password reset error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password reset service error"
        )


@router.post("/setup-mfa", response_model=MFASetupResponse)
async def setup_mfa(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Setup multi-factor authentication for user.
    
    Args:
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        MFA setup information including QR code
    """
    try:
        # Generate MFA secret
        secret = pyotp.random_base32()
        
        # Generate QR code
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=current_user.email,
            issuer_name="PhishGuard"
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert QR code to base64
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        qr_code_base64 = base64.b64encode(img_buffer.getvalue()).decode()
        
        # Generate backup codes
        backup_codes = [secrets.token_hex(4) for _ in range(10)]
        
        # Store MFA configuration (but don't enable until verified)
        current_user.mfa_secret = secret
        current_user.mfa_backup_codes = backup_codes
        
        db.commit()
        
        return MFASetupResponse(
            secret=secret,
            qr_code=f"data:image/png;base64,{qr_code_base64}",
            backup_codes=backup_codes
        )
        
    except Exception as e:
        logger.error(f"MFA setup error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA setup service error"
        )


@router.post("/verify-mfa")
async def verify_mfa(
    request: MFAVerifyRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Verify MFA token and enable MFA.
    
    Args:
        request: MFA verification request
        background_tasks: Background task handler
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        MFA verification confirmation
        
    Raises:
        HTTPException: If verification fails
    """
    try:
        if not current_user.mfa_secret:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA setup not initiated"
            )
        
        # Verify MFA token
        if not verify_mfa_token(current_user.mfa_secret, request.token):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid MFA token"
            )
        
        # Enable MFA
        current_user.mfa_enabled = True
        current_user.mfa_enabled_at = datetime.utcnow()
        
        db.commit()
        
        # Send MFA enabled notification
        background_tasks.add_task(
            send_mfa_enabled_notification,
            current_user.email
        )
        
        return {"message": "MFA enabled successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MFA verification error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA verification service error"
        )


@router.delete("/disable-mfa")
async def disable_mfa(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Disable multi-factor authentication.
    
    Args:
        background_tasks: Background task handler
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        MFA disable confirmation
    """
    try:
        # Disable MFA
        current_user.mfa_enabled = False
        current_user.mfa_secret = None
        current_user.mfa_backup_codes = None
        current_user.mfa_enabled_at = None
        
        db.commit()
        
        # Send MFA disabled notification
        background_tasks.add_task(
            send_mfa_disabled_notification,
            current_user.email
        )
        
        return {"message": "MFA disabled successfully"}
        
    except Exception as e:
        logger.error(f"MFA disable error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA disable service error"
        )


# Helper functions
def verify_mfa_token(secret: str, token: str) -> bool:
    """
    Verify MFA token against secret.
    
    Args:
        secret: MFA secret
        token: Token to verify
        
    Returns:
        True if token is valid
    """
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)  # Allow 1 time step tolerance
    except Exception:
        return False


async def log_security_event(
    db: Session,
    action: ActionType,
    user_email: str,
    ip_address: str,
    user_agent: str,
    details: str
):
    """Log security event to audit log."""
    try:
        audit_log = AuditLog.create_audit_entry(
            action=action,
            user_email=user_email,
            description=details,
            ip_address=ip_address,
            user_agent=user_agent,
            severity=SeverityLevel.MEDIUM if action == ActionType.LOGIN_FAILED else SeverityLevel.LOW,
            status=StatusType.SUCCESS if action in [ActionType.LOGIN, ActionType.PASSWORD_CHANGE] else StatusType.FAILURE
        )
        
        db.add(audit_log)
        db.commit()
    except Exception as e:
        logger.error(f"Error logging security event: {str(e)}")


async def send_welcome_email(email: str, first_name: str):
    """Send welcome email to new user."""
    # Implementation would use notification service
    pass


async def send_account_lockout_notification(email: str, ip_address: str):
    """Send account lockout notification."""
    # Implementation would use notification service
    pass


async def send_password_change_notification(email: str, ip_address: str):
    """Send password change notification."""
    # Implementation would use notification service
    pass


async def send_password_reset_email(email: str, reset_token: str):
    """Send password reset email."""
    # Implementation would use notification service
    pass


async def send_password_reset_confirmation(email: str):
    """Send password reset confirmation."""
    # Implementation would use notification service
    pass


async def send_mfa_enabled_notification(email: str):
    """Send MFA enabled notification."""
    # Implementation would use notification service
    pass


async def send_mfa_disabled_notification(email: str):
    """Send MFA disabled notification."""
    # Implementation would use notification service
    pass
