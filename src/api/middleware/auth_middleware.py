"""
Authentication Middleware for PhishGuard API

This middleware handles JWT token validation, user authentication,
and request authorization for all API endpoints.
"""

from fastapi import Request, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
import logging

from ..utils.config import settings
from ..database import get_db
from ..models.user import User
from ..utils.logger import get_logger

logger = get_logger(__name__)
security = HTTPBearer()

class AuthMiddleware:
    """JWT Authentication middleware for FastAPI."""
    
    def __init__(self):
        self.secret_key = settings.JWT_SECRET_KEY
        self.algorithm = settings.JWT_ALGORITHM
        self.access_token_expire_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES

    async def __call__(self, request: Request, call_next):
        """Process authentication for each request."""
        
        # Skip authentication for certain paths
        skip_paths = [
            "/docs", "/redoc", "/openapi.json", 
            "/health", "/auth/login", "/auth/register"
        ]
        
        if any(request.url.path.startswith(path) for path in skip_paths):
            return await call_next(request)
        
        try:
            # Extract token from Authorization header
            authorization = request.headers.get("Authorization")
            if not authorization or not authorization.startswith("Bearer "):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Missing or invalid authorization header",
                    headers={"WWW-Authenticate": "Bearer"}
                )
            
            token = authorization.split(" ")[1]
            
            # Validate and decode token
            user_info = await self.validate_token(token)
            if not user_info:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired token",
                    headers={"WWW-Authenticate": "Bearer"}
                )
            
            # Add user info to request state
            request.state.user = user_info
            request.state.user_id = user_info["sub"]
            request.state.user_email = user_info.get("email")
            request.state.user_roles = user_info.get("roles", [])
            
            # Log authentication success
            logger.info(f"Authenticated user: {user_info.get('email')} for {request.method} {request.url.path}")
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        response = await call_next(request)
        return response

    async def validate_token(self, token: str) -> Optional[dict]:
        """
        Validate JWT token and return user information.
        
        Args:
            token: JWT token string
            
        Returns:
            User information dict if valid, None if invalid
        """
        try:
            # Decode JWT token
            payload = jwt.decode(
                token, 
                self.secret_key, 
                algorithms=[self.algorithm]
            )
            
            # Check if token is expired
            exp_timestamp = payload.get("exp")
            if exp_timestamp:
                exp_datetime = datetime.fromtimestamp(exp_timestamp)
                if datetime.utcnow() > exp_datetime:
                    logger.warning("Token expired")
                    return None
            
            # Validate required claims
            user_id = payload.get("sub")
            if not user_id:
                logger.warning("Token missing user ID")
                return None
            
            return payload
            
        except JWTError as e:
            logger.warning(f"JWT validation error: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Token validation error: {str(e)}")
            return None

    def create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """
        Create JWT access token.
        
        Args:
            data: Data to encode in token
            expires_delta: Token expiration time
            
        Returns:
            JWT token string
        """
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        
        to_encode.update({"exp": expire})
        
        encoded_jwt = jwt.encode(
            to_encode, 
            self.secret_key, 
            algorithm=self.algorithm
        )
        
        return encoded_jwt

    def create_refresh_token(self, data: dict) -> str:
        """
        Create JWT refresh token with longer expiration.
        
        Args:
            data: Data to encode in token
            
        Returns:
            JWT refresh token string
        """
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=7)  # Refresh token expires in 7 days
        to_encode.update({"exp": expire, "type": "refresh"})
        
        encoded_jwt = jwt.encode(
            to_encode,
            self.secret_key,
            algorithm=self.algorithm
        )
        
        return encoded_jwt


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db = Depends(get_db)
) -> User:
    """
    Dependency to get current authenticated user.
    
    Args:
        credentials: HTTP Bearer credentials
        db: Database session
        
    Returns:
        Current authenticated user
        
    Raises:
        HTTPException: If user not found or token invalid
    """
    try:
        token = credentials.credentials
        auth_middleware = AuthMiddleware()
        
        # Validate token
        payload = await auth_middleware.validate_token(token)
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        # Get user from database
        user_id = payload.get("sub")
        user = db.query(User).filter(User.id == user_id).first()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Inactive user",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        return user
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting current user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication error",
            headers={"WWW-Authenticate": "Bearer"}
        )


async def get_current_admin_user(current_user: User = Depends(get_current_user)) -> User:
    """
    Dependency to get current authenticated admin user.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        Current authenticated admin user
        
    Raises:
        HTTPException: If user is not an admin
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    
    return current_user


async def verify_user_permissions(
    required_permissions: list,
    current_user: User = Depends(get_current_user)
) -> bool:
    """
    Verify user has required permissions.
    
    Args:
        required_permissions: List of required permission strings
        current_user: Current authenticated user
        
    Returns:
        True if user has all required permissions
        
    Raises:
        HTTPException: If user lacks required permissions
    """
    user_permissions = current_user.get_permissions()  # This would be implemented on User model
    
    missing_permissions = []
    for permission in required_permissions:
        if permission not in user_permissions:
            missing_permissions.append(permission)
    
    if missing_permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Missing permissions: {', '.join(missing_permissions)}"
        )
    
    return True


class RoleBasedAccessControl:
    """Role-based access control helper."""
    
    @staticmethod
    def require_roles(allowed_roles: list):
        """
        Decorator to require specific roles for endpoint access.
        
        Args:
            allowed_roles: List of allowed role names
            
        Returns:
            Dependency function
        """
        def role_checker(current_user: User = Depends(get_current_user)):
            user_roles = [role.name for role in current_user.roles]  # Assuming User has roles relationship
            
            if not any(role in user_roles for role in allowed_roles):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Access denied. Required roles: {', '.join(allowed_roles)}"
                )
            
            return current_user
        
        return role_checker


# Rate limiting decorator
class RateLimiter:
    """Simple rate limiter for API endpoints."""
    
    def __init__(self):
        self.requests = {}  # In production, use Redis
    
    def limit_requests(self, max_requests: int, window_seconds: int):
        """
        Rate limiting decorator.
        
        Args:
            max_requests: Maximum number of requests
            window_seconds: Time window in seconds
        """
        def decorator(func):
            async def wrapper(request: Request, *args, **kwargs):
                # Get client identifier
                client_id = request.client.host
                current_time = datetime.utcnow()
                
                # Initialize or clean up request history
                if client_id not in self.requests:
                    self.requests[client_id] = []
                
                # Remove old requests outside the window
                cutoff_time = current_time - timedelta(seconds=window_seconds)
                self.requests[client_id] = [
                    req_time for req_time in self.requests[client_id]
                    if req_time > cutoff_time
                ]
                
                # Check rate limit
                if len(self.requests[client_id]) >= max_requests:
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail="Rate limit exceeded"
                    )
                
                # Add current request
                self.requests[client_id].append(current_time)
                
                return await func(request, *args, **kwargs)
            
            return wrapper
        return decorator


# Initialize middleware and helpers
auth_middleware = AuthMiddleware()
rbac = RoleBasedAccessControl()
rate_limiter = RateLimiter()

# Common role requirements
require_admin = rbac.require_roles(["admin"])
require_analyst = rbac.require_roles(["admin", "analyst"])
require_viewer = rbac.require_roles(["admin", "analyst", "viewer"])

# Rate limiting decorators
limit_login_attempts = rate_limiter.limit_requests(max_requests=5, window_seconds=300)  # 5 attempts per 5 minutes
limit_api_requests = rate_limiter.limit_requests(max_requests=100, window_seconds=60)  # 100 requests per minute
