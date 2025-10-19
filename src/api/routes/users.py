"""
Users Routes for PhishGuard API

Comprehensive user management endpoints including user CRUD operations,
profile management, role assignments, and security settings.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request, Query, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import desc, and_, or_, func
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, validator, EmailStr
import uuid
from enum import Enum

from ..database import get_db
from ..models.user import User, Role, UserSettings, UserSecuritySettings
from ..models.audit_log import AuditLog, ActionType
from ..models.simulation import SimulationParticipant
from ..middleware.auth_middleware import get_current_user, get_current_admin_user, RoleBasedAccessControl
from ..services.user_service import UserService
from ..utils.security import hash_password, verify_password, generate_temporary_password
from ..utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/users", tags=["users"])

# Pydantic models for request/response
class UserCreateRequest(BaseModel):
    email: EmailStr
    first_name: str
    last_name: str
    department: Optional[str] = None
    role: Role = Role.USER
    phone_number: Optional[str] = None
    job_title: Optional[str] = None
    manager_email: Optional[EmailStr] = None
    send_welcome_email: bool = True
    temporary_password: Optional[str] = None

class UserUpdateRequest(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    department: Optional[str] = None
    role: Optional[Role] = None
    phone_number: Optional[str] = None
    job_title: Optional[str] = None
    manager_email: Optional[EmailStr] = None
    is_active: Optional[bool] = None

class UserPasswordUpdateRequest(BaseModel):
    current_password: str
    new_password: str
    confirm_password: str
    
    @validator('confirm_password')
    def passwords_match(cls, v, values, **kwargs):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v

class UserSecuritySettingsRequest(BaseModel):
    mfa_enabled: Optional[bool] = None
    login_notifications: Optional[bool] = None
    security_alerts: Optional[bool] = None
    session_timeout: Optional[int] = None  # minutes
    allowed_ip_ranges: Optional[List[str]] = None
    require_password_change: Optional[bool] = None

class UserSettingsRequest(BaseModel):
    notification_preferences: Optional[Dict[str, bool]] = None
    language: Optional[str] = None
    timezone: Optional[str] = None
    email_frequency: Optional[str] = None  # immediate, daily, weekly
    dashboard_layout: Optional[Dict[str, Any]] = None

class BulkUserOperationRequest(BaseModel):
    user_ids: List[uuid.UUID]
    operation: str  # activate, deactivate, assign_role, update_department
    parameters: Optional[Dict[str, Any]] = None

class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    first_name: str
    last_name: str
    full_name: str
    department: Optional[str]
    role: Role
    phone_number: Optional[str]
    job_title: Optional[str]
    manager_email: Optional[str]
    is_active: bool
    last_login_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    profile_completion: float
    risk_score: Optional[float]

class UserDetailResponse(UserResponse):
    security_settings: Dict[str, Any]
    notification_settings: Dict[str, Any]
    login_history: List[Dict[str, Any]]
    simulation_stats: Dict[str, Any]
    training_progress: Dict[str, Any]
    recent_activities: List[Dict[str, Any]]

class UserStatsResponse(BaseModel):
    total_users: int
    active_users: int
    inactive_users: int
    users_by_role: Dict[str, int]
    users_by_department: Dict[str, int]
    recent_registrations: int
    average_risk_score: float
    mfa_adoption_rate: float


@router.post("", response_model=UserResponse)
async def create_user(
    user_request: UserCreateRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Create a new user account.
    
    Args:
        user_request: User creation data
        background_tasks: Background task handler
        current_user: Current authenticated admin user
        db: Database session
        
    Returns:
        Created user data
    """
    try:
        user_service = UserService(db)
        
        # Check if user already exists
        existing_user = await user_service.get_user_by_email(user_request.email)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User with this email already exists"
            )
        
        # Validate manager if provided
        manager = None
        if user_request.manager_email:
            manager = await user_service.get_user_by_email(user_request.manager_email)
            if not manager:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Manager not found"
                )
        
        # Generate temporary password if not provided
        temp_password = user_request.temporary_password
        if not temp_password:
            temp_password = generate_temporary_password()
        
        # Create user
        user = await user_service.create_user(
            email=user_request.email,
            first_name=user_request.first_name,
            last_name=user_request.last_name,
            department=user_request.department,
            role=user_request.role,
            phone_number=user_request.phone_number,
            job_title=user_request.job_title,
            manager_id=manager.id if manager else None,
            temporary_password=temp_password,
            created_by=current_user.id
        )
        
        # Send welcome email if requested
        if user_request.send_welcome_email:
            background_tasks.add_task(
                send_welcome_email,
                user.id,
                temp_password,
                db
            )
        
        # Log user creation
        await user_service.log_action(
            action=ActionType.CREATE,
            resource_type="user",
            resource_id=user.id,
            user_id=current_user.id,
            details={
                "user_email": user.email,
                "role": user.role.value,
                "department": user.department
            }
        )
        
        return UserResponse(
            id=user.id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            full_name=f"{user.first_name} {user.last_name}",
            department=user.department,
            role=user.role,
            phone_number=user.phone_number,
            job_title=user.job_title,
            manager_email=manager.email if manager else None,
            is_active=user.is_active,
            last_login_at=user.last_login_at,
            created_at=user.created_at,
            updated_at=user.updated_at,
            profile_completion=calculate_profile_completion(user),
            risk_score=0.0
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user"
        )


@router.get("", response_model=List[UserResponse])
async def get_users(
    department: Optional[str] = Query(None, description="Filter by department"),
    role: Optional[Role] = Query(None, description="Filter by role"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    search: Optional[str] = Query(None, description="Search by name or email"),
    sort_by: str = Query("created_at", description="Sort field"),
    sort_order: str = Query("desc", description="Sort order (asc/desc)"),
    skip: int = Query(0, ge=0, description="Number of users to skip"),
    limit: int = Query(100, ge=1, le=100, description="Number of users to return"),
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Get users with optional filtering and sorting.
    
    Args:
        department: Optional department filter
        role: Optional role filter
        is_active: Optional active status filter
        search: Optional search term
        sort_by: Sort field
        sort_order: Sort order
        skip: Number of users to skip
        limit: Number of users to return
        current_user: Current authenticated admin user
        db: Database session
        
    Returns:
        List of users
    """
    try:
        user_service = UserService(db)
        
        # Get users with filters
        users = await user_service.get_users(
            department=department,
            role=role,
            is_active=is_active,
            search=search,
            sort_by=sort_by,
            sort_order=sort_order,
            skip=skip,
            limit=limit
        )
        
        result = []
        for user in users:
            # Get user risk score
            risk_score = await user_service.calculate_user_risk_score(user.id)
            
            # Get manager email if exists
            manager_email = None
            if user.manager_id:
                manager = await user_service.get_user_by_id(user.manager_id)
                manager_email = manager.email if manager else None
            
            result.append(UserResponse(
                id=user.id,
                email=user.email,
                first_name=user.first_name,
                last_name=user.last_name,
                full_name=f"{user.first_name} {user.last_name}",
                department=user.department,
                role=user.role,
                phone_number=user.phone_number,
                job_title=user.job_title,
                manager_email=manager_email,
                is_active=user.is_active,
                last_login_at=user.last_login_at,
                created_at=user.created_at,
                updated_at=user.updated_at,
                profile_completion=calculate_profile_completion(user),
                risk_score=risk_score
            ))
        
        return result
        
    except Exception as e:
        logger.error(f"Error getting users: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get users"
        )


@router.get("/me", response_model=UserDetailResponse)
async def get_current_user_profile(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get current user's profile with detailed information.
    
    Args:
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        Current user's detailed profile
    """
    try:
        user_service = UserService(db)
        
        # Get detailed user information
        user_details = await user_service.get_user_details(current_user.id)
        
        return UserDetailResponse(**user_details)
        
    except Exception as e:
        logger.error(f"Error getting current user profile: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get user profile"
        )


@router.get("/{user_id}", response_model=UserDetailResponse)
async def get_user(
    user_id: uuid.UUID,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Get a specific user's detailed information.
    
    Args:
        user_id: User ID
        current_user: Current authenticated admin user
        db: Database session
        
    Returns:
        User's detailed information
    """
    try:
        user_service = UserService(db)
        
        # Get user
        user = await user_service.get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Get detailed user information
        user_details = await user_service.get_user_details(user_id)
        
        return UserDetailResponse(**user_details)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get user"
        )


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: uuid.UUID,
    user_update: UserUpdateRequest,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Update a user's information.
    
    Args:
        user_id: User ID
        user_update: User update data
        current_user: Current authenticated admin user
        db: Database session
        
    Returns:
        Updated user data
    """
    try:
        user_service = UserService(db)
        
        # Get user
        user = await user_service.get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Validate manager if provided
        manager = None
        if user_update.manager_email:
            manager = await user_service.get_user_by_email(user_update.manager_email)
            if not manager:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Manager not found"
                )
        
        # Update user
        updated_user = await user_service.update_user(
            user_id=user_id,
            first_name=user_update.first_name,
            last_name=user_update.last_name,
            department=user_update.department,
            role=user_update.role,
            phone_number=user_update.phone_number,
            job_title=user_update.job_title,
            manager_id=manager.id if manager else None,
            is_active=user_update.is_active,
            updated_by=current_user.id
        )
        
        # Log user update
        await user_service.log_action(
            action=ActionType.UPDATE,
            resource_type="user",
            resource_id=user_id,
            user_id=current_user.id,
            details={
                "updated_fields": [k for k, v in user_update.dict(exclude_unset=True).items() if v is not None],
                "user_email": updated_user.email
            }
        )
        
        return UserResponse(
            id=updated_user.id,
            email=updated_user.email,
            first_name=updated_user.first_name,
            last_name=updated_user.last_name,
            full_name=f"{updated_user.first_name} {updated_user.last_name}",
            department=updated_user.department,
            role=updated_user.role,
            phone_number=updated_user.phone_number,
            job_title=updated_user.job_title,
            manager_email=manager.email if manager else None,
            is_active=updated_user.is_active,
            last_login_at=updated_user.last_login_at,
            created_at=updated_user.created_at,
            updated_at=updated_user.updated_at,
            profile_completion=calculate_profile_completion(updated_user),
            risk_score=await user_service.calculate_user_risk_score(user_id)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user"
        )


@router.delete("/{user_id}")
async def delete_user(
    user_id: uuid.UUID,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Delete a user account (soft delete).
    
    Args:
        user_id: User ID
        current_user: Current authenticated admin user
        db: Database session
        
    Returns:
        Deletion confirmation
    """
    try:
        user_service = UserService(db)
        
        # Get user
        user = await user_service.get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Prevent self-deletion
        if user_id == current_user.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete your own account"
            )
        
        # Soft delete user
        await user_service.delete_user(user_id, deleted_by=current_user.id)
        
        # Log user deletion
        await user_service.log_action(
            action=ActionType.DELETE,
            resource_type="user",
            resource_id=user_id,
            user_id=current_user.id,
            details={"user_email": user.email}
        )
        
        return {"message": "User deleted successfully", "user_id": user_id}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user"
        )


@router.put("/me/password")
async def update_current_user_password(
    password_update: UserPasswordUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update current user's password.
    
    Args:
        password_update: Password update data
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        Password update confirmation
    """
    try:
        user_service = UserService(db)
        
        # Verify current password
        if not verify_password(password_update.current_password, current_user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )
        
        # Update password
        await user_service.update_user_password(
            user_id=current_user.id,
            new_password=password_update.new_password,
            updated_by=current_user.id
        )
        
        # Log password change
        await user_service.log_action(
            action=ActionType.UPDATE,
            resource_type="user_password",
            resource_id=current_user.id,
            user_id=current_user.id,
            details={"action": "password_changed"}
        )
        
        return {"message": "Password updated successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating user password: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update password"
        )


@router.put("/me/security-settings")
async def update_current_user_security_settings(
    security_settings: UserSecuritySettingsRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update current user's security settings.
    
    Args:
        security_settings: Security settings data
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        Security settings update confirmation
    """
    try:
        user_service = UserService(db)
        
        # Update security settings
        await user_service.update_user_security_settings(
            user_id=current_user.id,
            **security_settings.dict(exclude_unset=True)
        )
        
        # Log security settings change
        await user_service.log_action(
            action=ActionType.UPDATE,
            resource_type="user_security_settings",
            resource_id=current_user.id,
            user_id=current_user.id,
            details={
                "updated_settings": list(security_settings.dict(exclude_unset=True).keys())
            }
        )
        
        return {"message": "Security settings updated successfully"}
        
    except Exception as e:
        logger.error(f"Error updating user security settings: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update security settings"
        )


@router.put("/me/settings")
async def update_current_user_settings(
    user_settings: UserSettingsRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update current user's preferences and settings.
    
    Args:
        user_settings: User settings data
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        Settings update confirmation
    """
    try:
        user_service = UserService(db)
        
        # Update user settings
        await user_service.update_user_settings(
            user_id=current_user.id,
            **user_settings.dict(exclude_unset=True)
        )
        
        return {"message": "User settings updated successfully"}
        
    except Exception as e:
        logger.error(f"Error updating user settings: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user settings"
        )


@router.post("/bulk-operations")
async def bulk_user_operations(
    operation_request: BulkUserOperationRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Perform bulk operations on multiple users.
    
    Args:
        operation_request: Bulk operation data
        background_tasks: Background task handler
        current_user: Current authenticated admin user
        db: Database session
        
    Returns:
        Bulk operation status
    """
    try:
        user_service = UserService(db)
        
        # Validate users exist
        users = await user_service.get_users_by_ids(operation_request.user_ids)
        if len(users) != len(operation_request.user_ids):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Some users not found"
            )
        
        # Perform bulk operation
        if operation_request.operation == "activate":
            result = await user_service.bulk_activate_users(
                user_ids=operation_request.user_ids,
                updated_by=current_user.id
            )
        elif operation_request.operation == "deactivate":
            result = await user_service.bulk_deactivate_users(
                user_ids=operation_request.user_ids,
                updated_by=current_user.id
            )
        elif operation_request.operation == "assign_role":
            if not operation_request.parameters or "role" not in operation_request.parameters:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Role parameter required for role assignment"
                )
            result = await user_service.bulk_assign_role(
                user_ids=operation_request.user_ids,
                role=Role(operation_request.parameters["role"]),
                updated_by=current_user.id
            )
        elif operation_request.operation == "update_department":
            if not operation_request.parameters or "department" not in operation_request.parameters:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Department parameter required for department update"
                )
            result = await user_service.bulk_update_department(
                user_ids=operation_request.user_ids,
                department=operation_request.parameters["department"],
                updated_by=current_user.id
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid bulk operation"
            )
        
        # Log bulk operation
        await user_service.log_action(
            action=ActionType.UPDATE,
            resource_type="bulk_user_operation",
            resource_id=None,
            user_id=current_user.id,
            details={
                "operation": operation_request.operation,
                "user_count": len(operation_request.user_ids),
                "parameters": operation_request.parameters
            }
        )
        
        return {
            "message": f"Bulk operation '{operation_request.operation}' completed",
            "users_affected": result.get("users_affected", 0),
            "operation": operation_request.operation
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error performing bulk user operation: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to perform bulk operation"
        )


@router.get("/stats/overview", response_model=UserStatsResponse)
async def get_user_statistics(
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Get user statistics and overview.
    
    Args:
        current_user: Current authenticated admin user
        db: Database session
        
    Returns:
        User statistics
    """
    try:
        user_service = UserService(db)
        
        # Get user statistics
        stats = await user_service.get_user_statistics()
        
        return UserStatsResponse(**stats)
        
    except Exception as e:
        logger.error(f"Error getting user statistics: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get user statistics"
        )


@router.post("/{user_id}/reset-password")
async def reset_user_password(
    user_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Reset a user's password (admin only).
    
    Args:
        user_id: User ID
        background_tasks: Background task handler
        current_user: Current authenticated admin user
        db: Database session
        
    Returns:
        Password reset confirmation
    """
    try:
        user_service = UserService(db)
        
        # Get user
        user = await user_service.get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Generate temporary password
        temp_password = generate_temporary_password()
        
        # Reset password
        await user_service.reset_user_password(
            user_id=user_id,
            temporary_password=temp_password,
            reset_by=current_user.id
        )
        
        # Send password reset email
        background_tasks.add_task(
            send_password_reset_email,
            user_id,
            temp_password,
            db
        )
        
        # Log password reset
        await user_service.log_action(
            action=ActionType.UPDATE,
            resource_type="user_password",
            resource_id=user_id,
            user_id=current_user.id,
            details={
                "action": "password_reset",
                "user_email": user.email
            }
        )
        
        return {
            "message": "Password reset successfully",
            "user_id": user_id,
            "temporary_password_sent": True
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resetting user password: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reset password"
        )


# Helper functions
def calculate_profile_completion(user: User) -> float:
    """Calculate user profile completion percentage."""
    total_fields = 8
    completed_fields = 0
    
    if user.first_name:
        completed_fields += 1
    if user.last_name:
        completed_fields += 1
    if user.email:
        completed_fields += 1
    if user.department:
        completed_fields += 1
    if user.phone_number:
        completed_fields += 1
    if user.job_title:
        completed_fields += 1
    if user.manager_id:
        completed_fields += 1
    if user.password_hash:  # Has set password
        completed_fields += 1
    
    return (completed_fields / total_fields) * 100


# Background task functions
async def send_welcome_email(user_id: uuid.UUID, temporary_password: str, db: Session):
    """Background task to send welcome email to new user."""
    try:
        # In a real implementation, you would send an actual email
        logger.info(f"Welcome email sent to user {user_id} with temporary password")
    except Exception as e:
        logger.error(f"Error sending welcome email to user {user_id}: {str(e)}")


async def send_password_reset_email(user_id: uuid.UUID, temporary_password: str, db: Session):
    """Background task to send password reset email."""
    try:
        # In a real implementation, you would send an actual email
        logger.info(f"Password reset email sent to user {user_id}")
    except Exception as e:
        logger.error(f"Error sending password reset email to user {user_id}: {str(e)}")
