"""
User Service for PhishGuard

Business logic for user management, authentication, profile management,
risk scoring, and user-related operations.
"""

from sqlalchemy.orm import Session
from sqlalchemy import desc, and_, or_, func
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
import uuid
import hashlib
import secrets
import string

from ..models.user import User, Role, UserSettings, UserSecuritySettings
from ..models.audit_log import AuditLog, ActionType
from ..models.simulation import SimulationParticipant, ParticipantStatus
from ..models.quarantine import QuarantinedEmail
from ..utils.security import hash_password, verify_password
from ..utils.logger import get_logger
from ..utils.event_bus import EventBus

logger = get_logger(__name__)

class UserService:
    """Service for managing users and user-related operations."""
    
    def __init__(self, db: Session):
        """
        Initialize user service.
        
        Args:
            db: Database session
        """
        self.db = db
        self.event_bus = EventBus()
    
    async def create_user(
        self,
        email: str,
        first_name: str,
        last_name: str,
        department: Optional[str] = None,
        role: Role = Role.USER,
        phone_number: Optional[str] = None,
        job_title: Optional[str] = None,
        manager_id: Optional[uuid.UUID] = None,
        temporary_password: Optional[str] = None,
        created_by: Optional[uuid.UUID] = None
    ) -> User:
        """
        Create a new user.
        
        Args:
            email: User email address
            first_name: User first name
            last_name: User last name
            department: User department
            role: User role
            phone_number: User phone number
            job_title: User job title
            manager_id: Manager user ID
            temporary_password: Temporary password
            created_by: User who created this user
            
        Returns:
            Created user
        """
        try:
            # Generate password if not provided
            if not temporary_password:
                temporary_password = self._generate_temporary_password()
            
            # Create user
            user = User(
                id=uuid.uuid4(),
                email=email.lower(),
                first_name=first_name,
                last_name=last_name,
                department=department,
                role=role,
                phone_number=phone_number,
                job_title=job_title,
                manager_id=manager_id,
                password_hash=hash_password(temporary_password),
                is_active=True,
                requires_password_change=True,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            
            self.db.add(user)
            self.db.commit()
            self.db.refresh(user)
            
            # Create default user settings
            await self._create_default_user_settings(user.id)
            
            # Log user creation
            await self._log_user_action(
                action=ActionType.CREATE,
                user_id=user.id,
                performed_by=created_by,
                details={
                    "email": email,
                    "role": role.value,
                    "department": department
                }
            )
            
            # Emit user created event
            await self.event_bus.emit("user_created", {
                "user_id": str(user.id),
                "email": email,
                "role": role.value,
                "temporary_password": temporary_password
            })
            
            logger.info(f"User created successfully: {email}")
            return user
            
        except Exception as e:
            logger.error(f"Error creating user: {str(e)}")
            self.db.rollback()
            raise
    
    async def get_user_by_id(self, user_id: uuid.UUID) -> Optional[User]:
        """Get user by ID."""
        try:
            return self.db.query(User).filter(User.id == user_id).first()
        except Exception as e:
            logger.error(f"Error getting user by ID: {str(e)}")
            raise
    
    async def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        try:
            return self.db.query(User).filter(User.email == email.lower()).first()
        except Exception as e:
            logger.error(f"Error getting user by email: {str(e)}")
            raise
    
    async def get_users(
        self,
        department: Optional[str] = None,
        role: Optional[Role] = None,
        is_active: Optional[bool] = None,
        search: Optional[str] = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
        skip: int = 0,
        limit: int = 100
    ) -> List[User]:
        """
        Get users with filtering and sorting.
        
        Args:
            department: Filter by department
            role: Filter by role
            is_active: Filter by active status
            search: Search by name or email
            sort_by: Sort field
            sort_order: Sort order (asc/desc)
            skip: Number of users to skip
            limit: Number of users to return
            
        Returns:
            List of users
        """
        try:
            query = self.db.query(User)
            
            # Apply filters
            if department:
                query = query.filter(User.department == department)
            
            if role:
                query = query.filter(User.role == role)
            
            if is_active is not None:
                query = query.filter(User.is_active == is_active)
            
            if search:
                search_pattern = f"%{search}%"
                query = query.filter(
                    or_(
                        User.first_name.ilike(search_pattern),
                        User.last_name.ilike(search_pattern),
                        User.email.ilike(search_pattern)
                    )
                )
            
            # Apply sorting
            if sort_order.lower() == "desc":
                order_clause = desc(getattr(User, sort_by))
            else:
                order_clause = getattr(User, sort_by)
            
            query = query.order_by(order_clause)
            
            # Apply pagination
            users = query.offset(skip).limit(limit).all()
            
            return users
            
        except Exception as e:
            logger.error(f"Error getting users: {str(e)}")
            raise
    
    async def update_user(
        self,
        user_id: uuid.UUID,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        department: Optional[str] = None,
        role: Optional[Role] = None,
        phone_number: Optional[str] = None,
        job_title: Optional[str] = None,
        manager_id: Optional[uuid.UUID] = None,
        is_active: Optional[bool] = None,
        updated_by: Optional[uuid.UUID] = None
    ) -> User:
        """
        Update user information.
        
        Args:
            user_id: User ID to update
            first_name: New first name
            last_name: New last name
            department: New department
            role: New role
            phone_number: New phone number
            job_title: New job title
            manager_id: New manager ID
            is_active: New active status
            updated_by: User performing the update
            
        Returns:
            Updated user
        """
        try:
            # Get user
            user = await self.get_user_by_id(user_id)
            if not user:
                raise ValueError("User not found")
            
            # Store original values for audit
            original_values = {
                "first_name": user.first_name,
                "last_name": user.last_name,
                "department": user.department,
                "role": user.role.value if user.role else None,
                "phone_number": user.phone_number,
                "job_title": user.job_title,
                "manager_id": str(user.manager_id) if user.manager_id else None,
                "is_active": user.is_active
            }
            
            # Update fields
            if first_name is not None:
                user.first_name = first_name
            if last_name is not None:
                user.last_name = last_name
            if department is not None:
                user.department = department
            if role is not None:
                user.role = role
            if phone_number is not None:
                user.phone_number = phone_number
            if job_title is not None:
                user.job_title = job_title
            if manager_id is not None:
                user.manager_id = manager_id
            if is_active is not None:
                user.is_active = is_active
            
            user.updated_at = datetime.utcnow()
            
            self.db.commit()
            self.db.refresh(user)
            
            # Log user update
            updated_values = {
                "first_name": user.first_name,
                "last_name": user.last_name,
                "department": user.department,
                "role": user.role.value if user.role else None,
                "phone_number": user.phone_number,
                "job_title": user.job_title,
                "manager_id": str(user.manager_id) if user.manager_id else None,
                "is_active": user.is_active
            }
            
            await self._log_user_action(
                action=ActionType.UPDATE,
                user_id=user_id,
                performed_by=updated_by,
                details={
                    "original_values": original_values,
                    "updated_values": updated_values
                }
            )
            
            # Emit user updated event
            await self.event_bus.emit("user_updated", {
                "user_id": str(user_id),
                "updated_by": str(updated_by) if updated_by else None,
                "changes": {k: v for k, v in updated_values.items() if v != original_values.get(k)}
            })
            
            logger.info(f"User updated successfully: {user.email}")
            return user
            
        except Exception as e:
            logger.error(f"Error updating user: {str(e)}")
            self.db.rollback()
            raise
    
    async def delete_user(
        self,
        user_id: uuid.UUID,
        deleted_by: Optional[uuid.UUID] = None
    ) -> bool:
        """
        Soft delete a user.
        
        Args:
            user_id: User ID to delete
            deleted_by: User performing the deletion
            
        Returns:
            True if successful
        """
        try:
            # Get user
            user = await self.get_user_by_id(user_id)
            if not user:
                raise ValueError("User not found")
            
            # Soft delete (deactivate)
            user.is_active = False
            user.deleted_at = datetime.utcnow()
            user.updated_at = datetime.utcnow()
            
            self.db.commit()
            
            # Log user deletion
            await self._log_user_action(
                action=ActionType.DELETE,
                user_id=user_id,
                performed_by=deleted_by,
                details={"email": user.email}
            )
            
            # Emit user deleted event
            await self.event_bus.emit("user_deleted", {
                "user_id": str(user_id),
                "email": user.email,
                "deleted_by": str(deleted_by) if deleted_by else None
            })
            
            logger.info(f"User deleted successfully: {user.email}")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting user: {str(e)}")
            self.db.rollback()
            raise
    
    async def update_user_password(
        self,
        user_id: uuid.UUID,
        new_password: str,
        updated_by: Optional[uuid.UUID] = None
    ) -> bool:
        """
        Update user password.
        
        Args:
            user_id: User ID
            new_password: New password
            updated_by: User performing the update
            
        Returns:
            True if successful
        """
        try:
            # Get user
            user = await self.get_user_by_id(user_id)
            if not user:
                raise ValueError("User not found")
            
            # Update password
            user.password_hash = hash_password(new_password)
            user.requires_password_change = False
            user.password_changed_at = datetime.utcnow()
            user.updated_at = datetime.utcnow()
            
            self.db.commit()
            
            # Log password change
            await self._log_user_action(
                action=ActionType.UPDATE,
                user_id=user_id,
                performed_by=updated_by,
                details={"action": "password_changed"}
            )
            
            logger.info(f"Password updated for user: {user.email}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating user password: {str(e)}")
            self.db.rollback()
            raise
    
    async def reset_user_password(
        self,
        user_id: uuid.UUID,
        temporary_password: str,
        reset_by: Optional[uuid.UUID] = None
    ) -> bool:
        """
        Reset user password to temporary password.
        
        Args:
            user_id: User ID
            temporary_password: Temporary password
            reset_by: User performing the reset
            
        Returns:
            True if successful
        """
        try:
            # Get user
            user = await self.get_user_by_id(user_id)
            if not user:
                raise ValueError("User not found")
            
            # Reset password
            user.password_hash = hash_password(temporary_password)
            user.requires_password_change = True
            user.password_changed_at = datetime.utcnow()
            user.updated_at = datetime.utcnow()
            
            self.db.commit()
            
            # Log password reset
            await self._log_user_action(
                action=ActionType.UPDATE,
                user_id=user_id,
                performed_by=reset_by,
                details={"action": "password_reset"}
            )
            
            # Emit password reset event
            await self.event_bus.emit("user_password_reset", {
                "user_id": str(user_id),
                "email": user.email,
                "temporary_password": temporary_password,
                "reset_by": str(reset_by) if reset_by else None
            })
            
            logger.info(f"Password reset for user: {user.email}")
            return True
            
        except Exception as e:
            logger.error(f"Error resetting user password: {str(e)}")
            self.db.rollback()
            raise
    
    async def get_user_details(self, user_id: uuid.UUID) -> Dict[str, Any]:
        """
        Get detailed user information including settings and statistics.
        
        Args:
            user_id: User ID
            
        Returns:
            Detailed user information
        """
        try:
            # Get user
            user = await self.get_user_by_id(user_id)
            if not user:
                raise ValueError("User not found")
            
            # Get user settings
            user_settings = self.db.query(UserSettings).filter(
                UserSettings.user_id == user_id
            ).first()
            
            security_settings = self.db.query(UserSecuritySettings).filter(
                UserSecuritySettings.user_id == user_id
            ).first()
            
            # Get simulation statistics
            simulation_stats = await self._get_user_simulation_stats(user_id)
            
            # Get recent login history
            login_history = await self._get_user_login_history(user_id, limit=10)
            
            # Get recent activities
            recent_activities = await self._get_user_recent_activities(user_id, limit=20)
            
            # Calculate risk score
            risk_score = await self.calculate_user_risk_score(user_id)
            
            # Get manager info
            manager_email = None
            if user.manager_id:
                manager = await self.get_user_by_id(user.manager_id)
                manager_email = manager.email if manager else None
            
            return {
                "id": user.id,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "full_name": f"{user.first_name} {user.last_name}",
                "department": user.department,
                "role": user.role,
                "phone_number": user.phone_number,
                "job_title": user.job_title,
                "manager_email": manager_email,
                "is_active": user.is_active,
                "last_login_at": user.last_login_at,
                "created_at": user.created_at,
                "updated_at": user.updated_at,
                "profile_completion": self._calculate_profile_completion(user),
                "risk_score": risk_score,
                "security_settings": {
                    "mfa_enabled": security_settings.mfa_enabled if security_settings else False,
                    "login_notifications": security_settings.login_notifications if security_settings else True,
                    "security_alerts": security_settings.security_alerts if security_settings else True,
                    "session_timeout": security_settings.session_timeout if security_settings else 60,
                    "allowed_ip_ranges": security_settings.allowed_ip_ranges if security_settings else []
                },
                "notification_settings": {
                    "email_notifications": user_settings.email_notifications if user_settings else True,
                    "sms_notifications": user_settings.sms_notifications if user_settings else False,
                    "notification_frequency": user_settings.notification_frequency if user_settings else "immediate",
                    "language": user_settings.language if user_settings else "en",
                    "timezone": user_settings.timezone if user_settings else "UTC"
                },
                "login_history": login_history,
                "simulation_stats": simulation_stats,
                "training_progress": {
                    "completed_courses": 0,  # Would be calculated from training system
                    "total_courses": 0,
                    "completion_rate": 0.0,
                    "last_training_date": None
                },
                "recent_activities": recent_activities
            }
            
        except Exception as e:
            logger.error(f"Error getting user details: {str(e)}")
            raise
    
    async def calculate_user_risk_score(self, user_id: uuid.UUID) -> float:
        """
        Calculate user risk score based on simulation performance and other factors.
        
        Args:
            user_id: User ID
            
        Returns:
            Risk score (0.0 to 10.0, where 10.0 is highest risk)
        """
        try:
            # Base risk score
            risk_score = 5.0
            
            # Get simulation participation data
            simulation_participants = self.db.query(SimulationParticipant).filter(
                SimulationParticipant.user_email == (
                    self.db.query(User.email).filter(User.id == user_id).scalar()
                )
            ).all()
            
            if simulation_participants:
                # Calculate click rate (higher = more risky)
                total_simulations = len(simulation_participants)
                clicked_simulations = len([
                    p for p in simulation_participants 
                    if p.link_clicked_at is not None
                ])
                reported_simulations = len([
                    p for p in simulation_participants 
                    if p.reported_at is not None
                ])
                
                click_rate = clicked_simulations / total_simulations if total_simulations > 0 else 0
                report_rate = reported_simulations / total_simulations if total_simulations > 0 else 0
                
                # Adjust risk based on behavior
                risk_score += (click_rate * 3.0)  # Add up to 3 points for high click rate
                risk_score -= (report_rate * 2.0)  # Subtract up to 2 points for high report rate
                
                # Recent behavior matters more
                recent_simulations = [
                    p for p in simulation_participants 
                    if p.email_sent_at and p.email_sent_at > datetime.utcnow() - timedelta(days=90)
                ]
                
                if recent_simulations:
                    recent_clicked = len([
                        p for p in recent_simulations 
                        if p.link_clicked_at is not None
                    ])
                    recent_click_rate = recent_clicked / len(recent_simulations)
                    risk_score += (recent_click_rate * 2.0)  # Additional weight for recent behavior
            
            # Factor in training completion (if available)
            # This would integrate with a training system
            
            # Factor in department risk (some departments may be higher risk)
            user = await self.get_user_by_id(user_id)
            if user and user.department:
                high_risk_departments = ["finance", "accounting", "executive", "hr"]
                if user.department.lower() in high_risk_departments:
                    risk_score += 1.0
            
            # Ensure score is within bounds
            risk_score = max(0.0, min(10.0, risk_score))
            
            return round(risk_score, 2)
            
        except Exception as e:
            logger.error(f"Error calculating user risk score: {str(e)}")
            return 5.0  # Default medium risk
    
    async def get_user_statistics(self) -> Dict[str, Any]:
        """
        Get overall user statistics.
        
        Returns:
            User statistics
        """
        try:
            # Basic counts
            total_users = self.db.query(User).count()
            active_users = self.db.query(User).filter(User.is_active == True).count()
            inactive_users = total_users - active_users
            
            # Users by role
            role_stats = self.db.query(
                User.role,
                func.count(User.id)
            ).group_by(User.role).all()
            
            users_by_role = {role.value: count for role, count in role_stats}
            
            # Users by department
            dept_stats = self.db.query(
                User.department,
                func.count(User.id)
            ).filter(
                User.department.isnot(None)
            ).group_by(User.department).all()
            
            users_by_department = {dept: count for dept, count in dept_stats}
            
            # Recent registrations (last 30 days)
            thirty_days_ago = datetime.utcnow() - timedelta(days=30)
            recent_registrations = self.db.query(User).filter(
                User.created_at >= thirty_days_ago
            ).count()
            
            # Calculate average risk score
            # This would need to be calculated for all users, but for performance
            # we'll estimate based on simulation data
            avg_risk_score = 5.0  # Default medium risk
            
            # MFA adoption rate
            mfa_enabled_count = self.db.query(UserSecuritySettings).filter(
                UserSecuritySettings.mfa_enabled == True
            ).count()
            mfa_adoption_rate = (mfa_enabled_count / total_users * 100) if total_users > 0 else 0
            
            return {
                "total_users": total_users,
                "active_users": active_users,
                "inactive_users": inactive_users,
                "users_by_role": users_by_role,
                "users_by_department": users_by_department,
                "recent_registrations": recent_registrations,
                "average_risk_score": avg_risk_score,
                "mfa_adoption_rate": round(mfa_adoption_rate, 2)
            }
            
        except Exception as e:
            logger.error(f"Error getting user statistics: {str(e)}")
            raise
    
    async def bulk_activate_users(
        self,
        user_ids: List[uuid.UUID],
        updated_by: Optional[uuid.UUID] = None
    ) -> Dict[str, Any]:
        """Bulk activate users."""
        try:
            users = self.db.query(User).filter(User.id.in_(user_ids)).all()
            
            for user in users:
                user.is_active = True
                user.updated_at = datetime.utcnow()
            
            self.db.commit()
            
            # Log bulk operation
            await self._log_user_action(
                action=ActionType.UPDATE,
                user_id=None,
                performed_by=updated_by,
                details={
                    "action": "bulk_activate",
                    "user_count": len(users),
                    "user_ids": [str(uid) for uid in user_ids]
                }
            )
            
            return {"users_affected": len(users)}
            
        except Exception as e:
            logger.error(f"Error in bulk activate users: {str(e)}")
            self.db.rollback()
            raise
    
    async def bulk_deactivate_users(
        self,
        user_ids: List[uuid.UUID],
        updated_by: Optional[uuid.UUID] = None
    ) -> Dict[str, Any]:
        """Bulk deactivate users."""
        try:
            users = self.db.query(User).filter(User.id.in_(user_ids)).all()
            
            for user in users:
                user.is_active = False
                user.updated_at = datetime.utcnow()
            
            self.db.commit()
            
            # Log bulk operation
            await self._log_user_action(
                action=ActionType.UPDATE,
                user_id=None,
                performed_by=updated_by,
                details={
                    "action": "bulk_deactivate",
                    "user_count": len(users),
                    "user_ids": [str(uid) for uid in user_ids]
                }
            )
            
            return {"users_affected": len(users)}
            
        except Exception as e:
            logger.error(f"Error in bulk deactivate users: {str(e)}")
            self.db.rollback()
            raise
    
    async def bulk_assign_role(
        self,
        user_ids: List[uuid.UUID],
        role: Role,
        updated_by: Optional[uuid.UUID] = None
    ) -> Dict[str, Any]:
        """Bulk assign role to users."""
        try:
            users = self.db.query(User).filter(User.id.in_(user_ids)).all()
            
            for user in users:
                user.role = role
                user.updated_at = datetime.utcnow()
            
            self.db.commit()
            
            # Log bulk operation
            await self._log_user_action(
                action=ActionType.UPDATE,
                user_id=None,
                performed_by=updated_by,
                details={
                    "action": "bulk_assign_role",
                    "role": role.value,
                    "user_count": len(users),
                    "user_ids": [str(uid) for uid in user_ids]
                }
            )
            
            return {"users_affected": len(users)}
            
        except Exception as e:
            logger.error(f"Error in bulk assign role: {str(e)}")
            self.db.rollback()
            raise
    
    async def bulk_update_department(
        self,
        user_ids: List[uuid.UUID],
        department: str,
        updated_by: Optional[uuid.UUID] = None
    ) -> Dict[str, Any]:
        """Bulk update department for users."""
        try:
            users = self.db.query(User).filter(User.id.in_(user_ids)).all()
            
            for user in users:
                user.department = department
                user.updated_at = datetime.utcnow()
            
            self.db.commit()
            
            # Log bulk operation
            await self._log_user_action(
                action=ActionType.UPDATE,
                user_id=None,
                performed_by=updated_by,
                details={
                    "action": "bulk_update_department",
                    "department": department,
                    "user_count": len(users),
                    "user_ids": [str(uid) for uid in user_ids]
                }
            )
            
            return {"users_affected": len(users)}
            
        except Exception as e:
            logger.error(f"Error in bulk update department: {str(e)}")
            self.db.rollback()
            raise
    
    async def get_users_by_ids(self, user_ids: List[uuid.UUID]) -> List[User]:
        """Get multiple users by their IDs."""
        try:
            return self.db.query(User).filter(User.id.in_(user_ids)).all()
        except Exception as e:
            logger.error(f"Error getting users by IDs: {str(e)}")
            raise
    
    async def update_user_security_settings(
        self,
        user_id: uuid.UUID,
        **settings
    ) -> bool:
        """Update user security settings."""
        try:
            # Get or create security settings
            security_settings = self.db.query(UserSecuritySettings).filter(
                UserSecuritySettings.user_id == user_id
            ).first()
            
            if not security_settings:
                security_settings = UserSecuritySettings(
                    id=uuid.uuid4(),
                    user_id=user_id
                )
                self.db.add(security_settings)
            
            # Update settings
            for key, value in settings.items():
                if hasattr(security_settings, key):
                    setattr(security_settings, key, value)
            
            security_settings.updated_at = datetime.utcnow()
            self.db.commit()
            
            return True
            
        except Exception as e:
            logger.error(f"Error updating user security settings: {str(e)}")
            self.db.rollback()
            raise
    
    async def update_user_settings(
        self,
        user_id: uuid.UUID,
        **settings
    ) -> bool:
        """Update user preferences and settings."""
        try:
            # Get or create user settings
            user_settings = self.db.query(UserSettings).filter(
                UserSettings.user_id == user_id
            ).first()
            
            if not user_settings:
                user_settings = UserSettings(
                    id=uuid.uuid4(),
                    user_id=user_id
                )
                self.db.add(user_settings)
            
            # Update settings
            for key, value in settings.items():
                if hasattr(user_settings, key):
                    setattr(user_settings, key, value)
            
            user_settings.updated_at = datetime.utcnow()
            self.db.commit()
            
            return True
            
        except Exception as e:
            logger.error(f"Error updating user settings: {str(e)}")
            self.db.rollback()
            raise
    
    def _generate_temporary_password(self, length: int = 12) -> str:
        """Generate a secure temporary password."""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    async def _create_default_user_settings(self, user_id: uuid.UUID):
        """Create default settings for a new user."""
        try:
            # Create user settings
            user_settings = UserSettings(
                id=uuid.uuid4(),
                user_id=user_id,
                email_notifications=True,
                sms_notifications=False,
                notification_frequency="immediate",
                language="en",
                timezone="UTC"
            )
            
            # Create security settings
            security_settings = UserSecuritySettings(
                id=uuid.uuid4(),
                user_id=user_id,
                mfa_enabled=False,
                login_notifications=True,
                security_alerts=True,
                session_timeout=60
            )
            
            self.db.add(user_settings)
            self.db.add(security_settings)
            # Don't commit here, let the calling method handle it
            
        except Exception as e:
            logger.error(f"Error creating default user settings: {str(e)}")
            raise
    
    def _calculate_profile_completion(self, user: User) -> float:
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
        if user.password_hash:
            completed_fields += 1
        
        return (completed_fields / total_fields) * 100
    
    async def _get_user_simulation_stats(self, user_id: uuid.UUID) -> Dict[str, Any]:
        """Get user simulation statistics."""
        try:
            user = await self.get_user_by_id(user_id)
            if not user:
                return {}
            
            participants = self.db.query(SimulationParticipant).filter(
                SimulationParticipant.user_email == user.email
            ).all()
            
            if not participants:
                return {
                    "total_simulations": 0,
                    "emails_opened": 0,
                    "links_clicked": 0,
                    "data_entered": 0,
                    "reported_phishing": 0,
                    "click_rate": 0.0,
                    "report_rate": 0.0,
                    "average_response_time": 0,
                    "last_simulation_date": None
                }
            
            total_simulations = len(participants)
            emails_opened = len([p for p in participants if p.email_opened_at])
            links_clicked = len([p for p in participants if p.link_clicked_at])
            data_entered = len([p for p in participants if p.data_entered_at])
            reported_phishing = len([p for p in participants if p.reported_at])
            
            click_rate = (links_clicked / total_simulations * 100) if total_simulations > 0 else 0
            report_rate = (reported_phishing / total_simulations * 100) if total_simulations > 0 else 0
            
            # Calculate average response time
            response_times = [p.response_time for p in participants if p.response_time]
            avg_response_time = sum(response_times) // len(response_times) if response_times else 0
            
            # Get last simulation date
            last_simulation = max([p.email_sent_at for p in participants if p.email_sent_at], default=None)
            
            return {
                "total_simulations": total_simulations,
                "emails_opened": emails_opened,
                "links_clicked": links_clicked,
                "data_entered": data_entered,
                "reported_phishing": reported_phishing,
                "click_rate": round(click_rate, 2),
                "report_rate": round(report_rate, 2),
                "average_response_time": avg_response_time,
                "last_simulation_date": last_simulation.isoformat() if last_simulation else None
            }
            
        except Exception as e:
            logger.error(f"Error getting user simulation stats: {str(e)}")
            return {}
    
    async def _get_user_login_history(self, user_id: uuid.UUID, limit: int = 10) -> List[Dict[str, Any]]:
        """Get user login history."""
        try:
            # Get recent login audit logs
            login_logs = self.db.query(AuditLog).filter(
                and_(
                    AuditLog.user_id == user_id,
                    AuditLog.action == ActionType.LOGIN
                )
            ).order_by(desc(AuditLog.timestamp)).limit(limit).all()
            
            return [
                {
                    "timestamp": log.timestamp.isoformat(),
                    "ip_address": log.details.get("ip_address"),
                    "user_agent": log.details.get("user_agent"),
                    "success": log.details.get("success", True)
                }
                for log in login_logs
            ]
            
        except Exception as e:
            logger.error(f"Error getting user login history: {str(e)}")
            return []
    
    async def _get_user_recent_activities(self, user_id: uuid.UUID, limit: int = 20) -> List[Dict[str, Any]]:
        """Get user recent activities."""
        try:
            # Get recent audit logs for the user
            activity_logs = self.db.query(AuditLog).filter(
                AuditLog.user_id == user_id
            ).order_by(desc(AuditLog.timestamp)).limit(limit).all()
            
            return [
                {
                    "timestamp": log.timestamp.isoformat(),
                    "action": log.action.value,
                    "resource_type": log.resource_type,
                    "resource_id": str(log.resource_id) if log.resource_id else None,
                    "details": log.details
                }
                for log in activity_logs
            ]
            
        except Exception as e:
            logger.error(f"Error getting user recent activities: {str(e)}")
            return []
    
    async def _log_user_action(
        self,
        action: ActionType,
        user_id: Optional[uuid.UUID],
        performed_by: Optional[uuid.UUID],
        details: Dict[str, Any]
    ):
        """Log user-related actions."""
        try:
            audit_log = AuditLog(
                id=uuid.uuid4(),
                action=action,
                resource_type="user",
                resource_id=user_id,
                user_id=performed_by,
                details=details,
                timestamp=datetime.utcnow()
            )
            
            self.db.add(audit_log)
            # Note: Don't commit here, let the calling method handle it
            
        except Exception as e:
            logger.error(f"Error logging user action: {str(e)}")
    
    async def log_action(
        self,
        action: ActionType,
        resource_type: str,
        resource_id: Optional[uuid.UUID],
        user_id: Optional[uuid.UUID],
        details: Dict[str, Any]
    ):
        """Public method to log actions."""
        await self._log_user_action(action, resource_id, user_id, {**details, "resource_type": resource_type})
