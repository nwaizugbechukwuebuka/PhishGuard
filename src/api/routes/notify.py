"""
Notification Routes for PhishGuard API

Comprehensive notification management endpoints including creation,
delivery tracking, preferences, and analytics.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request, Query, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import desc, and_, or_
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, EmailStr, validator
import uuid

from ..database import get_db
from ..models.notification import Notification, NotificationTemplate, NotificationPreference
from ..models.notification import NotificationType, NotificationChannel, NotificationPriority, DeliveryStatus
from ..models.user import User
from ..middleware.auth_middleware import get_current_user, get_current_admin_user
from ..services.notification_service import NotificationService
from ..utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/notifications", tags=["notifications"])

# Pydantic models for request/response
class NotificationCreateRequest(BaseModel):
    type: NotificationType
    title: str
    message: str
    recipient_email: Optional[EmailStr] = None
    recipient_id: Optional[str] = None
    additional_recipients: Optional[List[str]] = None
    channel: NotificationChannel = NotificationChannel.EMAIL
    fallback_channels: Optional[List[NotificationChannel]] = None
    priority: NotificationPriority = NotificationPriority.NORMAL
    scheduled_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    template_id: Optional[str] = None
    template_variables: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None

class NotificationResponse(BaseModel):
    id: str
    type: str
    title: str
    message: str
    recipient_email: Optional[str]
    channel: str
    priority: str
    status: str
    created_at: str
    scheduled_at: Optional[str]
    sent_at: Optional[str]
    delivered_at: Optional[str]

class NotificationListResponse(BaseModel):
    notifications: List[NotificationResponse]
    total: int
    page: int
    page_size: int
    total_pages: int

class NotificationStatsResponse(BaseModel):
    total_sent: int
    total_delivered: int
    total_failed: int
    total_pending: int
    delivery_rate: float
    average_delivery_time: Optional[float]
    channel_stats: Dict[str, int]
    type_stats: Dict[str, int]

class NotificationPreferenceRequest(BaseModel):
    email_enabled: bool = True
    sms_enabled: bool = False
    slack_enabled: bool = False
    in_app_enabled: bool = True
    type_preferences: Optional[Dict[str, Dict[str, bool]]] = None
    quiet_hours_start: Optional[str] = None
    quiet_hours_end: Optional[str] = None
    timezone: str = "UTC"
    digest_frequency: str = "daily"
    max_emails_per_day: int = 10

class BulkNotificationRequest(BaseModel):
    type: NotificationType
    title: str
    message: str
    recipients: List[str]  # List of email addresses or user IDs
    channel: NotificationChannel = NotificationChannel.EMAIL
    priority: NotificationPriority = NotificationPriority.NORMAL
    template_id: Optional[str] = None
    template_variables: Optional[Dict[str, Any]] = None
    send_individually: bool = True


@router.post("/", response_model=NotificationResponse)
async def create_notification(
    request: NotificationCreateRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create a new notification.
    
    Args:
        request: Notification creation request
        background_tasks: Background task handler
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        Created notification details
        
    Raises:
        HTTPException: If creation fails
    """
    try:
        notification_service = NotificationService(db)
        
        # Validate recipient
        if not request.recipient_email and not request.recipient_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either recipient_email or recipient_id must be provided"
            )
        
        # Get recipient information
        recipient_email = request.recipient_email
        if request.recipient_id:
            recipient = db.query(User).filter(User.id == request.recipient_id).first()
            if not recipient:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Recipient user not found"
                )
            recipient_email = recipient.email
        
        # Create notification
        notification = await notification_service.create_notification(
            type=request.type,
            title=request.title,
            message=request.message,
            recipient_email=recipient_email,
            recipient_id=request.recipient_id,
            additional_recipients=request.additional_recipients,
            channel=request.channel,
            fallback_channels=request.fallback_channels,
            priority=request.priority,
            scheduled_at=request.scheduled_at,
            expires_at=request.expires_at,
            template_id=request.template_id,
            template_variables=request.template_variables,
            metadata=request.metadata,
            created_by=current_user.id
        )
        
        # Schedule delivery
        background_tasks.add_task(
            notification_service.schedule_delivery,
            notification.id
        )
        
        return NotificationResponse(**notification.to_dict())
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating notification: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create notification"
        )


@router.post("/bulk", response_model=Dict[str, Any])
async def create_bulk_notifications(
    request: BulkNotificationRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Create bulk notifications for multiple recipients.
    
    Args:
        request: Bulk notification request
        background_tasks: Background task handler
        current_user: Current authenticated admin user
        db: Database session
        
    Returns:
        Bulk creation results
        
    Raises:
        HTTPException: If bulk creation fails
    """
    try:
        notification_service = NotificationService(db)
        
        # Create notifications for all recipients
        created_notifications = []
        failed_recipients = []
        
        for recipient in request.recipients:
            try:
                # Determine if recipient is email or user ID
                recipient_email = recipient
                recipient_id = None
                
                if not "@" in recipient:  # Assume it's a user ID
                    user = db.query(User).filter(User.id == recipient).first()
                    if user:
                        recipient_email = user.email
                        recipient_id = recipient
                    else:
                        failed_recipients.append({"recipient": recipient, "error": "User not found"})
                        continue
                
                # Create individual notification
                notification = await notification_service.create_notification(
                    type=request.type,
                    title=request.title,
                    message=request.message,
                    recipient_email=recipient_email,
                    recipient_id=recipient_id,
                    channel=request.channel,
                    priority=request.priority,
                    template_id=request.template_id,
                    template_variables=request.template_variables,
                    created_by=current_user.id
                )
                
                created_notifications.append(str(notification.id))
                
                # Schedule delivery
                if request.send_individually:
                    background_tasks.add_task(
                        notification_service.schedule_delivery,
                        notification.id
                    )
                
            except Exception as e:
                failed_recipients.append({"recipient": recipient, "error": str(e)})
        
        # Schedule bulk delivery if not sending individually
        if not request.send_individually and created_notifications:
            background_tasks.add_task(
                notification_service.schedule_bulk_delivery,
                created_notifications
            )
        
        return {
            "created_count": len(created_notifications),
            "failed_count": len(failed_recipients),
            "created_notifications": created_notifications,
            "failed_recipients": failed_recipients
        }
        
    except Exception as e:
        logger.error(f"Error creating bulk notifications: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create bulk notifications"
        )


@router.get("/", response_model=NotificationListResponse)
async def list_notifications(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    type: Optional[NotificationType] = Query(None, description="Filter by notification type"),
    status: Optional[DeliveryStatus] = Query(None, description="Filter by delivery status"),
    channel: Optional[NotificationChannel] = Query(None, description="Filter by delivery channel"),
    priority: Optional[NotificationPriority] = Query(None, description="Filter by priority"),
    recipient_email: Optional[str] = Query(None, description="Filter by recipient email"),
    start_date: Optional[datetime] = Query(None, description="Filter notifications from this date"),
    end_date: Optional[datetime] = Query(None, description="Filter notifications until this date"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List notifications with filtering and pagination.
    
    Args:
        page: Page number
        page_size: Items per page
        type: Filter by notification type
        status: Filter by delivery status
        channel: Filter by delivery channel
        priority: Filter by priority
        recipient_email: Filter by recipient email
        start_date: Filter from date
        end_date: Filter until date
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        Paginated list of notifications
    """
    try:
        # Build query
        query = db.query(Notification).filter(Notification.is_deleted == False)
        
        # Apply filters
        if type:
            query = query.filter(Notification.type == type)
        if status:
            query = query.filter(Notification.status == status)
        if channel:
            query = query.filter(Notification.channel == channel)
        if priority:
            query = query.filter(Notification.priority == priority)
        if recipient_email:
            query = query.filter(Notification.recipient_email == recipient_email)
        if start_date:
            query = query.filter(Notification.created_at >= start_date)
        if end_date:
            query = query.filter(Notification.created_at <= end_date)
        
        # Non-admin users can only see their own notifications
        if not current_user.is_admin:
            query = query.filter(
                or_(
                    Notification.recipient_id == current_user.id,
                    Notification.recipient_email == current_user.email
                )
            )
        
        # Get total count
        total = query.count()
        
        # Apply pagination and ordering
        notifications = query.order_by(desc(Notification.created_at))\
                            .offset((page - 1) * page_size)\
                            .limit(page_size)\
                            .all()
        
        # Convert to response format
        notification_responses = [
            NotificationResponse(**notification.to_dict(include_content=False))
            for notification in notifications
        ]
        
        total_pages = (total + page_size - 1) // page_size
        
        return NotificationListResponse(
            notifications=notification_responses,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages
        )
        
    except Exception as e:
        logger.error(f"Error listing notifications: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list notifications"
        )


@router.get("/{notification_id}", response_model=NotificationResponse)
async def get_notification(
    notification_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get notification details by ID.
    
    Args:
        notification_id: Notification ID
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        Notification details
        
    Raises:
        HTTPException: If notification not found or access denied
    """
    try:
        notification = db.query(Notification).filter(
            Notification.id == notification_id,
            Notification.is_deleted == False
        ).first()
        
        if not notification:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Notification not found"
            )
        
        # Check access permissions
        if not current_user.is_admin:
            if (notification.recipient_id != current_user.id and 
                notification.recipient_email != current_user.email):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied"
                )
        
        # Mark as read if it's the recipient viewing it
        if (notification.recipient_id == current_user.id or 
            notification.recipient_email == current_user.email):
            if notification.status == DeliveryStatus.DELIVERED:
                notification.mark_read()
                db.commit()
        
        return NotificationResponse(**notification.to_dict())
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting notification {notification_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get notification"
        )


@router.put("/{notification_id}/resend")
async def resend_notification(
    notification_id: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Resend a failed notification.
    
    Args:
        notification_id: Notification ID
        background_tasks: Background task handler
        current_user: Current authenticated admin user
        db: Database session
        
    Returns:
        Resend confirmation
        
    Raises:
        HTTPException: If notification not found or cannot be resent
    """
    try:
        notification = db.query(Notification).filter(
            Notification.id == notification_id,
            Notification.is_deleted == False
        ).first()
        
        if not notification:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Notification not found"
            )
        
        if not notification.can_retry():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Notification cannot be resent"
            )
        
        # Reset notification status
        notification.status = DeliveryStatus.PENDING
        notification.error_message = None
        
        db.commit()
        
        # Schedule delivery
        notification_service = NotificationService(db)
        background_tasks.add_task(
            notification_service.schedule_delivery,
            notification.id
        )
        
        return {"message": "Notification scheduled for resending"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resending notification {notification_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to resend notification"
        )


@router.delete("/{notification_id}")
async def delete_notification(
    notification_id: str,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Delete (soft delete) a notification.
    
    Args:
        notification_id: Notification ID
        current_user: Current authenticated admin user
        db: Database session
        
    Returns:
        Deletion confirmation
        
    Raises:
        HTTPException: If notification not found
    """
    try:
        notification = db.query(Notification).filter(
            Notification.id == notification_id,
            Notification.is_deleted == False
        ).first()
        
        if not notification:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Notification not found"
            )
        
        # Soft delete
        notification.is_deleted = True
        notification.deleted_at = datetime.utcnow()
        
        db.commit()
        
        return {"message": "Notification deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting notification {notification_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete notification"
        )


@router.get("/stats/overview", response_model=NotificationStatsResponse)
async def get_notification_stats(
    start_date: Optional[datetime] = Query(None, description="Stats from this date"),
    end_date: Optional[datetime] = Query(None, description="Stats until this date"),
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Get notification statistics and analytics.
    
    Args:
        start_date: Stats from date
        end_date: Stats until date
        current_user: Current authenticated admin user
        db: Database session
        
    Returns:
        Notification statistics
    """
    try:
        # Build base query
        query = db.query(Notification).filter(Notification.is_deleted == False)
        
        if start_date:
            query = query.filter(Notification.created_at >= start_date)
        if end_date:
            query = query.filter(Notification.created_at <= end_date)
        
        notifications = query.all()
        
        # Calculate statistics
        total_sent = sum(1 for n in notifications if n.status != DeliveryStatus.PENDING)
        total_delivered = sum(1 for n in notifications if n.status == DeliveryStatus.DELIVERED)
        total_failed = sum(1 for n in notifications if n.status == DeliveryStatus.FAILED)
        total_pending = sum(1 for n in notifications if n.status == DeliveryStatus.PENDING)
        
        delivery_rate = (total_delivered / total_sent * 100) if total_sent > 0 else 0
        
        # Calculate average delivery time
        delivery_times = []
        for notification in notifications:
            if notification.sent_at and notification.delivered_at:
                delivery_time = (notification.delivered_at - notification.sent_at).total_seconds()
                delivery_times.append(delivery_time)
        
        average_delivery_time = sum(delivery_times) / len(delivery_times) if delivery_times else None
        
        # Channel statistics
        channel_stats = {}
        for notification in notifications:
            channel = notification.channel.value if notification.channel else "unknown"
            channel_stats[channel] = channel_stats.get(channel, 0) + 1
        
        # Type statistics
        type_stats = {}
        for notification in notifications:
            notification_type = notification.type.value if notification.type else "unknown"
            type_stats[notification_type] = type_stats.get(notification_type, 0) + 1
        
        return NotificationStatsResponse(
            total_sent=total_sent,
            total_delivered=total_delivered,
            total_failed=total_failed,
            total_pending=total_pending,
            delivery_rate=round(delivery_rate, 2),
            average_delivery_time=round(average_delivery_time, 2) if average_delivery_time else None,
            channel_stats=channel_stats,
            type_stats=type_stats
        )
        
    except Exception as e:
        logger.error(f"Error getting notification stats: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get notification statistics"
        )


@router.get("/preferences/my")
async def get_my_preferences(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get current user's notification preferences.
    
    Args:
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        User's notification preferences
    """
    try:
        preferences = db.query(NotificationPreference).filter(
            NotificationPreference.user_id == current_user.id
        ).first()
        
        if not preferences:
            # Return default preferences
            return {
                "email_enabled": True,
                "sms_enabled": False,
                "slack_enabled": False,
                "in_app_enabled": True,
                "type_preferences": {},
                "quiet_hours_start": None,
                "quiet_hours_end": None,
                "timezone": "UTC",
                "digest_frequency": "daily",
                "max_emails_per_day": 10
            }
        
        return {
            "email_enabled": preferences.email_enabled,
            "sms_enabled": preferences.sms_enabled,
            "slack_enabled": preferences.slack_enabled,
            "in_app_enabled": preferences.in_app_enabled,
            "type_preferences": preferences.type_preferences,
            "quiet_hours_start": preferences.quiet_hours_start,
            "quiet_hours_end": preferences.quiet_hours_end,
            "timezone": preferences.timezone,
            "digest_frequency": preferences.digest_frequency,
            "max_emails_per_day": preferences.max_emails_per_day
        }
        
    except Exception as e:
        logger.error(f"Error getting notification preferences: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get notification preferences"
        )


@router.put("/preferences/my")
async def update_my_preferences(
    request: NotificationPreferenceRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update current user's notification preferences.
    
    Args:
        request: Preference update request
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        Update confirmation
    """
    try:
        preferences = db.query(NotificationPreference).filter(
            NotificationPreference.user_id == current_user.id
        ).first()
        
        if not preferences:
            # Create new preferences
            preferences = NotificationPreference(
                user_id=current_user.id,
                email_enabled=request.email_enabled,
                sms_enabled=request.sms_enabled,
                slack_enabled=request.slack_enabled,
                in_app_enabled=request.in_app_enabled,
                type_preferences=request.type_preferences,
                quiet_hours_start=request.quiet_hours_start,
                quiet_hours_end=request.quiet_hours_end,
                timezone=request.timezone,
                digest_frequency=request.digest_frequency,
                max_emails_per_day=request.max_emails_per_day
            )
            db.add(preferences)
        else:
            # Update existing preferences
            preferences.email_enabled = request.email_enabled
            preferences.sms_enabled = request.sms_enabled
            preferences.slack_enabled = request.slack_enabled
            preferences.in_app_enabled = request.in_app_enabled
            preferences.type_preferences = request.type_preferences
            preferences.quiet_hours_start = request.quiet_hours_start
            preferences.quiet_hours_end = request.quiet_hours_end
            preferences.timezone = request.timezone
            preferences.digest_frequency = request.digest_frequency
            preferences.max_emails_per_day = request.max_emails_per_day
            preferences.updated_at = datetime.utcnow()
        
        db.commit()
        
        return {"message": "Notification preferences updated successfully"}
        
    except Exception as e:
        logger.error(f"Error updating notification preferences: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update notification preferences"
        )


@router.post("/test")
async def send_test_notification(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Send a test notification to current user.
    
    Args:
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        Test notification confirmation
    """
    try:
        notification_service = NotificationService(db)
        
        # Create test notification
        notification = await notification_service.create_notification(
            type=NotificationType.SYSTEM_MAINTENANCE,
            title="Test Notification",
            message="This is a test notification to verify your notification settings.",
            recipient_email=current_user.email,
            recipient_id=str(current_user.id),
            channel=NotificationChannel.EMAIL,
            priority=NotificationPriority.LOW,
            metadata={"test": True}
        )
        
        # Send immediately
        await notification_service.send_notification(notification.id)
        
        return {
            "message": "Test notification sent",
            "notification_id": str(notification.id)
        }
        
    except Exception as e:
        logger.error(f"Error sending test notification: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send test notification"
        )
