"""
Notification Service for PhishGuard

Business logic for managing notifications, templates, delivery channels,
and notification preferences across email, SMS, and Slack.
"""

from sqlalchemy.orm import Session
from sqlalchemy import desc, and_, or_, func
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
import uuid
import json
import asyncio
from enum import Enum

from ..models.notification import (
    Notification, NotificationTemplate, NotificationPreference,
    NotificationChannel, NotificationStatus, NotificationType, Priority
)
from ..models.user import User
from ..models.audit_log import AuditLog, ActionType
from ..utils.logger import get_logger
from ..utils.mail_client import MailClient
from ..utils.event_bus import EventBus
from ..utils.config import get_settings

logger = get_logger(__name__)
settings = get_settings()

class NotificationService:
    """Service for managing notifications and delivery."""
    
    def __init__(self, db: Session):
        """
        Initialize notification service.
        
        Args:
            db: Database session
        """
        self.db = db
        self.mail_client = MailClient()
        self.event_bus = EventBus()
    
    async def create_notification(
        self,
        recipient_id: uuid.UUID,
        notification_type: NotificationType,
        title: str,
        message: str,
        priority: Priority = Priority.MEDIUM,
        channels: List[NotificationChannel] = None,
        template_id: Optional[uuid.UUID] = None,
        metadata: Optional[Dict[str, Any]] = None,
        scheduled_for: Optional[datetime] = None,
        created_by: Optional[uuid.UUID] = None
    ) -> Notification:
        """
        Create a new notification.
        
        Args:
            recipient_id: User ID of recipient
            notification_type: Type of notification
            title: Notification title
            message: Notification message
            priority: Notification priority
            channels: Delivery channels
            template_id: Optional template ID
            metadata: Additional metadata
            scheduled_for: Optional scheduled delivery time
            created_by: User who created the notification
            
        Returns:
            Created notification
        """
        try:
            # Get recipient user
            recipient = self.db.query(User).filter(User.id == recipient_id).first()
            if not recipient:
                raise ValueError("Recipient user not found")
            
            # Get user preferences for channels if not specified
            if channels is None:
                channels = await self._get_user_preferred_channels(recipient_id, notification_type)
            
            # Apply template if specified
            if template_id:
                template = self.db.query(NotificationTemplate).filter(
                    NotificationTemplate.id == template_id
                ).first()
                if template:
                    title = template.subject_template.format(**metadata) if metadata else template.subject_template
                    message = template.body_template.format(**metadata) if metadata else template.body_template
            
            # Create notification
            notification = Notification(
                id=uuid.uuid4(),
                recipient_id=recipient_id,
                notification_type=notification_type,
                title=title,
                message=message,
                priority=priority,
                channels=channels,
                template_id=template_id,
                metadata=metadata or {},
                status=NotificationStatus.PENDING,
                scheduled_for=scheduled_for or datetime.utcnow(),
                created_by=created_by,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            
            self.db.add(notification)
            self.db.commit()
            self.db.refresh(notification)
            
            # Schedule immediate delivery if not scheduled for later
            if scheduled_for is None or scheduled_for <= datetime.utcnow():
                await self._deliver_notification(notification)
            
            # Log notification creation
            await self._log_notification_action(
                action=ActionType.CREATE,
                notification_id=notification.id,
                user_id=created_by,
                details={
                    "recipient": recipient.email,
                    "type": notification_type.value,
                    "channels": [channel.value for channel in channels],
                    "priority": priority.value
                }
            )
            
            logger.info(f"Notification created successfully: {notification.id}")
            return notification
            
        except Exception as e:
            logger.error(f"Error creating notification: {str(e)}")
            self.db.rollback()
            raise
    
    async def create_bulk_notifications(
        self,
        recipient_ids: List[uuid.UUID],
        notification_type: NotificationType,
        title: str,
        message: str,
        priority: Priority = Priority.MEDIUM,
        channels: List[NotificationChannel] = None,
        template_id: Optional[uuid.UUID] = None,
        metadata: Optional[Dict[str, Any]] = None,
        scheduled_for: Optional[datetime] = None,
        created_by: Optional[uuid.UUID] = None
    ) -> List[Notification]:
        """
        Create bulk notifications for multiple recipients.
        
        Args:
            recipient_ids: List of user IDs
            notification_type: Type of notification
            title: Notification title
            message: Notification message
            priority: Notification priority
            channels: Delivery channels
            template_id: Optional template ID
            metadata: Additional metadata
            scheduled_for: Optional scheduled delivery time
            created_by: User who created the notifications
            
        Returns:
            List of created notifications
        """
        try:
            notifications = []
            
            for recipient_id in recipient_ids:
                try:
                    notification = await self.create_notification(
                        recipient_id=recipient_id,
                        notification_type=notification_type,
                        title=title,
                        message=message,
                        priority=priority,
                        channels=channels,
                        template_id=template_id,
                        metadata=metadata,
                        scheduled_for=scheduled_for,
                        created_by=created_by
                    )
                    notifications.append(notification)
                except Exception as e:
                    logger.error(f"Error creating notification for user {recipient_id}: {str(e)}")
                    continue
            
            # Log bulk notification creation
            await self._log_notification_action(
                action=ActionType.CREATE,
                notification_id=None,
                user_id=created_by,
                details={
                    "action": "bulk_create",
                    "recipient_count": len(recipient_ids),
                    "successful_count": len(notifications),
                    "type": notification_type.value,
                    "priority": priority.value
                }
            )
            
            logger.info(f"Bulk notifications created: {len(notifications)} of {len(recipient_ids)}")
            return notifications
            
        except Exception as e:
            logger.error(f"Error creating bulk notifications: {str(e)}")
            raise
    
    async def get_notifications(
        self,
        recipient_id: Optional[uuid.UUID] = None,
        notification_type: Optional[NotificationType] = None,
        status: Optional[NotificationStatus] = None,
        priority: Optional[Priority] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        skip: int = 0,
        limit: int = 100
    ) -> Tuple[List[Notification], int]:
        """
        Get notifications with filtering.
        
        Args:
            recipient_id: Filter by recipient
            notification_type: Filter by type
            status: Filter by status
            priority: Filter by priority
            start_date: Filter by start date
            end_date: Filter by end date
            skip: Number of records to skip
            limit: Number of records to return
            
        Returns:
            Tuple of (notifications list, total count)
        """
        try:
            query = self.db.query(Notification)
            
            # Apply filters
            if recipient_id:
                query = query.filter(Notification.recipient_id == recipient_id)
            
            if notification_type:
                query = query.filter(Notification.notification_type == notification_type)
            
            if status:
                query = query.filter(Notification.status == status)
            
            if priority:
                query = query.filter(Notification.priority == priority)
            
            if start_date:
                query = query.filter(Notification.created_at >= start_date)
            
            if end_date:
                query = query.filter(Notification.created_at <= end_date)
            
            # Get total count
            total_count = query.count()
            
            # Apply pagination and ordering
            notifications = query.order_by(
                desc(Notification.created_at)
            ).offset(skip).limit(limit).all()
            
            return notifications, total_count
            
        except Exception as e:
            logger.error(f"Error getting notifications: {str(e)}")
            raise
    
    async def mark_notification_read(
        self,
        notification_id: uuid.UUID,
        user_id: uuid.UUID
    ) -> bool:
        """
        Mark a notification as read.
        
        Args:
            notification_id: Notification ID
            user_id: User marking as read
            
        Returns:
            True if successful
        """
        try:
            notification = self.db.query(Notification).filter(
                Notification.id == notification_id
            ).first()
            
            if not notification:
                raise ValueError("Notification not found")
            
            # Verify user can mark this notification as read
            if notification.recipient_id != user_id:
                raise ValueError("User not authorized to mark this notification as read")
            
            # Update notification
            notification.read_at = datetime.utcnow()
            notification.updated_at = datetime.utcnow()
            
            self.db.commit()
            
            # Log read action
            await self._log_notification_action(
                action=ActionType.UPDATE,
                notification_id=notification_id,
                user_id=user_id,
                details={"action": "marked_read"}
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Error marking notification as read: {str(e)}")
            self.db.rollback()
            raise
    
    async def delete_notification(
        self,
        notification_id: uuid.UUID,
        user_id: uuid.UUID
    ) -> bool:
        """
        Delete a notification.
        
        Args:
            notification_id: Notification ID
            user_id: User deleting the notification
            
        Returns:
            True if successful
        """
        try:
            notification = self.db.query(Notification).filter(
                Notification.id == notification_id
            ).first()
            
            if not notification:
                raise ValueError("Notification not found")
            
            # Verify user can delete this notification
            if notification.recipient_id != user_id:
                raise ValueError("User not authorized to delete this notification")
            
            # Soft delete
            notification.deleted_at = datetime.utcnow()
            notification.updated_at = datetime.utcnow()
            
            self.db.commit()
            
            # Log deletion
            await self._log_notification_action(
                action=ActionType.DELETE,
                notification_id=notification_id,
                user_id=user_id,
                details={"action": "deleted"}
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Error deleting notification: {str(e)}")
            self.db.rollback()
            raise
    
    async def get_notification_statistics(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        user_id: Optional[uuid.UUID] = None
    ) -> Dict[str, Any]:
        """
        Get notification statistics.
        
        Args:
            start_date: Start date for statistics
            end_date: End date for statistics
            user_id: Optional user filter
            
        Returns:
            Notification statistics
        """
        try:
            query = self.db.query(Notification)
            
            if user_id:
                query = query.filter(Notification.recipient_id == user_id)
            
            if start_date:
                query = query.filter(Notification.created_at >= start_date)
            
            if end_date:
                query = query.filter(Notification.created_at <= end_date)
            
            # Basic counts
            total_notifications = query.count()
            delivered_count = query.filter(Notification.status == NotificationStatus.DELIVERED).count()
            failed_count = query.filter(Notification.status == NotificationStatus.FAILED).count()
            pending_count = query.filter(Notification.status == NotificationStatus.PENDING).count()
            read_count = query.filter(Notification.read_at.isnot(None)).count()
            
            # Delivery rate
            delivery_rate = (delivered_count / total_notifications * 100) if total_notifications > 0 else 0
            
            # Read rate
            read_rate = (read_count / delivered_count * 100) if delivered_count > 0 else 0
            
            # Type distribution
            type_stats = self.db.query(
                Notification.notification_type,
                func.count(Notification.id)
            ).filter(
                query.whereclause
            ).group_by(Notification.notification_type).all()
            
            type_distribution = {ntype.value: count for ntype, count in type_stats}
            
            # Channel distribution
            channel_stats = {}
            notifications = query.all()
            for notification in notifications:
                for channel in notification.channels:
                    channel_name = channel.value
                    channel_stats[channel_name] = channel_stats.get(channel_name, 0) + 1
            
            # Priority distribution
            priority_stats = self.db.query(
                Notification.priority,
                func.count(Notification.id)
            ).filter(
                query.whereclause
            ).group_by(Notification.priority).all()
            
            priority_distribution = {priority.value: count for priority, count in priority_stats}
            
            return {
                "total_notifications": total_notifications,
                "delivered_count": delivered_count,
                "failed_count": failed_count,
                "pending_count": pending_count,
                "read_count": read_count,
                "delivery_rate": round(delivery_rate, 2),
                "read_rate": round(read_rate, 2),
                "type_distribution": type_distribution,
                "channel_distribution": channel_stats,
                "priority_distribution": priority_distribution,
                "period": {
                    "start_date": start_date.isoformat() if start_date else None,
                    "end_date": end_date.isoformat() if end_date else None
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting notification statistics: {str(e)}")
            raise
    
    async def create_notification_template(
        self,
        name: str,
        notification_type: NotificationType,
        subject_template: str,
        body_template: str,
        description: Optional[str] = None,
        variables: Optional[List[str]] = None,
        is_active: bool = True,
        created_by: Optional[uuid.UUID] = None
    ) -> NotificationTemplate:
        """
        Create a notification template.
        
        Args:
            name: Template name
            notification_type: Type of notification
            subject_template: Subject template with variables
            body_template: Body template with variables
            description: Template description
            variables: List of available variables
            is_active: Whether template is active
            created_by: User who created the template
            
        Returns:
            Created notification template
        """
        try:
            template = NotificationTemplate(
                id=uuid.uuid4(),
                name=name,
                notification_type=notification_type,
                subject_template=subject_template,
                body_template=body_template,
                description=description,
                variables=variables or [],
                is_active=is_active,
                created_by=created_by,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            
            self.db.add(template)
            self.db.commit()
            self.db.refresh(template)
            
            # Log template creation
            await self._log_notification_action(
                action=ActionType.CREATE,
                notification_id=None,
                user_id=created_by,
                details={
                    "resource_type": "notification_template",
                    "template_name": name,
                    "notification_type": notification_type.value
                }
            )
            
            logger.info(f"Notification template created: {name}")
            return template
            
        except Exception as e:
            logger.error(f"Error creating notification template: {str(e)}")
            self.db.rollback()
            raise
    
    async def get_notification_templates(
        self,
        notification_type: Optional[NotificationType] = None,
        is_active: Optional[bool] = None
    ) -> List[NotificationTemplate]:
        """
        Get notification templates with filtering.
        
        Args:
            notification_type: Filter by notification type
            is_active: Filter by active status
            
        Returns:
            List of notification templates
        """
        try:
            query = self.db.query(NotificationTemplate)
            
            if notification_type:
                query = query.filter(NotificationTemplate.notification_type == notification_type)
            
            if is_active is not None:
                query = query.filter(NotificationTemplate.is_active == is_active)
            
            templates = query.order_by(NotificationTemplate.name).all()
            return templates
            
        except Exception as e:
            logger.error(f"Error getting notification templates: {str(e)}")
            raise
    
    async def update_user_notification_preferences(
        self,
        user_id: uuid.UUID,
        preferences: Dict[str, Any]
    ) -> bool:
        """
        Update user notification preferences.
        
        Args:
            user_id: User ID
            preferences: Notification preferences
            
        Returns:
            True if successful
        """
        try:
            # Get or create user preferences
            user_prefs = self.db.query(NotificationPreference).filter(
                NotificationPreference.user_id == user_id
            ).first()
            
            if not user_prefs:
                user_prefs = NotificationPreference(
                    id=uuid.uuid4(),
                    user_id=user_id
                )
                self.db.add(user_prefs)
            
            # Update preferences
            for key, value in preferences.items():
                if hasattr(user_prefs, key):
                    setattr(user_prefs, key, value)
            
            user_prefs.updated_at = datetime.utcnow()
            self.db.commit()
            
            return True
            
        except Exception as e:
            logger.error(f"Error updating user notification preferences: {str(e)}")
            self.db.rollback()
            raise
    
    async def get_user_notification_preferences(
        self,
        user_id: uuid.UUID
    ) -> Dict[str, Any]:
        """
        Get user notification preferences.
        
        Args:
            user_id: User ID
            
        Returns:
            User notification preferences
        """
        try:
            prefs = self.db.query(NotificationPreference).filter(
                NotificationPreference.user_id == user_id
            ).first()
            
            if not prefs:
                # Return default preferences
                return {
                    "email_enabled": True,
                    "sms_enabled": False,
                    "slack_enabled": True,
                    "security_alerts": True,
                    "phishing_alerts": True,
                    "simulation_results": True,
                    "weekly_reports": True,
                    "immediate_threats": True,
                    "quiet_hours_start": None,
                    "quiet_hours_end": None,
                    "frequency": "immediate"
                }
            
            return {
                "email_enabled": prefs.email_enabled,
                "sms_enabled": prefs.sms_enabled,
                "slack_enabled": prefs.slack_enabled,
                "security_alerts": prefs.security_alerts,
                "phishing_alerts": prefs.phishing_alerts,
                "simulation_results": prefs.simulation_results,
                "weekly_reports": prefs.weekly_reports,
                "immediate_threats": prefs.immediate_threats,
                "quiet_hours_start": prefs.quiet_hours_start.isoformat() if prefs.quiet_hours_start else None,
                "quiet_hours_end": prefs.quiet_hours_end.isoformat() if prefs.quiet_hours_end else None,
                "frequency": prefs.frequency
            }
            
        except Exception as e:
            logger.error(f"Error getting user notification preferences: {str(e)}")
            raise
    
    async def process_scheduled_notifications(self) -> int:
        """
        Process notifications scheduled for delivery.
        
        Returns:
            Number of notifications processed
        """
        try:
            current_time = datetime.utcnow()
            
            # Get pending notifications that are due for delivery
            pending_notifications = self.db.query(Notification).filter(
                and_(
                    Notification.status == NotificationStatus.PENDING,
                    Notification.scheduled_for <= current_time,
                    Notification.deleted_at.is_(None)
                )
            ).all()
            
            processed_count = 0
            for notification in pending_notifications:
                try:
                    await self._deliver_notification(notification)
                    processed_count += 1
                except Exception as e:
                    logger.error(f"Error delivering notification {notification.id}: {str(e)}")
                    continue
            
            logger.info(f"Processed {processed_count} scheduled notifications")
            return processed_count
            
        except Exception as e:
            logger.error(f"Error processing scheduled notifications: {str(e)}")
            raise
    
    async def _deliver_notification(self, notification: Notification):
        """Deliver a notification through specified channels."""
        try:
            delivery_results = {}
            
            for channel in notification.channels:
                try:
                    if channel == NotificationChannel.EMAIL:
                        result = await self._deliver_email(notification)
                        delivery_results["email"] = result
                    elif channel == NotificationChannel.SMS:
                        result = await self._deliver_sms(notification)
                        delivery_results["sms"] = result
                    elif channel == NotificationChannel.SLACK:
                        result = await self._deliver_slack(notification)
                        delivery_results["slack"] = result
                    elif channel == NotificationChannel.IN_APP:
                        # In-app notifications are stored in database (already done)
                        delivery_results["in_app"] = {"success": True}
                        
                except Exception as e:
                    logger.error(f"Error delivering via {channel.value}: {str(e)}")
                    delivery_results[channel.value] = {"success": False, "error": str(e)}
            
            # Update notification status
            if any(result.get("success") for result in delivery_results.values()):
                notification.status = NotificationStatus.DELIVERED
                notification.delivered_at = datetime.utcnow()
            else:
                notification.status = NotificationStatus.FAILED
                notification.failed_at = datetime.utcnow()
            
            notification.delivery_results = delivery_results
            notification.updated_at = datetime.utcnow()
            
            self.db.commit()
            
            # Emit delivery event
            await self.event_bus.emit("notification_delivered", {
                "notification_id": str(notification.id),
                "status": notification.status.value,
                "channels": [channel.value for channel in notification.channels],
                "delivery_results": delivery_results
            })
            
        except Exception as e:
            logger.error(f"Error in notification delivery: {str(e)}")
            notification.status = NotificationStatus.FAILED
            notification.failed_at = datetime.utcnow()
            notification.updated_at = datetime.utcnow()
            self.db.commit()
    
    async def _deliver_email(self, notification: Notification) -> Dict[str, Any]:
        """Deliver notification via email."""
        try:
            # Get recipient user
            recipient = self.db.query(User).filter(
                User.id == notification.recipient_id
            ).first()
            
            if not recipient:
                raise ValueError("Recipient not found")
            
            # Send email
            result = await self.mail_client.send_email(
                to_email=recipient.email,
                subject=notification.title,
                body=notification.message,
                is_html=True
            )
            
            return {"success": True, "message_id": result.get("message_id")}
            
        except Exception as e:
            logger.error(f"Error delivering email notification: {str(e)}")
            return {"success": False, "error": str(e)}
    
    async def _deliver_sms(self, notification: Notification) -> Dict[str, Any]:
        """Deliver notification via SMS."""
        try:
            # Get recipient user
            recipient = self.db.query(User).filter(
                User.id == notification.recipient_id
            ).first()
            
            if not recipient or not recipient.phone_number:
                raise ValueError("Recipient phone number not available")
            
            # In a real implementation, this would integrate with SMS service (Twilio, AWS SNS, etc.)
            # For now, we'll simulate SMS delivery
            
            # Emit SMS event for external processing
            await self.event_bus.emit("send_sms", {
                "phone_number": recipient.phone_number,
                "message": notification.message,
                "notification_id": str(notification.id)
            })
            
            return {"success": True, "sms_queued": True}
            
        except Exception as e:
            logger.error(f"Error delivering SMS notification: {str(e)}")
            return {"success": False, "error": str(e)}
    
    async def _deliver_slack(self, notification: Notification) -> Dict[str, Any]:
        """Deliver notification via Slack."""
        try:
            # In a real implementation, this would integrate with Slack API
            # For now, we'll emit an event for external processing
            
            await self.event_bus.emit("send_slack_message", {
                "recipient_id": str(notification.recipient_id),
                "title": notification.title,
                "message": notification.message,
                "notification_id": str(notification.id)
            })
            
            return {"success": True, "slack_queued": True}
            
        except Exception as e:
            logger.error(f"Error delivering Slack notification: {str(e)}")
            return {"success": False, "error": str(e)}
    
    async def _get_user_preferred_channels(
        self,
        user_id: uuid.UUID,
        notification_type: NotificationType
    ) -> List[NotificationChannel]:
        """Get user's preferred notification channels for a notification type."""
        try:
            prefs = await self.get_user_notification_preferences(user_id)
            
            channels = []
            
            # Always include in-app notifications
            channels.append(NotificationChannel.IN_APP)
            
            # Add other channels based on preferences
            if prefs.get("email_enabled", True):
                channels.append(NotificationChannel.EMAIL)
            
            if prefs.get("sms_enabled", False):
                channels.append(NotificationChannel.SMS)
            
            if prefs.get("slack_enabled", True):
                channels.append(NotificationChannel.SLACK)
            
            # For high-priority security alerts, use all available channels
            if notification_type in [NotificationType.SECURITY_ALERT, NotificationType.IMMEDIATE_THREAT]:
                channels = [NotificationChannel.EMAIL, NotificationChannel.SMS, NotificationChannel.SLACK, NotificationChannel.IN_APP]
            
            return channels
            
        except Exception as e:
            logger.error(f"Error getting user preferred channels: {str(e)}")
            # Return default channels
            return [NotificationChannel.EMAIL, NotificationChannel.IN_APP]
    
    async def _log_notification_action(
        self,
        action: ActionType,
        notification_id: Optional[uuid.UUID],
        user_id: Optional[uuid.UUID],
        details: Dict[str, Any]
    ):
        """Log notification-related actions."""
        try:
            audit_log = AuditLog(
                id=uuid.uuid4(),
                action=action,
                resource_type=details.get("resource_type", "notification"),
                resource_id=notification_id,
                user_id=user_id,
                details=details,
                timestamp=datetime.utcnow()
            )
            
            self.db.add(audit_log)
            # Note: Don't commit here, let the calling method handle it
            
        except Exception as e:
            logger.error(f"Error logging notification action: {str(e)}")
