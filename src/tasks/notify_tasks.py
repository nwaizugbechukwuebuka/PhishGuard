"""
Celery tasks for handling notifications and alerts.
This module manages email notifications, Slack alerts, and other communication channels.
"""

import os
import sys
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from celery import Celery
from sqlalchemy.orm import Session
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import requests
import json

# Add src directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.database import get_db
from api.models.email import Email
from api.models.notification import Notification
from api.models.user import User
from api.services.notification_service import NotificationService
from api.utils.config import settings
from api.utils.logger import get_logger
from api.utils.mail_client import MailClient

# Get Celery app instance
from tasks.scan_tasks import celery_app

logger = get_logger(__name__)

# Initialize services
notification_service = NotificationService()
mail_client = MailClient()


@celery_app.task(bind=True, max_retries=3, default_retry_delay=60)
def send_threat_notification(self, email_id: int, threat_type: str, threat_score: float) -> Dict[str, Any]:
    """
    Send notification about detected threat.
    
    Args:
        email_id: ID of the email containing the threat
        threat_type: Type of threat detected
        threat_score: Threat confidence score
        
    Returns:
        Dictionary with notification results
    """
    try:
        logger.info(f"Sending threat notification for email {email_id}")
        
        db = next(get_db())
        
        # Get email details
        email = db.query(Email).filter(Email.id == email_id).first()
        if not email:
            raise ValueError(f"Email {email_id} not found")
        
        # Get notification recipients (security team, administrators)
        recipients = db.query(User).filter(
            User.role.in_(['admin', 'security_analyst']),
            User.notifications_enabled == True
        ).all()
        
        if not recipients:
            logger.warning("No notification recipients found")
            return {
                'status': 'skipped',
                'reason': 'no_recipients',
                'email_id': email_id
            }
        
        # Prepare notification content
        subject = f"🚨 Security Alert: {threat_type} Detected"
        
        threat_details = {
            'message_id': email.message_id,
            'sender': email.sender,
            'recipient': email.recipient,
            'subject': email.subject,
            'threat_type': threat_type,
            'threat_score': threat_score,
            'confidence': email.confidence,
            'detected_at': email.processed_at.isoformat(),
            'quarantined': email.is_threat
        }
        
        # Send email notifications
        email_results = []
        for recipient in recipients:
            if recipient.email_notifications:
                try:
                    result = send_email_notification.delay(
                        recipient_email=recipient.email,
                        subject=subject,
                        threat_details=threat_details,
                        template='threat_alert'
                    ).get(timeout=30)
                    email_results.append(result)
                except Exception as exc:
                    logger.error(f"Failed to send email to {recipient.email}: {str(exc)}")
                    email_results.append({
                        'status': 'failed',
                        'recipient': recipient.email,
                        'error': str(exc)
                    })
        
        # Send Slack notifications if configured
        slack_result = None
        if settings.SLACK_WEBHOOK_URL:
            try:
                slack_result = send_slack_notification.delay(
                    threat_details=threat_details,
                    channel='#security-alerts'
                ).get(timeout=30)
            except Exception as exc:
                logger.error(f"Failed to send Slack notification: {str(exc)}")
                slack_result = {
                    'status': 'failed',
                    'error': str(exc)
                }
        
        # Create notification record in database
        notification = Notification(
            type='threat_alert',
            title=subject,
            message=f"{threat_type} detected in email from {email.sender}",
            severity='high' if threat_score > 0.8 else 'medium',
            data=threat_details,
            created_at=datetime.utcnow()
        )
        db.add(notification)
        db.commit()
        
        logger.info(f"Threat notification sent for email {email_id}")
        
        return {
            'status': 'completed',
            'email_id': email_id,
            'notification_id': notification.id,
            'email_results': email_results,
            'slack_result': slack_result,
            'recipients_count': len(recipients),
            'sent_at': datetime.utcnow().isoformat()
        }
        
    except Exception as exc:
        logger.error(f"Error sending threat notification for email {email_id}: {str(exc)}")
        
        if self.request.retries < self.max_retries:
            logger.info(f"Retrying threat notification (attempt {self.request.retries + 1})")
            raise self.retry(exc=exc, countdown=60 * (self.request.retries + 1))
        
        return {
            'status': 'failed',
            'email_id': email_id,
            'error': str(exc),
            'sent_at': datetime.utcnow().isoformat()
        }
    finally:
        if 'db' in locals():
            db.close()


@celery_app.task(bind=True, max_retries=3)
def send_email_notification(
    self, 
    recipient_email: str, 
    subject: str, 
    threat_details: Dict[str, Any],
    template: str = 'default'
) -> Dict[str, Any]:
    """
    Send email notification to a specific recipient.
    
    Args:
        recipient_email: Email address of recipient
        subject: Email subject line
        threat_details: Dictionary containing threat information
        template: Email template to use
        
    Returns:
        Dictionary with send results
    """
    try:
        logger.info(f"Sending email notification to {recipient_email}")
        
        # Generate email body based on template
        if template == 'threat_alert':
            body = generate_threat_alert_email(threat_details)
        elif template == 'daily_digest':
            body = generate_daily_digest_email(threat_details)
        elif template == 'system_alert':
            body = generate_system_alert_email(threat_details)
        else:
            body = generate_default_email(threat_details)
        
        # Send email using mail client
        result = mail_client.send_email(
            to_email=recipient_email,
            subject=subject,
            body=body,
            is_html=True
        )
        
        if result['success']:
            logger.info(f"Email sent successfully to {recipient_email}")
            return {
                'status': 'sent',
                'recipient': recipient_email,
                'message_id': result.get('message_id'),
                'sent_at': datetime.utcnow().isoformat()
            }
        else:
            logger.error(f"Failed to send email to {recipient_email}: {result.get('error')}")
            return {
                'status': 'failed',
                'recipient': recipient_email,
                'error': result.get('error'),
                'sent_at': datetime.utcnow().isoformat()
            }
        
    except Exception as exc:
        logger.error(f"Error sending email notification to {recipient_email}: {str(exc)}")
        
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc, countdown=60)
        
        return {
            'status': 'failed',
            'recipient': recipient_email,
            'error': str(exc),
            'sent_at': datetime.utcnow().isoformat()
        }


@celery_app.task(bind=True, max_retries=3)
def send_slack_notification(
    self, 
    threat_details: Dict[str, Any], 
    channel: str = '#security-alerts'
) -> Dict[str, Any]:
    """
    Send notification to Slack channel.
    
    Args:
        threat_details: Dictionary containing threat information
        channel: Slack channel to send to
        
    Returns:
        Dictionary with send results
    """
    try:
        logger.info(f"Sending Slack notification to {channel}")
        
        webhook_url = settings.SLACK_WEBHOOK_URL
        if not webhook_url:
            return {
                'status': 'skipped',
                'reason': 'no_webhook_configured'
            }
        
        # Create Slack message payload
        payload = {
            "channel": channel,
            "username": "PhishGuard Security Bot",
            "icon_emoji": ":warning:",
            "attachments": [
                {
                    "color": "danger" if threat_details.get('threat_score', 0) > 0.8 else "warning",
                    "title": f"🚨 {threat_details.get('threat_type', 'Unknown')} Threat Detected",
                    "title_link": f"{settings.FRONTEND_URL}/quarantine",
                    "fields": [
                        {
                            "title": "Sender",
                            "value": threat_details.get('sender', 'Unknown'),
                            "short": True
                        },
                        {
                            "title": "Recipient",
                            "value": threat_details.get('recipient', 'Unknown'),
                            "short": True
                        },
                        {
                            "title": "Subject",
                            "value": threat_details.get('subject', 'No subject'),
                            "short": False
                        },
                        {
                            "title": "Threat Score",
                            "value": f"{threat_details.get('threat_score', 0):.2f}",
                            "short": True
                        },
                        {
                            "title": "Confidence",
                            "value": f"{threat_details.get('confidence', 0):.2f}",
                            "short": True
                        },
                        {
                            "title": "Status",
                            "value": "Quarantined" if threat_details.get('quarantined') else "Flagged",
                            "short": True
                        }
                    ],
                    "footer": "PhishGuard Security System",
                    "ts": int(datetime.utcnow().timestamp())
                }
            ]
        }
        
        # Send to Slack
        response = requests.post(
            webhook_url,
            json=payload,
            timeout=30,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            logger.info("Slack notification sent successfully")
            return {
                'status': 'sent',
                'channel': channel,
                'sent_at': datetime.utcnow().isoformat()
            }
        else:
            logger.error(f"Slack API error: {response.status_code} - {response.text}")
            return {
                'status': 'failed',
                'channel': channel,
                'error': f"HTTP {response.status_code}: {response.text}",
                'sent_at': datetime.utcnow().isoformat()
            }
        
    except Exception as exc:
        logger.error(f"Error sending Slack notification: {str(exc)}")
        
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc, countdown=60)
        
        return {
            'status': 'failed',
            'channel': channel,
            'error': str(exc),
            'sent_at': datetime.utcnow().isoformat()
        }


@celery_app.task
def send_daily_digest() -> Dict[str, Any]:
    """
    Send daily security digest to administrators.
    
    Returns:
        Dictionary with digest results
    """
    try:
        logger.info("Generating daily security digest")
        
        db = next(get_db())
        
        # Calculate date range for yesterday
        yesterday = datetime.utcnow().date() - timedelta(days=1)
        start_time = datetime.combine(yesterday, datetime.min.time())
        end_time = datetime.combine(yesterday, datetime.max.time())
        
        # Get yesterday's statistics
        total_emails = db.query(Email).filter(
            Email.processed_at.between(start_time, end_time)
        ).count()
        
        threats_detected = db.query(Email).filter(
            Email.processed_at.between(start_time, end_time),
            Email.is_threat == True
        ).count()
        
        # Get top threat types
        threat_types = db.query(Email.threat_type, db.func.count(Email.id)).filter(
            Email.processed_at.between(start_time, end_time),
            Email.is_threat == True
        ).group_by(Email.threat_type).all()
        
        # Get recipients for digest
        recipients = db.query(User).filter(
            User.role.in_(['admin', 'security_manager']),
            User.daily_digest_enabled == True
        ).all()
        
        if not recipients:
            logger.info("No digest recipients configured")
            return {
                'status': 'skipped',
                'reason': 'no_recipients'
            }
        
        # Prepare digest data
        digest_data = {
            'date': yesterday.isoformat(),
            'total_emails': total_emails,
            'threats_detected': threats_detected,
            'threat_types': dict(threat_types),
            'detection_rate': (threats_detected / total_emails * 100) if total_emails > 0 else 0
        }
        
        # Send digest to each recipient
        results = []
        for recipient in recipients:
            try:
                result = send_email_notification.delay(
                    recipient_email=recipient.email,
                    subject=f"PhishGuard Daily Security Digest - {yesterday.strftime('%B %d, %Y')}",
                    threat_details=digest_data,
                    template='daily_digest'
                ).get(timeout=30)
                results.append(result)
            except Exception as exc:
                logger.error(f"Failed to send digest to {recipient.email}: {str(exc)}")
                results.append({
                    'status': 'failed',
                    'recipient': recipient.email,
                    'error': str(exc)
                })
        
        logger.info(f"Daily digest sent to {len(recipients)} recipients")
        
        return {
            'status': 'completed',
            'digest_data': digest_data,
            'recipients_count': len(recipients),
            'results': results,
            'sent_at': datetime.utcnow().isoformat()
        }
        
    except Exception as exc:
        logger.error(f"Error generating daily digest: {str(exc)}")
        return {
            'status': 'failed',
            'error': str(exc),
            'sent_at': datetime.utcnow().isoformat()
        }
    finally:
        if 'db' in locals():
            db.close()


@celery_app.task(bind=True, max_retries=3)
def send_system_alert(
    self, 
    alert_type: str, 
    message: str, 
    severity: str = 'medium',
    metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Send system alert notification.
    
    Args:
        alert_type: Type of system alert
        message: Alert message
        severity: Alert severity (low, medium, high, critical)
        metadata: Additional alert metadata
        
    Returns:
        Dictionary with alert results
    """
    try:
        logger.info(f"Sending system alert: {alert_type}")
        
        db = next(get_db())
        
        # Get alert recipients based on severity
        if severity in ['high', 'critical']:
            recipients = db.query(User).filter(
                User.role.in_(['admin', 'security_manager']),
                User.critical_alerts_enabled == True
            ).all()
        else:
            recipients = db.query(User).filter(
                User.role.in_(['admin']),
                User.system_alerts_enabled == True
            ).all()
        
        if not recipients:
            return {
                'status': 'skipped',
                'reason': 'no_recipients',
                'alert_type': alert_type
            }
        
        # Create notification record
        notification = Notification(
            type='system_alert',
            title=f"System Alert: {alert_type}",
            message=message,
            severity=severity,
            data=metadata or {},
            created_at=datetime.utcnow()
        )
        db.add(notification)
        db.commit()
        
        # Send notifications
        email_results = []
        for recipient in recipients:
            if recipient.email_notifications:
                try:
                    result = send_email_notification.delay(
                        recipient_email=recipient.email,
                        subject=f"🔧 System Alert: {alert_type}",
                        threat_details={
                            'alert_type': alert_type,
                            'message': message,
                            'severity': severity,
                            'metadata': metadata or {},
                            'timestamp': datetime.utcnow().isoformat()
                        },
                        template='system_alert'
                    ).get(timeout=30)
                    email_results.append(result)
                except Exception as exc:
                    logger.error(f"Failed to send system alert to {recipient.email}: {str(exc)}")
                    email_results.append({
                        'status': 'failed',
                        'recipient': recipient.email,
                        'error': str(exc)
                    })
        
        # Send to Slack for critical alerts
        slack_result = None
        if severity == 'critical' and settings.SLACK_WEBHOOK_URL:
            try:
                slack_payload = {
                    "channel": "#critical-alerts",
                    "username": "PhishGuard System",
                    "icon_emoji": ":exclamation:",
                    "text": f"🚨 CRITICAL SYSTEM ALERT: {alert_type}\n{message}"
                }
                
                response = requests.post(
                    settings.SLACK_WEBHOOK_URL,
                    json=slack_payload,
                    timeout=30
                )
                
                slack_result = {
                    'status': 'sent' if response.status_code == 200 else 'failed',
                    'response_code': response.status_code
                }
            except Exception as exc:
                slack_result = {
                    'status': 'failed',
                    'error': str(exc)
                }
        
        logger.info(f"System alert sent: {alert_type}")
        
        return {
            'status': 'completed',
            'alert_type': alert_type,
            'notification_id': notification.id,
            'email_results': email_results,
            'slack_result': slack_result,
            'recipients_count': len(recipients),
            'sent_at': datetime.utcnow().isoformat()
        }
        
    except Exception as exc:
        logger.error(f"Error sending system alert {alert_type}: {str(exc)}")
        
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc, countdown=60)
        
        return {
            'status': 'failed',
            'alert_type': alert_type,
            'error': str(exc),
            'sent_at': datetime.utcnow().isoformat()
        }
    finally:
        if 'db' in locals():
            db.close()


# Email template generators
def generate_threat_alert_email(threat_details: Dict[str, Any]) -> str:
    """Generate HTML email for threat alerts."""
    return f"""
    <html>
    <body style="font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5;">
        <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
            <div style="background-color: #d32f2f; color: white; padding: 20px; text-align: center;">
                <h1 style="margin: 0; font-size: 24px;">🚨 Security Threat Detected</h1>
            </div>
            <div style="padding: 30px;">
                <p style="font-size: 16px; margin-bottom: 20px;">
                    A <strong>{threat_details.get('threat_type', 'Unknown')}</strong> threat has been detected and quarantined.
                </p>
                
                <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
                    <tr style="background-color: #f9f9f9;">
                        <td style="padding: 12px; border: 1px solid #ddd; font-weight: bold;">Sender:</td>
                        <td style="padding: 12px; border: 1px solid #ddd;">{threat_details.get('sender', 'Unknown')}</td>
                    </tr>
                    <tr>
                        <td style="padding: 12px; border: 1px solid #ddd; font-weight: bold;">Recipient:</td>
                        <td style="padding: 12px; border: 1px solid #ddd;">{threat_details.get('recipient', 'Unknown')}</td>
                    </tr>
                    <tr style="background-color: #f9f9f9;">
                        <td style="padding: 12px; border: 1px solid #ddd; font-weight: bold;">Subject:</td>
                        <td style="padding: 12px; border: 1px solid #ddd;">{threat_details.get('subject', 'No subject')}</td>
                    </tr>
                    <tr>
                        <td style="padding: 12px; border: 1px solid #ddd; font-weight: bold;">Threat Score:</td>
                        <td style="padding: 12px; border: 1px solid #ddd;">{threat_details.get('threat_score', 0):.2f}</td>
                    </tr>
                    <tr style="background-color: #f9f9f9;">
                        <td style="padding: 12px; border: 1px solid #ddd; font-weight: bold;">Detected At:</td>
                        <td style="padding: 12px; border: 1px solid #ddd;">{threat_details.get('detected_at', 'Unknown')}</td>
                    </tr>
                </table>
                
                <div style="text-align: center; margin-top: 30px;">
                    <a href="{settings.FRONTEND_URL}/quarantine" style="display: inline-block; background-color: #1976d2; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold;">
                        View in PhishGuard Dashboard
                    </a>
                </div>
            </div>
        </div>
    </body>
    </html>
    """


def generate_daily_digest_email(digest_data: Dict[str, Any]) -> str:
    """Generate HTML email for daily digest."""
    return f"""
    <html>
    <body style="font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5;">
        <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
            <div style="background-color: #1976d2; color: white; padding: 20px; text-align: center;">
                <h1 style="margin: 0; font-size: 24px;">📊 Daily Security Digest</h1>
                <p style="margin: 10px 0 0 0; opacity: 0.9;">{digest_data.get('date', 'Unknown Date')}</p>
            </div>
            <div style="padding: 30px;">
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px;">
                    <div style="text-align: center; padding: 20px; background-color: #e3f2fd; border-radius: 8px;">
                        <h2 style="margin: 0; font-size: 32px; color: #1976d2;">{digest_data.get('total_emails', 0)}</h2>
                        <p style="margin: 5px 0 0 0; color: #666;">Emails Processed</p>
                    </div>
                    <div style="text-align: center; padding: 20px; background-color: #ffebee; border-radius: 8px;">
                        <h2 style="margin: 0; font-size: 32px; color: #d32f2f;">{digest_data.get('threats_detected', 0)}</h2>
                        <p style="margin: 5px 0 0 0; color: #666;">Threats Detected</p>
                    </div>
                </div>
                
                <div style="text-align: center; margin-bottom: 30px;">
                    <h3 style="color: #333;">Detection Rate: {digest_data.get('detection_rate', 0):.1f}%</h3>
                </div>
                
                <div style="text-align: center;">
                    <a href="{settings.FRONTEND_URL}/analytics" style="display: inline-block; background-color: #1976d2; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold;">
                        View Full Analytics
                    </a>
                </div>
            </div>
        </div>
    </body>
    </html>
    """


def generate_system_alert_email(alert_data: Dict[str, Any]) -> str:
    """Generate HTML email for system alerts."""
    severity_colors = {
        'low': '#4caf50',
        'medium': '#ff9800',
        'high': '#f44336',
        'critical': '#d32f2f'
    }
    
    color = severity_colors.get(alert_data.get('severity', 'medium'), '#ff9800')
    
    return f"""
    <html>
    <body style="font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5;">
        <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
            <div style="background-color: {color}; color: white; padding: 20px; text-align: center;">
                <h1 style="margin: 0; font-size: 24px;">🔧 System Alert</h1>
                <p style="margin: 10px 0 0 0; opacity: 0.9;">{alert_data.get('alert_type', 'Unknown')}</p>
            </div>
            <div style="padding: 30px;">
                <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 4px; padding: 15px; margin-bottom: 20px;">
                    <p style="margin: 0; font-size: 16px;">{alert_data.get('message', 'No message provided')}</p>
                </div>
                
                <p style="color: #666; margin-bottom: 20px;">
                    <strong>Severity:</strong> {alert_data.get('severity', 'Unknown').title()}<br>
                    <strong>Time:</strong> {alert_data.get('timestamp', 'Unknown')}
                </p>
                
                <div style="text-align: center;">
                    <a href="{settings.FRONTEND_URL}/settings" style="display: inline-block; background-color: #1976d2; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold;">
                        View System Status
                    </a>
                </div>
            </div>
        </div>
    </body>
    </html>
    """


def generate_default_email(data: Dict[str, Any]) -> str:
    """Generate default HTML email template."""
    return f"""
    <html>
    <body style="font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5;">
        <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
            <h2 style="color: #333; margin-bottom: 20px;">PhishGuard Notification</h2>
            <p style="color: #666; line-height: 1.6;">
                This is a notification from your PhishGuard security system.
            </p>
            <div style="text-align: center; margin-top: 30px;">
                <a href="{settings.FRONTEND_URL}" style="display: inline-block; background-color: #1976d2; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold;">
                    Open PhishGuard Dashboard
                </a>
            </div>
        </div>
    </body>
    </html>
    """


# Configure periodic tasks for notifications
celery_app.conf.beat_schedule.update({
    'send-daily-digest': {
        'task': 'tasks.notify_tasks.send_daily_digest',
        'schedule': 86400.0,  # Every 24 hours
        'options': {'countdown': 3600}  # Start 1 hour after midnight
    },
})

if __name__ == '__main__':
    # For testing individual tasks
    pass
